//! Control-plane adapter for agent-managed High virtual machines.

use hf_core::{
    AgentCommand, HighGuestConnection, HighOsProfile, HighVmDeployment, HighVmRuntimeMode,
};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    errors::AppError,
    models::TrapLevel,
    resources::{RouteMode, Transport, Trap},
};

pub const UBUNTU_BASE_IMAGE: &str = "/var/lib/honeyforge/images/noble-server-cloudimg-amd64.img";
pub const DEBIAN_BASE_IMAGE: &str = "/var/lib/honeyforge/images/debian-12-genericcloud-amd64.qcow2";
pub const ARCH_BASE_IMAGE: &str = "/var/lib/honeyforge/images/arch-linux-x86_64-cloudimg.qcow2";
pub const WINDOWS_BASE_IMAGE: &str = "/var/lib/honeyforge/images/windows-server-prepared.qcow2";

pub fn os_profile(config: &Value) -> Result<HighOsProfile, AppError> {
    match config.get("os_profile").and_then(Value::as_str) {
        Some("ubuntu_ssh") => Ok(HighOsProfile::ubuntu_ssh()),
        Some("debian_ssh") => Ok(HighOsProfile::debian_ssh()),
        Some("arch_linux_ssh") => Ok(HighOsProfile::arch_linux_ssh()),
        Some("windows_rdp") => Ok(HighOsProfile::windows_rdp()),
        _ => Err(AppError::invalid(
            "high_vm requires a supported os_profile: ubuntu_ssh, debian_ssh, arch_linux_ssh, or windows_rdp",
        )),
    }
}

pub fn validate_profile(
    level: TrapLevel,
    service: &str,
    config: &Value,
) -> Result<HighOsProfile, AppError> {
    if level != TrapLevel::High {
        return Err(AppError::invalid("high_vm requires high interaction"));
    }
    if config.get("base_image").is_some() || config.get("image_source").is_some() {
        return Err(AppError::invalid(
            "High VM images are managed by the agent and cannot be overridden in profile config",
        ));
    }
    let profile = os_profile(config)?;
    let service_matches = match profile.connection {
        HighGuestConnection::Ssh { .. } => service == "ssh",
        HighGuestConnection::Rdp { .. } => service == "rdp",
    };
    if !service_matches {
        return Err(AppError::invalid(
            "selected High OS profile requires its matching SSH or RDP service",
        ));
    }
    Ok(profile)
}

pub fn validate_ports(trap: &Trap) -> Result<(), AppError> {
    validate_port_bindings(&trap.effective_config, &trap.ports)
}

pub fn runtime_mode(config: &Value) -> Result<HighVmRuntimeMode, AppError> {
    match config.get("high_runtime_mode").and_then(Value::as_str) {
        None | Some("public_kvm") => Ok(HighVmRuntimeMode::PublicKvm),
        Some("private_tcg_test") => Ok(HighVmRuntimeMode::PrivateTcgTest),
        Some(_) => Err(AppError::invalid(
            "high_runtime_mode must be public_kvm or private_tcg_test",
        )),
    }
}

pub fn validate_port_bindings(
    config: &Value,
    ports: &[crate::resources::PortBinding],
) -> Result<(), AppError> {
    let mode = runtime_mode(config)?;
    if mode == HighVmRuntimeMode::PrivateTcgTest {
        if !ports.is_empty() {
            return Err(AppError::invalid(
                "Private TCG test traps must not reserve or publish a host port",
            ));
        }
        return Ok(());
    }
    if ports.len() != 1
        || ports[0].transport != Transport::Tcp
        || ports[0].route_mode != RouteMode::Direct
        || ports[0].host_port == 0
    {
        return Err(AppError::conflict(
            "Public High traps need one direct TCP port and cannot join a Dispatcher group",
        ));
    }
    let profile = os_profile(config)?;
    let expected_target_port = match profile.connection {
        HighGuestConnection::Ssh { guest_port } => guest_port,
        HighGuestConnection::Rdp { guest_port } => guest_port,
    };
    if ports[0].target_port != expected_target_port {
        return Err(AppError::invalid(
            "High guest port does not match the selected OS profile",
        ));
    }
    Ok(())
}

pub fn deployment_command(trap: &Trap) -> Result<AgentCommand, AppError> {
    let profile = validate_profile(
        trap.profile_snapshot.level,
        &trap.profile_snapshot.service_type,
        &trap.profile_snapshot.config,
    )?;
    let effective_profile = validate_profile(
        trap.profile_snapshot.level,
        &trap.profile_snapshot.service_type,
        &trap.effective_config,
    )?;
    if profile != effective_profile {
        return Err(AppError::conflict(
            "High trap OS no longer matches its selected profile",
        ));
    }
    validate_ports(trap)?;
    let base_image = match profile.guest_os {
        hf_core::HighGuestOs::Ubuntu => UBUNTU_BASE_IMAGE,
        hf_core::HighGuestOs::Debian => DEBIAN_BASE_IMAGE,
        hf_core::HighGuestOs::ArchLinux => ARCH_BASE_IMAGE,
        hf_core::HighGuestOs::Windows => WINDOWS_BASE_IMAGE,
        _ => return Err(AppError::invalid("Unsupported High VM operating system")),
    };
    let runtime_mode = runtime_mode(&trap.effective_config)?;
    Ok(AgentCommand::DeployHighVm(HighVmDeployment {
        command_id: Uuid::new_v4(),
        trap_id: trap.trap_id,
        base_image: base_image.to_owned(),
        external_service_port: if runtime_mode == HighVmRuntimeMode::PrivateTcgTest {
            0
        } else {
            trap.ports[0].host_port
        },
        profile,
        image_source: None,
        runtime_mode,
    }))
}
