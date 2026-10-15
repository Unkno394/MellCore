//! Control-plane adapter for agent-managed High virtual machines.

use hf_core::{AgentCommand, HighGuestConnection, HighOsProfile, HighVmDeployment};
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

pub fn os_profile(config: &Value) -> Result<HighOsProfile, AppError> {
    match config.get("os_profile").and_then(Value::as_str) {
        Some("ubuntu_ssh") => Ok(HighOsProfile::ubuntu_ssh()),
        Some("debian_ssh") => Ok(HighOsProfile::debian_ssh()),
        Some("arch_linux_ssh") => Ok(HighOsProfile::arch_linux_ssh()),
        _ => Err(AppError::invalid(
            "high_vm requires a supported os_profile: ubuntu_ssh, debian_ssh, or arch_linux_ssh",
        )),
    }
}

pub fn validate_profile(
    level: TrapLevel,
    service: &str,
    config: &Value,
) -> Result<HighOsProfile, AppError> {
    if level != TrapLevel::High || service != "ssh" {
        return Err(AppError::invalid(
            "high_vm requires high interaction and the SSH service",
        ));
    }
    if config.get("base_image").is_some() || config.get("image_source").is_some() {
        return Err(AppError::invalid(
            "High VM images are managed by the agent and cannot be overridden in profile config",
        ));
    }
    os_profile(config)
}

pub fn validate_ports(trap: &Trap) -> Result<(), AppError> {
    if trap.ports.len() != 1
        || trap.ports[0].transport != Transport::Tcp
        || trap.ports[0].route_mode != RouteMode::Direct
        || trap.ports[0].host_port == 0
    {
        return Err(AppError::conflict(
            "High SSH traps need one direct TCP port and cannot join a Dispatcher group",
        ));
    }
    let profile = os_profile(&trap.effective_config)?;
    let expected_target_port = match profile.connection {
        HighGuestConnection::Ssh { guest_port } => guest_port,
        HighGuestConnection::Rdp { .. } => {
            return Err(AppError::invalid(
                "high_vm currently supports SSH profiles only",
            ));
        }
    };
    if trap.ports[0].target_port != expected_target_port {
        return Err(AppError::invalid(
            "High SSH guest port does not match the selected OS profile",
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
        _ => return Err(AppError::invalid("Unsupported High VM operating system")),
    };
    Ok(AgentCommand::DeployHighVm(HighVmDeployment {
        command_id: Uuid::new_v4(),
        trap_id: trap.trap_id,
        base_image: base_image.to_owned(),
        external_service_port: trap.ports[0].host_port,
        profile,
        image_source: None,
    }))
}
