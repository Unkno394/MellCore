//! Control-plane adapter for agent-managed High virtual machines.

use hf_core::{
    AgentCommand, HighGuestConnection, HighImageArchitecture, HighImageFormat, HighImageSource,
    HighOsProfile, HighVmDeployment, HighVmRuntimeMode,
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
    if config.get("base_image").is_some() {
        return Err(AppError::invalid(
            "High VM base images are managed by the agent and cannot be overridden in profile config",
        ));
    }
    let profile = deployment_profile(config)?;
    let service_matches = match profile.connection {
        HighGuestConnection::Ssh { .. } => service == "ssh",
        HighGuestConnection::Rdp { .. } => service == "rdp",
    };
    if !service_matches {
        return Err(AppError::invalid(
            "selected High OS profile requires its matching SSH or RDP service",
        ));
    }
    if config.get("high_image_mode").and_then(Value::as_str) == Some("custom_iso")
        && runtime_mode(config)? == HighVmRuntimeMode::PrivateTcgTest
    {
        return Err(AppError::invalid(
            "A user-supplied ISO requires public KVM mode",
        ));
    }
    Ok(profile)
}

fn deployment_profile(config: &Value) -> Result<HighOsProfile, AppError> {
    match config.get("high_image_mode").and_then(Value::as_str) {
        None | Some("prepared") => {
            if config.get("image_source").is_some() || config.get("custom_iso_os").is_some() {
                return Err(AppError::invalid(
                    "Prepared High images cannot include a custom ISO source",
                ));
            }
            os_profile(config)
        }
        Some("custom_iso") => {
            let selected = config
                .get("custom_iso_os")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    AppError::invalid("Choose the operating system contained in the ISO")
                })?;
            let profile = match selected {
                "ubuntu" => HighOsProfile::ubuntu_iso_ssh(),
                "debian" => HighOsProfile::debian_iso_ssh(),
                "arch" => HighOsProfile::arch_linux_iso_ssh(),
                "windows" => HighOsProfile::windows_rdp_legacy_iso(),
                _ => {
                    return Err(AppError::invalid(
                        "Unsupported operating system in custom ISO",
                    ));
                }
            };
            let base_profile = os_profile(config)?;
            if base_profile.guest_os != profile.guest_os {
                return Err(AppError::invalid(
                    "The selected trap profile must match the operating system in the ISO",
                ));
            }
            let source: HighImageSource = config
                .get("image_source")
                .cloned()
                .and_then(|source| serde_json::from_value(source).ok())
                .ok_or_else(|| AppError::invalid("Upload an ISO before starting this High trap"))?;
            if source.format != HighImageFormat::Iso
                || source.architecture != HighImageArchitecture::X86_64
                || source.sha256.len() != 64
                || !source.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
                || !source.url.starts_with("https://")
            {
                return Err(AppError::invalid(
                    "Custom ISO must be an uploaded x86_64 ISO with a valid SHA-256",
                ));
            }
            Ok(profile)
        }
        Some(_) => Err(AppError::invalid(
            "high_image_mode must be prepared or custom_iso",
        )),
    }
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
    let profile = deployment_profile(config)?;
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
    let selected_iso = trap
        .effective_config
        .get("high_image_mode")
        .and_then(Value::as_str)
        == Some("custom_iso");
    if if selected_iso {
        profile.guest_os != effective_profile.guest_os
            || profile.connection != effective_profile.connection
    } else {
        profile != effective_profile
    } {
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
    let image_source = if selected_iso {
        Some(
            serde_json::from_value(
                trap.effective_config
                    .get("image_source")
                    .cloned()
                    .ok_or_else(|| {
                        AppError::invalid("Upload an ISO before starting this High trap")
                    })?,
            )
            .map_err(|_| AppError::invalid("Invalid uploaded ISO metadata"))?,
        )
    } else {
        None
    };
    let deployment_profile = if selected_iso {
        effective_profile
    } else {
        profile
    };
    Ok(AgentCommand::DeployHighVm(HighVmDeployment {
        command_id: Uuid::new_v4(),
        trap_id: trap.trap_id,
        base_image: base_image.to_owned(),
        external_service_port: if runtime_mode == HighVmRuntimeMode::PrivateTcgTest {
            0
        } else {
            trap.ports[0].host_port
        },
        profile: deployment_profile,
        image_source,
        runtime_mode,
    }))
}
