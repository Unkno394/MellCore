//! Control-plane adapter for agent-managed High virtual machines.

use hf_core::{
    AgentCommand, BaitFile, BaitImplementation, BaitKind, HighGuestConfig, HighGuestConnection,
    HighGuestOs, HighImageArchitecture, HighImageFormat, HighImageSource, HighOsProfile,
    HighVmDeployment, HighVmRuntimeMode, MiddleSshCredential,
};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    errors::AppError,
    models::TrapLevel,
    resources::{RouteMode, Transport, Trap},
};

pub const UBUNTU_BASE_IMAGE: &str = "/var/lib/honeyforge/images/noble-server-cloudimg-amd64-hf-prepared.img";
pub const DEBIAN_BASE_IMAGE: &str = "/var/lib/honeyforge/images/debian-12-genericcloud-amd64-hf-prepared.qcow2";
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
    guest_config(config, profile)?;
    Ok(profile)
}

fn guest_config(config: &Value, profile: HighOsProfile) -> Result<HighGuestConfig, AppError> {
    let hostname = config.get("hostname").and_then(Value::as_str).map(str::to_owned);
    let username = config.get("username").and_then(Value::as_str).map(str::to_owned);
    let credentials: Vec<MiddleSshCredential> = serde_json::from_value(
        config.get("ssh_credentials").cloned().unwrap_or_else(|| Value::Array(vec![])),
    ).map_err(|_| AppError::invalid("Invalid High SSH credentials"))?;
    let vulnerabilities: Vec<String> = serde_json::from_value(
        config.get("vulnerability_profiles").cloned().unwrap_or_else(|| Value::Array(vec![])),
    ).map_err(|_| AppError::invalid("Invalid High vulnerability profiles"))?;
    let baits: Vec<BaitFile> = serde_json::from_value(
        config.get("baits").cloned().unwrap_or_else(|| Value::Array(vec![])),
    ).map_err(|_| AppError::invalid("Invalid High bait files"))?;
    if profile.guest_os == HighGuestOs::Windows {
        if !credentials.is_empty() || !vulnerabilities.is_empty() || !baits.is_empty() {
            return Err(AppError::invalid("High SSH credentials, baits and vulnerability profiles currently require a Linux guest"));
        }
        return Ok(HighGuestConfig { hostname, username: None, ssh_credentials: vec![], vulnerability_profiles: vec![], baits: vec![] });
    }
    if let Some(name) = &hostname {
        if name.is_empty() || name.len() > 63 || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-') {
            return Err(AppError::invalid("High hostname must be a DNS label of at most 63 characters"));
        }
    }
    if let Some(name) = &username {
        if !valid_login(name) || name == "root" {
            return Err(AppError::invalid("High SSH username must be a non-root Unix login"));
        }
    }
    if config.get("ssh_auth_mode").and_then(Value::as_str).is_some_and(|mode| mode != "realistic") {
        return Err(AppError::invalid("High VM SSH supports realistic credentials only"));
    }
    if credentials.len() > 1 || (!credentials.is_empty() && username.is_none()) {
        return Err(AppError::invalid("High SSH requires one primary username and at most one credential"));
    }
    let mut seen_users = std::collections::HashSet::new();
    for credential in &credentials {
        if !valid_login(&credential.username)
            || !seen_users.insert(credential.username.to_ascii_lowercase())
            || credential.password.is_empty()
            || credential.password.len() > 128
            || credential.password.chars().any(char::is_control)
        {
            return Err(AppError::invalid("Invalid or duplicate High SSH credential"));
        }
    }
    if let Some(name) = &username {
        if !credentials.is_empty() && credentials[0].username != *name {
            return Err(AppError::invalid("The first High SSH credential must match the selected username"));
        }
    }
    let mut seen_profiles = std::collections::HashSet::new();
    for profile in &vulnerabilities {
        if !matches!(profile.as_str(), "ssh_weak_credentials" | "ssh_root_login_enabled" | "sudo_nopasswd")
            || !seen_profiles.insert(profile.as_str())
        {
            return Err(AppError::invalid("Unsupported or duplicate Linux High vulnerability profile"));
        }
    }
    if vulnerabilities.iter().any(|profile| profile == "ssh_root_login_enabled" || profile == "sudo_nopasswd")
        && (username.is_none() || credentials.is_empty())
    {
        return Err(AppError::invalid("High root login and sudo_nopasswd require SSH credentials"));
    }
    hf_core::validate_bait_files(&baits).map_err(AppError::invalid)?;
    for bait in &baits {
        let path = bait.path.as_deref().ok_or_else(|| AppError::invalid("High bait needs a file path"))?;
        let allowed = path.starts_with("/srv/") || path.starts_with("/opt/")
            || path.starts_with("/var/backups/")
            || username.as_ref().is_some_and(|name| path.starts_with(&format!("/home/{name}/")));
        if bait.kind == BaitKind::Account || bait.implementation.is_some_and(|kind| kind != BaitImplementation::VirtualFile)
            || !allowed
        {
            return Err(AppError::invalid("Linux High supports file baits under /srv, /opt, /var/backups or its SSH user's home"));
        }
    }
    Ok(HighGuestConfig { hostname, username, ssh_credentials: credentials, vulnerability_profiles: vulnerabilities, baits })
}

fn valid_login(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|first| first.is_ascii_lowercase() || first == b'_')
        && value.len() <= 32
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-')
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
        guest: guest_config(&trap.effective_config, deployment_profile)?,
    }))
}
