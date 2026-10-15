//! Runtime configuration adapter for the standalone Middle SSH honeypot.
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use hf_core::{BaitFile, VirtualProcess};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    errors::AppError,
    models::TrapLevel,
    resources::{PortBinding, Transport, Trap},
};

pub const PROFILE_ID: Uuid = Uuid::from_u128(0x70726974_766f_4279_8000_000000000001);

#[derive(Clone, Copy, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CredentialCapture {
    None,
    Username,
    Password,
}

#[derive(Clone, Copy, Deserialize, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SshAuthMode {
    Realistic,
    Adaptive,
}

impl Default for SshAuthMode {
    fn default() -> Self {
        Self::Realistic
    }
}

#[derive(Clone, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SshCredential {
    pub username: String,
    #[schema(write_only)]
    pub password: String,
}

fn default_ssh_credentials() -> Vec<SshCredential> {
    vec![
        SshCredential {
            username: "root".into(),
            password: "admin123".into(),
        },
        SshCredential {
            username: "admin".into(),
            password: "password123".into(),
        },
        SshCredential {
            username: "test".into(),
            password: "test".into(),
        },
    ]
}

#[derive(Deserialize, Serialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    #[schema(value_type = String)]
    pub bind_address: IpAddr,
    #[schema(value_type = String)]
    pub health_bind_address: IpAddr,
    pub health_port: u16,
    pub hostname: String,
    pub username: String,
    pub distribution: String,
    pub host_key: String,
    pub credential_capture: CredentialCapture,
    #[serde(default)]
    pub ssh_auth_mode: SshAuthMode,
    #[serde(default = "default_ssh_credentials")]
    #[schema(value_type = Vec<Object>)]
    pub ssh_credentials: Vec<SshCredential>,
    pub max_connections: usize,
    pub idle_timeout_seconds: u64,
    pub max_input_bytes: usize,
    #[schema(value_type = Vec<Object>)]
    pub baits: Vec<BaitFile>,
    #[serde(default)]
    #[schema(value_type = Vec<Object>)]
    pub virtual_processes: Vec<VirtualProcess>,
    #[serde(default)]
    pub vulnerability_profiles: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            bind_address: Ipv4Addr::UNSPECIFIED.into(),
            health_bind_address: Ipv4Addr::LOCALHOST.into(),
            health_port: 9091,
            hostname: "srv-app-01".into(),
            username: "admin".into(),
            distribution: "ubuntu".into(),
            host_key: "/var/lib/pritvoryashka/host_ed25519".into(),
            credential_capture: CredentialCapture::Username,
            ssh_auth_mode: SshAuthMode::Realistic,
            ssh_credentials: default_ssh_credentials(),
            max_connections: 128,
            idle_timeout_seconds: 600,
            max_input_bytes: 8192,
            baits: Vec::new(),
            virtual_processes: Vec::new(),
            vulnerability_profiles: Vec::new(),
        }
    }
}

#[derive(Serialize, ToSchema)]
pub struct RuntimeAuth {
    pub policy: &'static str,
    pub username: Option<String>,
    pub password_env: Option<String>,
    pub capture: CredentialCapture,
    pub max_attempts: usize,
}

#[derive(Serialize, ToSchema)]
pub struct RuntimeTelemetry {
    pub endpoint: Option<String>,
    pub token_env: Option<String>,
    pub jsonl_path: Option<String>,
    pub queue_capacity: usize,
    pub batch_size: usize,
    pub flush_interval_ms: u64,
    pub max_event_bytes: usize,
}

#[derive(Serialize, ToSchema)]
#[schema(as = PritvoryashkaRuntimeConfig)]
pub struct RuntimeConfig {
    #[schema(value_type = String)]
    pub bind: SocketAddr,
    pub ssh_public_port: u16,
    #[schema(value_type = String)]
    pub health_bind: SocketAddr,
    pub trap_id: Uuid,
    pub server_id: Uuid,
    pub agent_id: Uuid,
    pub hostname: String,
    pub username: String,
    pub distribution: String,
    pub host_key: String,
    pub ssh_auth_mode: SshAuthMode,
    #[schema(value_type = Vec<Object>)]
    pub ssh_credentials: Vec<SshCredential>,
    pub auth: RuntimeAuth,
    pub telemetry: RuntimeTelemetry,
    pub max_connections: usize,
    pub idle_timeout_seconds: u64,
    pub max_input_bytes: usize,
    #[schema(value_type = Vec<Object>)]
    pub baits: Vec<BaitFile>,
    #[schema(value_type = Vec<Object>)]
    pub virtual_processes: Vec<VirtualProcess>,
    pub vulnerability_profiles: Vec<String>,
    pub network_listeners: Vec<RuntimeListener>,
}

#[derive(Serialize, ToSchema)]
pub struct RuntimeListener {
    pub service_type: String,
    #[schema(value_type = String)]
    pub bind: SocketAddr,
    pub public_port: Option<u16>,
}

pub fn validate_profile(
    level: TrapLevel,
    service: &str,
    config: &Value,
) -> Result<Settings, AppError> {
    if level != TrapLevel::Medium || service != "ssh" {
        return Err(AppError::invalid(
            "pritvoryashka requires medium interaction and ssh service",
        ));
    }
    let settings: Settings = serde_json::from_value(config.clone())
        .map_err(|_| AppError::invalid("Invalid pritvoryashka configuration fields"))?;
    if settings.health_port == 0
        || settings.hostname.is_empty()
        || settings.hostname.len() > 64
        || !settings
            .hostname
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
        || !valid_username(&settings.username, false)
        || !matches!(
            settings.distribution.as_str(),
            "ubuntu" | "debian" | "arch" | "windows"
        )
        || settings.host_key.is_empty()
        || settings.host_key.len() > 4096
        || settings.host_key.chars().any(char::is_control)
        || !(1..=10_000).contains(&settings.max_connections)
        || !(30..=86_400).contains(&settings.idle_timeout_seconds)
        || !(256..=65_536).contains(&settings.max_input_bytes)
    {
        return Err(AppError::invalid("Invalid pritvoryashka settings"));
    }
    validate_ssh_credentials(
        settings.ssh_auth_mode,
        &settings.ssh_credentials,
        &settings.username,
    )?;
    hf_core::pritvoryashka_service_endpoints_for_os(
        &settings.vulnerability_profiles,
        settings.distribution == "windows",
    )
    .map_err(AppError::invalid)?;
    hf_core::validate_bait_files(&settings.baits).map_err(AppError::invalid)?;
    if settings.distribution == "windows" {
        if settings
            .baits
            .iter()
            .filter_map(|bait| bait.config.account.as_ref())
            .any(|account| {
                !account
                    .home_directory
                    .as_deref()
                    .is_some_and(|home| home.starts_with("/C/Users/"))
                    || account.uid.is_some()
                    || account.shell.is_some()
            })
        {
            return Err(AppError::invalid(
                "Windows account baits require a /C/Users/ home directory and no Linux UID or shell",
            ));
        }
        if settings
            .baits
            .iter()
            .filter_map(|bait| bait.path.as_deref())
            .any(|path| !path.starts_with("/C/"))
        {
            return Err(AppError::invalid("Windows bait paths must be under /C/"));
        }
    } else if settings
        .baits
        .iter()
        .filter_map(|bait| bait.config.account.as_ref())
        .any(|account| {
            account
                .home_directory
                .as_deref()
                .is_some_and(|home| !home.starts_with("/home/"))
        })
    {
        return Err(AppError::invalid(
            "Linux account home directories must be under /home/",
        ));
    } else if settings
        .baits
        .iter()
        .filter_map(|bait| bait.path.as_deref())
        .any(|path| path.starts_with("/C/"))
    {
        return Err(AppError::invalid("/C/ bait paths require Windows Middle"));
    }
    hf_core::validate_virtual_processes(&settings.virtual_processes).map_err(AppError::invalid)?;
    Ok(settings)
}

pub fn expected_service_endpoints(profiles: &[String]) -> Result<Vec<(String, u16)>, AppError> {
    hf_core::pritvoryashka_service_endpoints(profiles)
        .map(|endpoints| {
            endpoints
                .into_iter()
                .map(|endpoint| (endpoint.service_type.to_owned(), endpoint.container_port))
                .collect()
        })
        .map_err(AppError::invalid)
}

pub fn validate_ports(
    ports: &[PortBinding],
    vulnerability_profiles: &[String],
) -> Result<u16, AppError> {
    if ports.is_empty() || ports.len() > 12 {
        return Err(AppError::invalid(
            "Middle requires one SSH binding and at most eleven service bindings",
        ));
    }
    let expected = expected_service_endpoints(vulnerability_profiles)?;
    let mut host_ports = BTreeSet::new();
    let mut service_ports = BTreeSet::new();
    let mut ssh_port = None;
    for port in ports {
        if port.transport != Transport::Tcp
            || port.host_port == 0
            || port.target_port == 0
            || !host_ports.insert(port.host_port)
        {
            return Err(AppError::invalid(
                "Middle endpoints require unique nonzero TCP ports",
            ));
        }
        if port.route_mode == crate::resources::RouteMode::DispatcherBackend {
            if ssh_port.is_some() || port.weight.is_none() {
                return Err(AppError::invalid(
                    "Only the SSH endpoint may use the TCP Dispatcher",
                ));
            }
            ssh_port = Some(port.target_port);
        } else if port.target_port == 2222 {
            if ssh_port.replace(port.target_port).is_some() {
                return Err(AppError::invalid(
                    "Middle must have exactly one SSH endpoint",
                ));
            }
        } else {
            if port.weight.is_some() || !service_ports.insert(port.target_port) {
                return Err(AppError::invalid(
                    "Middle service endpoint bindings must be unique direct ports",
                ));
            }
        }
    }
    let ssh_port = ssh_port.ok_or_else(|| {
        AppError::invalid("Middle requires an SSH endpoint on container port 2222")
    })?;
    let expected_ports: BTreeSet<_> = expected.iter().map(|(_, port)| *port).collect();
    if expected_ports != service_ports {
        return Err(AppError::invalid(
            "Port bindings must match the selected vulnerability profiles",
        ));
    }
    Ok(ssh_port)
}

pub fn runtime_config(
    trap: &Trap,
    telemetry_endpoint: Option<String>,
) -> Result<RuntimeConfig, AppError> {
    let profile = &trap.profile_snapshot;
    if profile.honeypot_type != "pritvoryashka" {
        return Err(AppError::conflict(
            "Runtime configuration adapter is not available for this profile",
        ));
    }
    let settings = validate_profile(profile.level, &profile.service_type, &trap.effective_config)?;
    let port = validate_ports(&trap.ports, &settings.vulnerability_profiles)?;
    let ssh_binding = trap
        .ports
        .iter()
        .find(|port| {
            port.route_mode == crate::resources::RouteMode::DispatcherBackend
                || port.target_port == 2222
        })
        .ok_or_else(AppError::internal)?;
    let container_port = if ssh_binding.route_mode == crate::resources::RouteMode::DispatcherBackend
    {
        2222
    } else {
        port
    };
    let vulnerability_profiles = settings.vulnerability_profiles;
    let network_listeners = expected_service_endpoints(&vulnerability_profiles)?
        .into_iter()
        .map(|(service_type, container_port)| {
            let binding = trap
                .ports
                .iter()
                .find(|binding| binding.target_port == container_port)
                .ok_or_else(AppError::internal)?;
            Ok(RuntimeListener {
                service_type,
                bind: SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), container_port),
                public_port: Some(binding.host_port),
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    Ok(RuntimeConfig {
        bind: SocketAddr::new(settings.bind_address, container_port),
        ssh_public_port: ssh_binding.host_port,
        health_bind: SocketAddr::new(settings.health_bind_address, settings.health_port),
        trap_id: trap.trap_id,
        server_id: trap.server_id,
        // HoneyForge has no deployed-agent resource yet. The server identity is stable
        // and keeps the existing telemetry contract usable until that registry lands.
        agent_id: trap.server_id,
        hostname: settings.hostname,
        username: settings.username,
        distribution: settings.distribution,
        host_key: settings.host_key,
        ssh_auth_mode: settings.ssh_auth_mode,
        ssh_credentials: settings.ssh_credentials,
        auth: RuntimeAuth {
            policy: "accept_all",
            username: None,
            password_env: None,
            capture: settings.credential_capture,
            max_attempts: 6,
        },
        telemetry: RuntimeTelemetry {
            token_env: telemetry_endpoint
                .as_ref()
                .map(|_| "PRITVORYASHKA_TELEMETRY_TOKEN".into()),
            endpoint: telemetry_endpoint,
            jsonl_path: Some("/var/lib/pritvoryashka/events.jsonl".into()),
            queue_capacity: 1024,
            batch_size: 50,
            flush_interval_ms: 500,
            max_event_bytes: 65_536,
        },
        max_connections: settings.max_connections,
        idle_timeout_seconds: settings.idle_timeout_seconds,
        max_input_bytes: settings.max_input_bytes,
        baits: settings.baits,
        virtual_processes: settings.virtual_processes,
        vulnerability_profiles,
        network_listeners,
    })
}

fn validate_ssh_credentials(
    mode: SshAuthMode,
    credentials: &[SshCredential],
    virtual_username: &str,
) -> Result<(), AppError> {
    if credentials.len() > 32 {
        return Err(AppError::invalid(
            "SSH authentication allows at most 32 credential pairs",
        ));
    }
    if mode == SshAuthMode::Adaptive {
        return Ok(());
    }
    if credentials.is_empty() {
        return Err(AppError::invalid(
            "Realistic SSH authentication requires at least one credential pair",
        ));
    }
    let mut unique_usernames = BTreeSet::new();
    for credential in credentials {
        if !valid_username(&credential.username, true)
            || credential.password.trim().is_empty()
            || credential.password.len() > 128
            || credential.password.chars().any(char::is_control)
        {
            return Err(AppError::invalid("Invalid SSH credential pair"));
        }
        if !unique_usernames.insert(credential.username.to_ascii_lowercase()) {
            return Err(AppError::invalid(
                "SSH credential usernames must be unique",
            ));
        }
    }
    if !unique_usernames.contains(&virtual_username.to_ascii_lowercase()) {
        return Err(AppError::invalid(
            "Realistic SSH authentication must include the virtual shell username",
        ));
    }
    Ok(())
}

fn valid_username(value: &str, allow_root: bool) -> bool {
    value.len() <= 32
        && (allow_root || value != "root")
        && value
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_lowercase() || *b == b'_')
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}
