//! Runtime configuration adapter for the standalone Middle SSH honeypot.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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

#[derive(Deserialize, Serialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    #[schema(value_type = String)]
    pub bind_address: IpAddr,
    #[schema(value_type = String)]
    pub health_bind_address: IpAddr,
    pub health_port: u16,
    pub hostname: String,
    pub host_key: String,
    pub credential_capture: CredentialCapture,
    pub max_connections: usize,
    pub idle_timeout_seconds: u64,
    pub max_input_bytes: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            bind_address: Ipv4Addr::UNSPECIFIED.into(),
            health_bind_address: Ipv4Addr::LOCALHOST.into(),
            health_port: 9091,
            hostname: "srv-app-01".into(),
            host_key: "/var/lib/pritvoryashka/host_ed25519".into(),
            credential_capture: CredentialCapture::Username,
            max_connections: 128,
            idle_timeout_seconds: 600,
            max_input_bytes: 8192,
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
    #[schema(value_type = String)]
    pub health_bind: SocketAddr,
    pub trap_id: Uuid,
    pub server_id: Uuid,
    pub agent_id: Uuid,
    pub hostname: String,
    pub host_key: String,
    pub auth: RuntimeAuth,
    pub telemetry: RuntimeTelemetry,
    pub max_connections: usize,
    pub idle_timeout_seconds: u64,
    pub max_input_bytes: usize,
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
        || settings.host_key.is_empty()
        || settings.host_key.len() > 4096
        || settings.host_key.chars().any(char::is_control)
        || !(1..=10_000).contains(&settings.max_connections)
        || !(30..=86_400).contains(&settings.idle_timeout_seconds)
        || !(256..=65_536).contains(&settings.max_input_bytes)
    {
        return Err(AppError::invalid("Invalid pritvoryashka settings"));
    }
    Ok(settings)
}

pub fn validate_ports(ports: &[PortBinding]) -> Result<u16, AppError> {
    if ports.len() != 1
        || ports[0].transport != Transport::Tcp
        || ports[0].host_port == 0
        || ports[0].target_port == 0
    {
        return Err(AppError::invalid(
            "pritvoryashka requires exactly one nonzero TCP port binding",
        ));
    }
    Ok(ports[0].target_port)
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
    let port = validate_ports(&trap.ports)?;
    Ok(RuntimeConfig {
        bind: SocketAddr::new(settings.bind_address, port),
        health_bind: SocketAddr::new(settings.health_bind_address, settings.health_port),
        trap_id: trap.trap_id,
        server_id: trap.server_id,
        // HoneyForge has no deployed-agent resource yet. The server identity is stable
        // and keeps the existing telemetry contract usable until that registry lands.
        agent_id: trap.server_id,
        hostname: settings.hostname,
        host_key: settings.host_key,
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
    })
}
