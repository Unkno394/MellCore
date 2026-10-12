//! Configuration adapter for the separately maintained honeyforge-low binary.
//! No process, socket, container or SSH connection is started here.
use crate::{
    errors::AppError,
    models::TrapLevel,
    resources::{PortBinding, Transport, Trap},
};
use hf_core::{AgentCommand, KozyavkaDeployment};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::{IpAddr, Ipv4Addr};
use utoipa::ToSchema;
use uuid::Uuid;

pub const PROFILE_ID: Uuid = Uuid::from_u128(0x6b6f7a79_6176_4b61_8000_000000000001);

#[derive(Deserialize, Serialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
#[schema(as = KozyavkaSettings)]
pub struct Settings {
    #[schema(value_type = String, example = "127.0.0.1")]
    pub bind_address: IpAddr,
    #[schema(min_length = 1, max_length = 253, pattern = "^[ -~]+$")]
    pub banner: String,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            bind_address: Ipv4Addr::LOCALHOST.into(),
            banner: "SSH-2.0-OpenSSH_9.6".into(),
        }
    }
}

/// Exact JSON accepted by honeyforge-low --config. Identity and port are derived.
#[derive(Serialize, ToSchema)]
#[schema(as = KozyavkaRuntimeConfig)]
pub struct RuntimeConfig {
    #[schema(value_type = String, example = "127.0.0.1")]
    pub bind_address: IpAddr,
    #[schema(minimum = 1, maximum = 65535)]
    pub port: u16,
    #[schema(min_length = 1, max_length = 253, pattern = "^[ -~]+$")]
    pub banner: String,
    pub trap_id: Uuid,
}

pub fn validate_profile(
    level: TrapLevel,
    service: &str,
    config: &Value,
) -> Result<Settings, AppError> {
    if level != TrapLevel::Low || service != "ssh" {
        return Err(AppError::invalid(
            "kozyavka requires low interaction and ssh service",
        ));
    }
    let settings: Settings = serde_json::from_value(config.clone())
        .map_err(|_| AppError::invalid("Invalid kozyavka configuration fields"))?;
    if settings.banner.is_empty()
        || settings.banner.len() > 253
        || !settings.banner.bytes().all(|b| (32..=126).contains(&b))
    {
        return Err(AppError::invalid(
            "kozyavka banner requires 1–253 printable ASCII bytes",
        ));
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
            "kozyavka requires exactly one nonzero TCP port binding",
        ));
    }
    Ok(ports[0].target_port)
}

/// Caller must first load the trap through the authenticated owner's resource API.
pub fn runtime_config(trap: &Trap) -> Result<RuntimeConfig, AppError> {
    let profile = &trap.profile_snapshot;
    if profile.honeypot_type != "kozyavka" {
        return Err(AppError::conflict(
            "Runtime configuration adapter is not available for this profile",
        ));
    }
    let settings = validate_profile(profile.level, &profile.service_type, &trap.effective_config)?;
    let port = validate_ports(&trap.ports)?;
    Ok(RuntimeConfig {
        bind_address: settings.bind_address,
        port,
        banner: settings.banner,
        trap_id: trap.trap_id,
    })
}

/// The control-plane representation sent through HFSP to the agent. It contains only values
/// already validated by the profile and port-reservation logic; never user-provided compose YAML.
pub fn deployment_command(trap: &Trap) -> Result<AgentCommand, AppError> {
    let runtime = runtime_config(trap)?;
    let binding = trap.ports.first().ok_or_else(AppError::internal)?;
    let host_port = binding.host_port;
    Ok(AgentCommand::DeployKozyavka(KozyavkaDeployment {
        command_id: Uuid::new_v4(),
        trap_id: runtime.trap_id,
        host_port,
        container_port: runtime.port,
        banner: runtime.banner,
        resources: trap.resources.into(),
        publish_address: if binding.route_mode == crate::resources::RouteMode::Direct {
            "0.0.0.0"
        } else {
            "127.0.0.1"
        }
        .into(),
    }))
}
