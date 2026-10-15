//! Control-plane adapter for the agent-managed High Ubuntu SSH VM.

use serde_json::Value;
use uuid::Uuid;

use crate::{
    errors::AppError,
    models::TrapLevel,
    resources::{RouteMode, Transport, Trap},
};
use hf_core::{AgentCommand, HighUbuntuDeployment};

pub const DEFAULT_BASE_IMAGE: &str = "/var/lib/honeyforge/images/noble-server-cloudimg-amd64.img";

pub fn validate_profile(level: TrapLevel, service: &str, config: &Value) -> Result<(), AppError> {
    if level != TrapLevel::High || service != "ssh" {
        return Err(AppError::invalid(
            "high_ubuntu_ssh requires high interaction and ssh service",
        ));
    }
    if let Some(image) = config.get("base_image") {
        let image = image
            .as_str()
            .ok_or_else(|| AppError::invalid("base_image must be an absolute image path"))?;
        if !image.is_empty()
            && (!image.starts_with('/')
                || image.len() > 4096
                || image.chars().any(char::is_control))
        {
            return Err(AppError::invalid(
                "base_image must be an absolute image path",
            ));
        }
    }
    Ok(())
}

pub fn deployment_command(trap: &Trap) -> Result<AgentCommand, AppError> {
    validate_profile(
        trap.profile_snapshot.level,
        &trap.profile_snapshot.service_type,
        &trap.effective_config,
    )?;
    if trap.ports.len() != 1
        || trap.ports[0].transport != Transport::Tcp
        || trap.ports[0].route_mode != RouteMode::Direct
        || trap.ports[0].host_port == 0
    {
        return Err(AppError::conflict(
            "High SSH traps need one direct TCP port and cannot join a Dispatcher group",
        ));
    }
    let base_image = trap
        .effective_config
        .get("base_image")
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
        .unwrap_or(DEFAULT_BASE_IMAGE);
    let external_ssh_port = trap.ports[0].host_port;
    Ok(AgentCommand::DeployHighUbuntu(HighUbuntuDeployment {
        command_id: Uuid::new_v4(),
        trap_id: trap.trap_id,
        base_image: base_image.to_owned(),
        external_ssh_port,
    }))
}
