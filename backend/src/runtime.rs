use serde::Serialize;
use utoipa::ToSchema;

use crate::{errors::AppError, resources::Trap};

#[derive(Serialize, ToSchema)]
#[serde(untagged)]
pub enum RuntimeConfig {
    Kozyavka(crate::kozyavka::RuntimeConfig),
    Pritvoryashka(Box<crate::pritvoryashka::RuntimeConfig>),
}

pub fn for_trap(
    trap: &Trap,
    telemetry_endpoint: Option<String>,
) -> Result<RuntimeConfig, AppError> {
    match trap.profile_snapshot.honeypot_type.as_str() {
        "kozyavka" => crate::kozyavka::runtime_config(trap).map(RuntimeConfig::Kozyavka),
        "pritvoryashka" => crate::pritvoryashka::runtime_config(trap, telemetry_endpoint)
            .map(Box::new)
            .map(RuntimeConfig::Pritvoryashka),
        _ => Err(AppError::conflict(
            "Runtime configuration adapter is not available for this profile",
        )),
    }
}
