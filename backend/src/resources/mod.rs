pub mod servers;
pub mod traps;

use crate::{
    auth::Principal,
    errors::AppError,
    management::{self, Page, Profile},
    models::{ActualState, Role},
};
use chrono::{DateTime, Utc};
use hf_core::ContainerResourceLimits as AgentContainerResourceLimits;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, ToSchema, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum ServerStatus {
    Unknown,
    Online,
    Offline,
    Error,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, ToSchema, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum TrapDesiredState {
    Running,
    Stopped,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash, ToSchema, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum Transport {
    Tcp,
    Udp,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, ToSchema, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum RouteMode {
    Direct,
    DispatcherBackend,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, ToSchema, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum PortPurpose {
    Ssh,
    Dispatcher,
    Trap,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContainerResourceLimits {
    #[schema(minimum = 0.05, maximum = 1.0)]
    pub cpu_cores: f64,
    #[schema(minimum = 32, maximum = 512)]
    pub memory_mb: u32,
    #[schema(minimum = 16, maximum = 256)]
    pub pids: u32,
}

impl ContainerResourceLimits {
    pub fn low_default() -> Self {
        Self {
            cpu_cores: 0.5,
            memory_mb: 128,
            pids: 64,
        }
    }

    pub fn middle_default() -> Self {
        Self {
            cpu_cores: 1.0,
            memory_mb: 512,
            pids: 256,
        }
    }

    pub fn validate_for_level(&self, level: crate::models::TrapLevel) -> Result<(), AppError> {
        let (cpu, memory, pids) = match level {
            crate::models::TrapLevel::Low => (0.5, 128, 64),
            crate::models::TrapLevel::Medium => (1.0, 512, 256),
            crate::models::TrapLevel::High => (0.5, 128, 64),
        };
        if !self.cpu_cores.is_finite()
            || self.cpu_cores < 0.05
            || self.cpu_cores > cpu
            || !(32..=memory).contains(&self.memory_mb)
            || !(16..=pids).contains(&self.pids)
        {
            return Err(AppError::invalid(
                "Container resource limits are outside the selected trap tier policy",
            ));
        }
        Ok(())
    }
}

impl Default for ContainerResourceLimits {
    fn default() -> Self {
        Self::low_default()
    }
}

impl From<ContainerResourceLimits> for AgentContainerResourceLimits {
    fn from(value: ContainerResourceLimits) -> Self {
        Self {
            cpu_cores: value.cpu_cores,
            memory_mb: value.memory_mb,
            pids: value.pids,
        }
    }
}

#[derive(Clone, Default, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ServerSettings {
    #[schema(minimum = 1, maximum = 1024)]
    pub cpu_limit: Option<u16>,
    #[schema(minimum = 16, maximum = 1048576)]
    pub memory_limit_mb: Option<u32>,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ServerInput {
    pub name: String,
    /// DNS hostname or IP literal, without URL scheme, credentials or port.
    pub host: String,
    #[serde(default = "default_ssh_port")]
    #[schema(minimum = 1, maximum = 65535, default = 22)]
    pub ssh_port: u16,
    pub ssh_user: String,
    /// Opaque reference scoped to the authenticated user; never an SSH key/password.
    pub credential_ref: Option<Uuid>,
    #[schema(minimum = 1, maximum = 65535)]
    pub dispatcher_port: Option<u16>,
    #[serde(default)]
    pub settings: ServerSettings,
}
fn default_ssh_port() -> u16 {
    22
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateServer {
    #[schema(minimum = 1)]
    pub expected_version: i64,
    pub server: ServerInput,
}
#[derive(Serialize, FromRow, ToSchema)]
pub struct Server {
    pub server_id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub host: String,
    pub ssh_port: i32,
    pub ssh_user: String,
    pub credential_ref: Option<Uuid>,
    pub dispatcher_port: Option<i32>,
    #[sqlx(json)]
    pub settings: ServerSettings,
    pub status: ServerStatus,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
#[derive(Serialize, ToSchema)]
pub struct ServerPage {
    pub items: Vec<Server>,
    pub next_cursor: Option<Uuid>,
}

#[derive(Clone, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PortBinding {
    pub transport: Transport,
    #[schema(minimum = 1, maximum = 65535)]
    pub host_port: u16,
    #[schema(minimum = 1, maximum = 65535)]
    pub target_port: u16,
    pub route_mode: RouteMode,
    #[serde(default)]
    pub weight: Option<u8>,
}
#[derive(Serialize, FromRow, ToSchema)]
pub struct PortReservation {
    pub server_id: Uuid,
    pub transport: Transport,
    pub host_port: i32,
    pub purpose: PortPurpose,
    pub trap_id: Option<Uuid>,
    pub target_port: Option<i32>,
    pub route_mode: Option<RouteMode>,
    pub weight: Option<i32>,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TrapInput {
    pub name: String,
    pub profile_id: Uuid,
    /// Shallow top-level overrides over the selected profile config.
    pub config: Value,
    /// Optional per-container budget; omitted values inherit profile defaults.
    #[serde(default)]
    pub resources: Option<ContainerResourceLimits>,
    pub desired_state: TrapDesiredState,
    #[schema(max_items = 32)]
    pub ports: Vec<PortBinding>,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateTrap {
    pub server_id: Uuid,
    pub trap: TrapInput,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateTrap {
    #[schema(minimum = 1)]
    pub expected_version: i64,
    pub trap: TrapInput,
}
#[derive(Serialize, FromRow, ToSchema)]
pub struct Trap {
    pub trap_id: Uuid,
    pub server_id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub profile_id: Uuid,
    pub profile_version: i64,
    #[sqlx(json)]
    pub profile_snapshot: Profile,
    pub config: Value,
    pub effective_config: Value,
    #[sqlx(json)]
    pub resources: ContainerResourceLimits,
    pub desired_state: TrapDesiredState,
    pub actual_state: ActualState,
    pub version: i64,
    #[sqlx(json)]
    pub ports: Vec<PortBinding>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
#[derive(Serialize, ToSchema)]
pub struct TrapPage {
    pub items: Vec<Trap>,
    pub next_cursor: Option<Uuid>,
}
#[derive(Default, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in=Query)]
pub struct TrapQuery {
    pub server_id: Option<Uuid>,
    pub after: Option<Uuid>,
    pub limit: Option<u32>,
}
impl TrapQuery {
    pub fn page(&self) -> Page {
        Page {
            after: self.after,
            limit: self.limit,
        }
    }
}

impl ServerInput {
    pub fn validate(&mut self) -> Result<(), AppError> {
        self.name = management::display_name(&self.name)?;
        self.host = normalize_host(&self.host)?;
        if self.ssh_port == 0
            || self.dispatcher_port == Some(0)
            || self.dispatcher_port == Some(self.ssh_port)
        {
            return Err(AppError::invalid("Invalid or conflicting management ports"));
        }
        let bytes = self.ssh_user.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 64
            || !(bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
            || !bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(b))
        {
            return Err(AppError::invalid("Invalid SSH username"));
        }
        if self.credential_ref.is_some_and(|id| id.is_nil())
            || self
                .settings
                .cpu_limit
                .is_some_and(|n| !(1..=1024).contains(&n))
            || self
                .settings
                .memory_limit_mb
                .is_some_and(|n| !(16..=1048576).contains(&n))
        {
            return Err(AppError::invalid("Invalid server settings"));
        }
        Ok(())
    }
}
pub fn normalize_host(host: &str) -> Result<String, AppError> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(ip.to_string());
    }
    let host = host.to_ascii_lowercase();
    if host.is_empty()
        || host.len() > 253
        || !host.is_ascii()
        || !host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
    {
        return Err(AppError::invalid(
            "Host must be a hostname or IP without scheme, port or credentials",
        ));
    }
    Ok(host)
}
impl TrapInput {
    pub fn validate(&mut self) -> Result<(), AppError> {
        self.name = management::display_name(&self.name)?;
        if self.profile_id.is_nil() {
            return Err(AppError::invalid("Invalid profile ID"));
        }
        management::validate_config(&self.config)?;
        if self.ports.len() > 32 {
            return Err(AppError::invalid("At most 32 port bindings are allowed"));
        }
        let mut seen = std::collections::HashSet::new();
        for port in &self.ports {
            if port.host_port == 0
                || port.target_port == 0
                || !seen.insert((port.transport, port.host_port))
                || (port.route_mode == RouteMode::DispatcherBackend
                    && port.transport != Transport::Tcp)
                || port
                    .weight
                    .is_some_and(|weight| weight == 0 || weight > 100)
                || (port.route_mode == RouteMode::Direct && port.weight.is_some())
            {
                return Err(AppError::invalid("Invalid or duplicate port binding"));
            }
        }
        Ok(())
    }
}

/// Lock account before the server row; current role/token are rechecked on writes.
/// No role bypasses ownership; Viewer preserves the existing read-only contract.
pub async fn owned_tx<'a>(
    pool: &'a PgPool,
    principal: &Principal,
) -> Result<Transaction<'a, Postgres>, AppError> {
    let mut tx = pool.begin().await?;
    let role: Role =
        sqlx::query_scalar("SELECT role FROM users WHERE id=$1 AND is_active FOR SHARE")
            .bind(principal.user.id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(AppError::unauthorized)?;
    if role == Role::Viewer {
        return Err(AppError::forbidden());
    }
    let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM access_tokens WHERE id=$1 AND user_id=$2 AND expires_at>now())").bind(principal.token_id).bind(principal.user.id).fetch_one(&mut *tx).await?;
    if !valid {
        return Err(AppError::unauthorized());
    }
    Ok(tx)
}
pub fn check_version(actual: i64, expected: i64) -> Result<(), AppError> {
    if expected < 1 {
        return Err(AppError::invalid("expected_version must be positive"));
    }
    if actual != expected {
        return Err(AppError::conflict("Resource version has changed"));
    }
    Ok(())
}
