//! Contracts only: no SSH/network/dispatcher implementation and no background execution.
use crate::{
    models::{ActualState, CommandType},
    resources::{Server, Trap},
};
use serde::{Deserialize, Serialize};
use std::{future::Future, pin::Pin};
use utoipa::ToSchema;
use uuid::Uuid;

/// A reference MUST be resolved within this owner's secret namespace, not globally.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct CredentialScope {
    pub user_id: Uuid,
    pub server_id: Uuid,
    pub credential_ref: Uuid,
}
/// A future worker builds this from authorized database snapshots, never client IDs.
#[derive(Serialize, ToSchema)]
pub struct DeploymentRequest {
    pub command_id: Uuid,
    pub operation: CommandType,
    pub server: Server,
    pub trap: Trap,
    pub credential: Option<CredentialScope>,
}
#[derive(Serialize, Deserialize, ToSchema)]
pub struct DeploymentReport {
    pub command_id: Uuid,
    pub trap_id: Uuid,
    pub applied_version: i64,
    pub actual_state: ActualState,
    pub error_code: Option<String>,
}
#[derive(Debug)]
pub enum InfrastructureError {
    NotConfigured,
    Unavailable,
}
pub type Execution<'a> =
    Pin<Box<dyn Future<Output = Result<DeploymentReport, InfrastructureError>> + Send + 'a>>;
/// Implementations must verify SSH host keys, scoped credentials and idempotency.
/// Implementing this trait alone does not expose an API or enable deployment.
pub trait InfrastructureGateway: Send + Sync {
    fn execute<'a>(&'a self, request: DeploymentRequest) -> Execution<'a>;
}
/// Dispatcher owns the public TCP listener; each backend port has an exclusive
/// reservation with route_mode=dispatcher_backend. Selection policy is not defined yet.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct DispatcherBackend {
    pub trap_id: Uuid,
    pub host_port: u16,
    pub config_version: i64,
}
#[derive(Serialize, Deserialize, ToSchema)]
pub struct DispatcherPlan {
    pub server_id: Uuid,
    pub listener_port: u16,
    pub backends: Vec<DispatcherBackend>,
}
