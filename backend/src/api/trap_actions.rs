use crate::{
    api::AppState,
    auth::Principal,
    errors::{AppError, RequestId},
    management,
    resources::{self, Trap},
};
use axum::{Extension, Json, extract::{Path, State}, http::StatusCode};
use hf_core::{AgentCommand, PritvoryashkaDeployment};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Clone, Copy, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TrapAction {
    Start,
    Stop,
    Restart,
    Remove,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TrapActionRequest {
    pub action: TrapAction,
}

#[derive(Serialize, ToSchema)]
pub struct TrapActionProgress {
    pub action_id: Uuid,
    pub status: String,
    pub detail: Option<String>,
}

#[derive(Deserialize)]
struct QueuedCommand { message_id: Uuid }

#[derive(Deserialize)]
struct CenterCommandStatus { status: String, detail: Option<String> }

#[utoipa::path(post, path="/api/v1/traps/{trap_id}/actions", tag="traps", security(("bearer"=[])), params(("trap_id"=Uuid, Path)), request_body=TrapActionRequest, responses((status=202, body=TrapActionProgress), (status=401, body=crate::errors::ErrorResponse), (status=404, body=crate::errors::ErrorResponse), (status=409, body=crate::errors::ErrorResponse), (status=503, body=crate::errors::ErrorResponse)))]
pub async fn start(
    State(state): State<AppState>, principal: Principal, Path(trap_id): Path<Uuid>,
    Extension(request_id): Extension<RequestId>, Json(input): Json<TrapActionRequest>,
) -> Result<(StatusCode, Json<TrapActionProgress>), AppError> {
    resources::owned_tx(state.pool()?, &principal).await?.commit().await?;
    let trap = resources::traps::get(state.pool()?, &principal, trap_id).await?;
    let agent_id: Uuid = sqlx::query_scalar("SELECT cas.agent_id FROM traps t JOIN center_agent_servers cas ON cas.server_id=t.server_id JOIN servers s ON s.server_id=t.server_id AND s.user_id=t.user_id WHERE t.trap_id=$1 AND t.user_id=$2 AND s.status='online'")
        .bind(trap_id).bind(principal.user.id).fetch_optional(state.pool()?).await?.ok_or_else(AppError::not_found)?;
    let action_id = Uuid::new_v4();
    let commands = commands_for(input.action, &trap)?;
    let mut message_ids = Vec::with_capacity(commands.len());
    for command in commands {
        let body = serde_json::to_vec(&command).map_err(|_| AppError::internal())?;
        let queued: QueuedCommand = serde_json::from_slice(&crate::api::server_bootstrap::center_request(
            &state, "POST", format!("/v1/agents/{agent_id}/commands"), Some(body),
        ).await?).map_err(|_| AppError::unavailable())?;
        message_ids.push(queued.message_id);
    }
    let action_name = match input.action { TrapAction::Start => "start", TrapAction::Stop => "stop", TrapAction::Restart => "restart", TrapAction::Remove => "remove" };
    sqlx::query("INSERT INTO trap_action_jobs(action_id,trap_id,agent_id,action,command_ids) VALUES($1,$2,$3,$4,$5)")
        .bind(action_id).bind(trap_id).bind(agent_id).bind(action_name).bind(&message_ids)
        .execute(state.pool()?).await?;
    let mut tx = state.pool()?.begin().await?;
    management::audit(&mut tx, principal.user.id, "trap.action_queued", trap_id, request_id.0).await?;
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(TrapActionProgress { action_id, status: "queued".into(), detail: None })))
}

#[utoipa::path(get, path="/api/v1/traps/{trap_id}/actions/{action_id}", tag="traps", security(("bearer"=[])), params(("trap_id"=Uuid, Path), ("action_id"=Uuid, Path)), responses((status=200, body=TrapActionProgress), (status=401, body=crate::errors::ErrorResponse), (status=404, body=crate::errors::ErrorResponse), (status=503, body=crate::errors::ErrorResponse)))]
pub async fn status(
    State(state): State<AppState>, principal: Principal, Path((trap_id, action_id)): Path<(Uuid, Uuid)>,
    Extension(request_id): Extension<RequestId>,
) -> Result<Json<TrapActionProgress>, AppError> {
    resources::owned_tx(state.pool()?, &principal).await?.commit().await?;
    let row = sqlx::query("SELECT j.agent_id,j.action,j.command_ids,j.status,j.detail FROM trap_action_jobs j JOIN traps t ON t.trap_id=j.trap_id WHERE j.action_id=$1 AND j.trap_id=$2 AND t.user_id=$3")
        .bind(action_id).bind(trap_id).bind(principal.user.id).fetch_optional(state.pool()?).await?.ok_or_else(AppError::not_found)?;
    let agent_id: Uuid = row.get("agent_id");
    let action: String = row.get("action");
    let message_ids: Vec<Uuid> = row.get("command_ids");
    let previous: String = row.get("status");
    if previous != "queued" { return Ok(Json(TrapActionProgress { action_id, status: previous, detail: row.get("detail") })); }

    let mut statuses = Vec::with_capacity(message_ids.len());
    for message_id in message_ids {
        let response: CenterCommandStatus = serde_json::from_slice(&crate::api::server_bootstrap::center_request(
            &state, "GET", format!("/v1/agents/{agent_id}/commands/{message_id}"), None,
        ).await?).map_err(|_| AppError::unavailable())?;
        statuses.push(response);
    }
    let rejected = statuses.iter().find(|status| status.status == "rejected");
    let all_applied = !statuses.is_empty() && statuses.iter().all(|status| status.status == "applied");
    let status = if rejected.is_some() { "failed" } else if all_applied { "succeeded" } else { "queued" };
    let detail = rejected.and_then(|item| item.detail.clone());
    if status != "queued" {
        sqlx::query("UPDATE trap_action_jobs SET status=$2,detail=$3,updated_at=now() WHERE action_id=$1")
            .bind(action_id).bind(status).bind(&detail).execute(state.pool()?).await?;
        if status == "succeeded" {
            match action.as_str() {
                "start" | "restart" => {
                    sqlx::query("UPDATE traps SET desired_state='running',actual_state='running',updated_at=now() WHERE trap_id=$1")
                        .bind(trap_id).execute(state.pool()?).await?;
                    sqlx::query("UPDATE center_agent_traps SET state='running',updated_at=now() WHERE trap_id=$1")
                        .bind(trap_id).execute(state.pool()?).await?;
                }
                "stop" => { sqlx::query("UPDATE traps SET desired_state='stopped',actual_state='stopped',updated_at=now() WHERE trap_id=$1")
                    .bind(trap_id).execute(state.pool()?).await?; }
                "remove" => {
                    // Center marks the trap removed only after the agent's ACK.
                    sqlx::query("UPDATE traps SET desired_state='stopped',actual_state='removed',updated_at=now() WHERE trap_id=$1 AND user_id=$2")
                        .bind(trap_id).bind(principal.user.id).execute(state.pool()?).await?;
                    resources::traps::delete(state.pool()?, &principal, trap_id, request_id.0).await?;
                }
                _ => {}
            }
        }
    }
    Ok(Json(TrapActionProgress { action_id, status: status.into(), detail }))
}

fn commands_for(action: TrapAction, trap: &Trap) -> Result<Vec<AgentCommand>, AppError> {
    let stop = || AgentCommand::StopTrap { command_id: Uuid::new_v4(), trap_id: trap.trap_id };
    let remove = || AgentCommand::RemoveTrap { command_id: Uuid::new_v4(), trap_id: trap.trap_id };
    let deploy = || -> Result<AgentCommand, AppError> {
        match trap.profile_snapshot.honeypot_type.as_str() {
            "kozyavka" => crate::kozyavka::deployment_command(trap),
            "pritvoryashka" => {
                let settings = crate::pritvoryashka::validate_profile(trap.profile_snapshot.level, &trap.profile_snapshot.service_type, &trap.effective_config)?;
                let port = trap.ports.first().ok_or_else(AppError::internal)?;
                let host_port = u16::try_from(port.host_port).map_err(|_| AppError::internal())?;
                let max_connections = u16::try_from(settings.max_connections.min(128)).map_err(|_| AppError::internal())?;
                Ok(AgentCommand::DeployPritvoryashka(PritvoryashkaDeployment {
                    command_id: Uuid::new_v4(), trap_id: trap.trap_id, server_id: trap.server_id,
                    host_port, publish_address: if port.route_mode == crate::resources::RouteMode::Direct { "0.0.0.0" } else { "127.0.0.1" }.into(),
                    hostname: settings.hostname, max_connections,
                    resources: trap.resources.into(),
                }))
            }
            _ => Err(AppError::conflict("No deployment recipe is available for this trap")),
        }
    };
    match action {
        TrapAction::Start => Ok(vec![deploy()?]),
        TrapAction::Stop => Ok(vec![stop()]),
        TrapAction::Restart => Ok(vec![stop(), deploy()?]),
        TrapAction::Remove => Ok(vec![remove()]),
    }
}
