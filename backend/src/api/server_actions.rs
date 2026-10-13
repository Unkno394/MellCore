use axum::{Extension, Json, extract::{Path, State}, http::StatusCode};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{api::{AppState, server_bootstrap::center_request}, auth::Principal, errors::{AppError, RequestId}, resources,};
use hf_core::AgentCommand;

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ServerActionInput { pub action: String }

#[derive(Serialize, ToSchema)]
pub struct ServerActionProgress {
    pub action_id: Uuid,
    pub action: String,
    pub status: String,
    pub detail: Option<String>,
}

#[derive(Deserialize)]
struct QueuedCommand { message_id: Uuid }

#[derive(Deserialize)]
struct CenterCommandStatus { status: String, detail: Option<String> }

#[utoipa::path(post,path="/api/v1/servers/{server_id}/actions",tag="servers",security(("bearer"=[])),params(("server_id"=Uuid,Path)),request_body=ServerActionInput,responses((status=202,body=ServerActionProgress),(status=404,body=crate::errors::ErrorResponse),(status=409,body=crate::errors::ErrorResponse)))]
pub async fn start(
    State(state): State<AppState>, principal: Principal, Path(server_id): Path<Uuid>,
    Extension(_request): Extension<RequestId>, Json(input): Json<ServerActionInput>,
) -> Result<(StatusCode, Json<ServerActionProgress>), AppError> {
    if input.action != "reboot" { return Err(AppError::invalid("Unsupported server action")); }
    resources::servers::get(state.pool()?, &principal, server_id).await?;
    let agent_id: Uuid = sqlx::query_scalar("SELECT agent_id FROM center_agent_servers WHERE server_id=$1")
        .bind(server_id).fetch_optional(state.pool()?).await?.ok_or_else(AppError::not_found)?;
    let presence = crate::api::servers::agent_presence(&state, agent_id).await?;
    if !presence.connected {
        return Err(AppError::conflict("Агент сейчас не отвечает Центру; перезагрузка не отправлена."));
    }
    if !presence.can_reboot {
        return Err(AppError::conflict("Для перезагрузки нужно обновить hf-agent на сервере."));
    }
    let mut tx = resources::owned_tx(state.pool()?, &principal).await?;
    resources::servers::lock(&mut tx, principal.user.id, server_id).await?;
    let deletion_pending: bool = sqlx::query_scalar(
        "SELECT deletion_pending FROM servers WHERE server_id=$1",
    )
    .bind(server_id)
    .fetch_one(&mut *tx)
    .await?;
    if deletion_pending {
        return Err(AppError::conflict("This server is being deleted."));
    }
    let command = AgentCommand::RebootSystem { command_id: Uuid::new_v4() };
    let queued: QueuedCommand = serde_json::from_slice(&center_request(
        &state, "POST", format!("/v1/agents/{agent_id}/commands"),
        Some(serde_json::to_vec(&command).map_err(|_| AppError::internal())?),
    ).await?).map_err(|_| AppError::unavailable())?;
    sqlx::query("INSERT INTO server_action_jobs(action_id,server_id,agent_id,action) VALUES($1,$2,$3,'reboot')")
        .bind(queued.message_id).bind(server_id).bind(agent_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(ServerActionProgress {
        action_id: queued.message_id, action: "reboot".into(), status: "queued".into(), detail: None,
    })))
}

#[utoipa::path(get,path="/api/v1/servers/{server_id}/actions/{action_id}",tag="servers",security(("bearer"=[])),params(("server_id"=Uuid,Path),("action_id"=Uuid,Path)),responses((status=200,body=ServerActionProgress),(status=404,body=crate::errors::ErrorResponse)))]
pub async fn status(
    State(state): State<AppState>, principal: Principal, Path((server_id, action_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ServerActionProgress>, AppError> {
    let row = sqlx::query("SELECT j.agent_id,j.action,j.status,j.detail FROM server_action_jobs j JOIN servers s USING(server_id) WHERE j.server_id=$1 AND j.action_id=$2 AND s.user_id=$3")
        .bind(server_id).bind(action_id).bind(principal.user.id).fetch_optional(state.pool()?).await?.ok_or_else(AppError::not_found)?;
    let agent_id: Uuid = row.get("agent_id");
    let action: String = row.get("action");
    let stored_status: String = row.get("status");
    let stored_detail: Option<String> = row.get("detail");
    if stored_status != "queued" {
        return Ok(Json(ServerActionProgress { action_id, action, status: stored_status, detail: stored_detail }));
    }
    let current: CenterCommandStatus = serde_json::from_slice(&center_request(
        &state, "GET", format!("/v1/agents/{agent_id}/commands/{action_id}"), None,
    ).await?).map_err(|_| AppError::unavailable())?;
    let status = match current.status.as_str() {
        "applied" => "succeeded",
        "rejected" => "failed",
        "queued" => "queued",
        _ => return Err(AppError::unavailable()),
    };
    if status != "queued" {
        sqlx::query("UPDATE server_action_jobs SET status=$2,detail=$3,updated_at=now() WHERE action_id=$1 AND status='queued'")
            .bind(action_id).bind(status).bind(&current.detail).execute(state.pool()?).await?;
    }
    Ok(Json(ServerActionProgress { action_id, action, status: status.into(), detail: current.detail }))
}
