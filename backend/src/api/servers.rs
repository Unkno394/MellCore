use crate::management::Page;
use crate::{
    api::AppState,
    auth::Principal,
    errors::{AppError, RequestId},
    resources::{self, Server, ServerInput, ServerPage, UpdateServer},
};
use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Deserialize, Serialize, ToSchema)]
pub struct ServerPresence {
    pub registered: bool,
    pub connected: bool,
    pub can_reboot: bool,
    pub can_uninstall: bool,
}

#[derive(Serialize, ToSchema)]
pub struct DeleteServerResult {
    /// scheduled: agent accepted cleanup; unreachable or unsupported: only Center access was revoked.
    pub remote_cleanup: String,
}

#[derive(Deserialize)]
struct QueuedCommand { message_id: Uuid }

#[derive(Deserialize)]
struct CenterCommandStatus { status: String }

pub(crate) async fn agent_presence(state: &AppState, agent_id: Uuid) -> Result<ServerPresence, AppError> {
    serde_json::from_slice(&crate::api::server_bootstrap::center_request(
        state, "GET", format!("/v1/agents/{agent_id}/presence"), None,
    ).await?).map_err(|_| AppError::unavailable())
}


#[utoipa::path(post,path="/api/v1/servers",tag="servers",security(("bearer"=[])),request_body=ServerInput,responses((status=201,body=Server),(status=401,body=crate::errors::ErrorResponse),(status=403,body=crate::errors::ErrorResponse),(status=404,description="Missing or owned by another user",body=crate::errors::ErrorResponse),(status=409,body=crate::errors::ErrorResponse),(status=422,body=crate::errors::ErrorResponse),(status=503,body=crate::errors::ErrorResponse)))]
pub async fn create(
    State(state): State<AppState>,
    principal: Principal,
    Extension(request): Extension<RequestId>,
    Json(input): Json<ServerInput>,
) -> Result<(StatusCode, Json<Server>), AppError> {
    Ok((
        StatusCode::CREATED,
        Json(resources::servers::create(state.pool()?, &principal, request.0, input).await?),
    ))
}

#[utoipa::path(get,path="/api/v1/servers",tag="servers",security(("bearer"=[])),params(Page),responses((status=200,body=ServerPage),(status=401,body=crate::errors::ErrorResponse),(status=403,body=crate::errors::ErrorResponse),(status=404,description="Missing or owned by another user",body=crate::errors::ErrorResponse),(status=409,body=crate::errors::ErrorResponse),(status=422,body=crate::errors::ErrorResponse),(status=503,body=crate::errors::ErrorResponse)))]
pub async fn list(
    State(state): State<AppState>,
    principal: Principal,
    Query(query): Query<Page>,
) -> Result<Json<ServerPage>, AppError> {
    Ok(Json(
        resources::servers::list(state.pool()?, &principal, query).await?,
    ))
}

#[utoipa::path(get,path="/api/v1/servers/{server_id}",tag="servers",security(("bearer"=[])),params(("server_id"=Uuid,Path)),responses((status=200,body=Server),(status=401,body=crate::errors::ErrorResponse),(status=403,body=crate::errors::ErrorResponse),(status=404,description="Missing or owned by another user",body=crate::errors::ErrorResponse),(status=409,body=crate::errors::ErrorResponse),(status=422,body=crate::errors::ErrorResponse),(status=503,body=crate::errors::ErrorResponse)))]
pub async fn get(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Json<Server>, AppError> {
    Ok(Json(
        resources::servers::get(state.pool()?, &principal, id).await?,
    ))
}

#[utoipa::path(get,path="/api/v1/servers/{server_id}/presence",tag="servers",security(("bearer"=[])),params(("server_id"=Uuid,Path)),responses((status=200,body=ServerPresence),(status=404,body=crate::errors::ErrorResponse),(status=503,body=crate::errors::ErrorResponse)))]
pub async fn presence(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Json<ServerPresence>, AppError> {
    resources::servers::get(state.pool()?, &principal, id).await?;
    let agent_id: Option<Uuid> = sqlx::query_scalar("SELECT agent_id FROM center_agent_servers WHERE server_id=$1")
        .bind(id).fetch_optional(state.pool()?).await?;
    match agent_id {
        Some(agent_id) => Ok(Json(agent_presence(&state, agent_id).await?)),
        None => Ok(Json(ServerPresence { registered: false, connected: false, can_reboot: false, can_uninstall: false })),
    }
}

#[utoipa::path(put,path="/api/v1/servers/{server_id}",tag="servers",security(("bearer"=[])),params(("server_id"=Uuid,Path)),request_body=UpdateServer,responses((status=200,body=Server),(status=401,body=crate::errors::ErrorResponse),(status=403,body=crate::errors::ErrorResponse),(status=404,description="Missing or owned by another user",body=crate::errors::ErrorResponse),(status=409,body=crate::errors::ErrorResponse),(status=422,body=crate::errors::ErrorResponse),(status=503,body=crate::errors::ErrorResponse)))]
pub async fn update(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Uuid>,
    Extension(request): Extension<RequestId>,
    Json(input): Json<UpdateServer>,
) -> Result<Json<Server>, AppError> {
    Ok(Json(
        resources::servers::update(state.pool()?, &principal, id, request.0, input).await?,
    ))
}

#[utoipa::path(delete,path="/api/v1/servers/{server_id}",tag="servers",security(("bearer"=[])),params(("server_id"=Uuid,Path)),responses((status=200,body=DeleteServerResult),(status=401,body=crate::errors::ErrorResponse),(status=403,body=crate::errors::ErrorResponse),(status=404,description="Missing or owned by another user",body=crate::errors::ErrorResponse),(status=409,body=crate::errors::ErrorResponse),(status=422,body=crate::errors::ErrorResponse),(status=503,body=crate::errors::ErrorResponse)))]
pub async fn delete(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Uuid>,
    Extension(request): Extension<RequestId>,
) -> Result<Json<DeleteServerResult>, AppError> {
    let mut tx = resources::owned_tx(state.pool()?, &principal).await?;
    resources::servers::lock(&mut tx, principal.user.id, id).await?;
    let has_traps: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM traps WHERE server_id=$1 AND user_id=$2 AND actual_state <> 'removed')")
        .bind(id).bind(principal.user.id).fetch_one(&mut *tx).await?;
    let has_pending_actions: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM trap_action_jobs j JOIN traps t USING(trap_id) WHERE t.server_id=$1 AND j.status='queued')",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    let has_pending_server_actions: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM server_action_jobs WHERE server_id=$1 AND status='queued')",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    if has_traps || has_pending_actions || has_pending_server_actions {
        sqlx::query("UPDATE servers SET deletion_pending=FALSE WHERE server_id=$1 AND user_id=$2")
            .bind(id).bind(principal.user.id).execute(&mut *tx).await?;
        tx.commit().await?;
        if has_traps {
            return Err(AppError::conflict("Удалите ловушки этого сервера перед удалением сервера."));
        }
        return Err(AppError::conflict(
            "Дождитесь завершения команд сервера и ловушек перед удалением сервера.",
        ));
    }
    let agent_id: Option<Uuid> = sqlx::query_scalar("SELECT agent_id FROM center_agent_servers WHERE server_id=$1")
        .bind(id).fetch_optional(&mut *tx).await?;
    sqlx::query("UPDATE servers SET deletion_pending=TRUE WHERE server_id=$1 AND user_id=$2")
        .bind(id).bind(principal.user.id).execute(&mut *tx).await?;
    tx.commit().await?;

    let mut remote_cleanup = "not_installed";
    let remote_result: Result<(), AppError> = async {
        if let Some(agent_id) = agent_id {
            let presence = agent_presence(&state, agent_id).await?;
            if presence.can_uninstall {
                let command = hf_core::AgentCommand::UninstallAgent { command_id: Uuid::new_v4() };
                let queued: QueuedCommand = serde_json::from_slice(&crate::api::server_bootstrap::center_request(
                    &state, "POST", format!("/v1/agents/{agent_id}/commands"),
                    Some(serde_json::to_vec(&command).map_err(|_| AppError::internal())?),
                ).await?).map_err(|_| AppError::unavailable())?;
                let mut applied = false;
                for _ in 0..60 {
                    let current: CenterCommandStatus = serde_json::from_slice(&crate::api::server_bootstrap::center_request(
                        &state, "GET", format!("/v1/agents/{agent_id}/commands/{}", queued.message_id), None,
                    ).await?).map_err(|_| AppError::unavailable())?;
                    match current.status.as_str() {
                        "applied" => { applied = true; break; }
                        "rejected" => return Err(AppError::conflict("Агент отказался удалиться. Проверьте локальные ловушки и журнал hf-agent.")),
                        "queued" => tokio::time::sleep(std::time::Duration::from_millis(500)).await,
                        _ => return Err(AppError::unavailable()),
                    }
                }
                if !applied { return Err(AppError::conflict("Агент не подтвердил удаление за 30 секунд. Повторите после проверки связи.")); }
                remote_cleanup = "scheduled";
            } else {
                remote_cleanup = if presence.connected { "unsupported" } else { "unreachable" };
            }
            match crate::api::server_bootstrap::center_request(
                &state, "POST", format!("/v1/agents/{agent_id}/revoke"), None,
            ).await {
                Ok(_) => {}
                Err(error) if error.status == StatusCode::NOT_FOUND => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }.await;
    if let Err(error) = remote_result {
        let _ = sqlx::query("UPDATE servers SET deletion_pending=FALSE WHERE server_id=$1 AND user_id=$2")
            .bind(id).bind(principal.user.id).execute(state.pool()?).await;
        return Err(error);
    }

    let delete_result: Result<(), AppError> = async {
        let mut tx = resources::owned_tx(state.pool()?, &principal).await?;
        resources::servers::lock(&mut tx, principal.user.id, id).await?;
        let has_traps: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM traps WHERE server_id=$1 AND user_id=$2 AND actual_state <> 'removed')")
            .bind(id).bind(principal.user.id).fetch_one(&mut *tx).await?;
        let has_pending_actions: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM trap_action_jobs j JOIN traps t USING(trap_id) WHERE t.server_id=$1 AND j.status='queued')",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        let has_pending_server_actions: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM server_action_jobs WHERE server_id=$1 AND status='queued')",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        if has_traps || has_pending_actions || has_pending_server_actions {
            return Err(AppError::conflict("Ловушка или команда появилась во время удаления сервера. Завершите её и повторите."));
        }
        // Removed trap rows are tombstones. Drop them before the server while the
        // telemetry migration detaches their retained events instead of deleting them.
        sqlx::query("DELETE FROM traps WHERE server_id=$1 AND user_id=$2 AND actual_state='removed'")
            .bind(id).bind(principal.user.id).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM servers WHERE server_id=$1 AND user_id=$2")
            .bind(id).bind(principal.user.id).execute(&mut *tx).await?;
        crate::management::audit(&mut tx, principal.user.id, "server.delete", id, request.0).await?;
        tx.commit().await?;
        Ok(())
    }.await;
    if let Err(error) = delete_result {
        sqlx::query("UPDATE servers SET deletion_pending=FALSE WHERE server_id=$1 AND user_id=$2")
            .bind(id).bind(principal.user.id).execute(state.pool()?).await?;
        return Err(error);
    }
    Ok(Json(DeleteServerResult { remote_cleanup: remote_cleanup.into() }))
}

#[utoipa::path(get,path="/api/v1/servers/{server_id}/ports",tag="servers",security(("bearer"=[])),params(("server_id"=Uuid,Path)),responses((status=200,body=[crate::resources::PortReservation]),(status=401,body=crate::errors::ErrorResponse),(status=404,body=crate::errors::ErrorResponse)))]
pub async fn ports(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<crate::resources::PortReservation>>, AppError> {
    Ok(Json(
        resources::servers::ports(state.pool()?, &principal, id).await?,
    ))
}
