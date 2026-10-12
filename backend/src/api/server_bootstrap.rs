//! Authenticated management bridge to Center's loopback SSH installer.
//! SSH credentials exist only in the request and are never written to PostgreSQL.
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

use axum::{Extension, Json, extract::{Path, State}, http::StatusCode};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    api::AppState,
    auth::Principal,
    errors::{AppError, RequestId},
    resources::{self, ServerInput},
};

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BootstrapServerInput {
    pub server: ServerInput,
    #[schema(write_only)]
    pub ssh_password: Option<String>,
    #[schema(write_only)]
    pub ssh_private_key: Option<String>,
    #[schema(write_only)]
    pub ssh_key_passphrase: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct BootstrapProgress {
    pub server_id: Uuid,
    pub agent_id: Uuid,
    pub status: String,
    pub registered: bool,
    pub message: Option<String>,
}

#[derive(Serialize)]
struct CenterRequest<'a> {
    host: &'a str,
    ssh_port: u16,
    ssh_user: &'a str,
    ssh_password: &'a Option<String>,
    ssh_private_key: &'a Option<String>,
    ssh_key_passphrase: &'a Option<String>,
}

#[derive(Deserialize)]
struct CenterStart {
    job_id: Uuid,
    agent_id: Uuid,
}

#[derive(Deserialize)]
struct CenterProgress {
    agent_id: Uuid,
    status: String,
    registered: bool,
    message: Option<String>,
}

fn validate_auth(input: &BootstrapServerInput) -> Result<(), AppError> {
    let password = input.ssh_password.is_some();
    let key = input.ssh_private_key.is_some();
    if password == key || input.ssh_password.as_ref().is_some_and(|s| s.is_empty() || s.len() > 8192)
        || input.ssh_private_key.as_ref().is_some_and(|s| s.is_empty() || s.len() > 65536)
        || input.ssh_key_passphrase.as_ref().is_some_and(|s| s.len() > 8192)
        || (!key && input.ssh_key_passphrase.is_some())
    {
        return Err(AppError::invalid("Supply exactly one SSH password or private key"));
    }
    Ok(())
}

fn center_token(state: &AppState) -> Result<String, AppError> {
    let token = state.config.center_control_token.as_ref().ok_or_else(AppError::unavailable)?.expose();
    if !token.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)) {
        return Err(AppError::internal());
    }
    Ok(token.to_owned())
}

pub(crate) async fn center_request(state: &AppState, method: &'static str, path: String, body: Option<Vec<u8>>)
    -> Result<Vec<u8>, AppError>
{
    let token = center_token(state)?;
    tokio::task::spawn_blocking(move || {
        let address: SocketAddr = "127.0.0.1:18081".parse().map_err(|_| AppError::internal())?;
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))
            .map_err(|_| AppError::unavailable())?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).map_err(|_| AppError::unavailable())?;
        stream.set_write_timeout(Some(Duration::from_secs(5))).map_err(|_| AppError::unavailable())?;
        let body = body.unwrap_or_default();
        let header = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Honeyforge-Control-Token: {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(header.as_bytes()).map_err(|_| AppError::unavailable())?;
        stream.write_all(&body).map_err(|_| AppError::unavailable())?;
        let mut response = Vec::new();
        stream.take(131_072).read_to_end(&mut response).map_err(|_| AppError::unavailable())?;
        let split = response.windows(4).position(|window| window == b"\r\n\r\n")
            .ok_or_else(AppError::unavailable)?;
        let status = std::str::from_utf8(&response[..split]).map_err(|_| AppError::unavailable())?;
        let status = status.split_whitespace().nth(1).and_then(|s| s.parse::<u16>().ok())
            .ok_or_else(AppError::unavailable)?;
        match status {
            200..=299 => Ok(response[split + 4..].to_vec()),
            400 | 422 => Err(AppError::invalid("Center rejected the management command")),
            404 => Err(AppError::not_found()),
            409 => Err(AppError::conflict("Center rejected the command due to the current server or trap state")),
            410 => Err(AppError::conflict("Agent access has been revoked")),
            _ => Err(AppError::unavailable()),
        }
    }).await.map_err(|_| AppError::unavailable())?
}

#[utoipa::path(post,path="/api/v1/servers/bootstrap",tag="servers",security(("bearer"=[])),
    request_body=BootstrapServerInput,
    responses((status=202,body=BootstrapProgress),(status=401,body=crate::errors::ErrorResponse),
        (status=403,body=crate::errors::ErrorResponse),(status=422,body=crate::errors::ErrorResponse),
        (status=503,body=crate::errors::ErrorResponse)))]
pub async fn start(
    State(state): State<AppState>,
    principal: Principal,
    Extension(request): Extension<RequestId>,
    Json(mut input): Json<BootstrapServerInput>,
) -> Result<(StatusCode, Json<BootstrapProgress>), AppError> {
    validate_auth(&input)?;
    input.server.validate()?;
    if input.server.credential_ref.is_some() || input.server.dispatcher_port.is_some() {
        return Err(AppError::invalid("SSH bootstrap does not accept credential references or dispatcher ports"));
    }
    center_token(&state)?;
    let body = serde_json::to_vec(&CenterRequest {
        host: &input.server.host, ssh_port: input.server.ssh_port, ssh_user: &input.server.ssh_user,
        ssh_password: &input.ssh_password, ssh_private_key: &input.ssh_private_key,
        ssh_key_passphrase: &input.ssh_key_passphrase,
    }).map_err(|_| AppError::internal())?;
    let server = resources::servers::create(state.pool()?, &principal, request.0, input.server).await?;
    let started: CenterStart = match center_request(&state, "POST", "/v1/agents/bootstrap".into(), Some(body)).await
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|_| AppError::unavailable()))
    {
        Ok(started) => started,
        Err(error) => {
            sqlx::query("DELETE FROM servers WHERE server_id=$1 AND user_id=$2")
                .bind(server.server_id).bind(principal.user.id).execute(state.pool()?).await?;
            return Err(error);
        }
    };
    let registration = async {
        let mut tx = state.pool()?.begin().await?;
        sqlx::query("INSERT INTO center_agent_servers(agent_id,server_id) VALUES($1,$2)")
            .bind(started.agent_id).bind(server.server_id).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO server_bootstrap_jobs(server_id,job_id,agent_id) VALUES($1,$2,$3)")
            .bind(server.server_id).bind(started.job_id).bind(started.agent_id).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok::<_, AppError>(())
    }.await;
    if let Err(error) = registration {
        // A Center job was already accepted. Invalidate its enrollment token
        // before removing the local server so it cannot become an orphan agent.
        let _ = center_request(&state, "POST", format!("/v1/agents/{}/revoke", started.agent_id), None).await;
        let _ = sqlx::query("DELETE FROM servers WHERE server_id=$1 AND user_id=$2")
            .bind(server.server_id).bind(principal.user.id).execute(state.pool()?).await;
        return Err(error);
    }
    Ok((StatusCode::ACCEPTED, Json(BootstrapProgress {
        server_id: server.server_id, agent_id: started.agent_id, status: "running".into(),
        registered: false, message: None,
    })))
}

#[utoipa::path(get,path="/api/v1/servers/{server_id}/bootstrap",tag="servers",security(("bearer"=[])),
    params(("server_id"=Uuid,Path)),
    responses((status=200,body=BootstrapProgress),(status=401,body=crate::errors::ErrorResponse),
        (status=404,body=crate::errors::ErrorResponse),(status=503,body=crate::errors::ErrorResponse)))]
pub async fn status(
    State(state): State<AppState>,
    principal: Principal,
    Path(server_id): Path<Uuid>,
) -> Result<Json<BootstrapProgress>, AppError> {
    let row = sqlx::query(
        "SELECT j.job_id,j.agent_id,j.status,j.message,j.created_at FROM server_bootstrap_jobs j JOIN servers s ON s.server_id=j.server_id WHERE j.server_id=$1 AND s.user_id=$2"
    ).bind(server_id).bind(principal.user.id).fetch_optional(state.pool()?).await?
        .ok_or_else(AppError::not_found)?;
    let job_id: Uuid = row.get("job_id");
    let agent_id: Uuid = row.get("agent_id");
    let stored_status: String = row.get("status");
    let stored_message: Option<String> = row.get("message");
    let created_at: DateTime<Utc> = row.get("created_at");
    if stored_status != "running" {
        return Ok(Json(BootstrapProgress { server_id, agent_id,
            registered: stored_status == "succeeded", status: stored_status, message: stored_message }));
    }
    let current: CenterProgress = serde_json::from_slice(
        &center_request(&state, "GET", format!("/v1/agents/bootstrap/{job_id}"), None).await?
    ).map_err(|_| AppError::unavailable())?;
    if current.agent_id != agent_id { return Err(AppError::unavailable()); }
    let timed_out = Utc::now().signed_duration_since(created_at).num_minutes() >= 15;
    let status = if current.status == "failed" || (timed_out && !current.registered) { "failed" }
        else if current.status == "succeeded" && current.registered { "succeeded" }
        else { "running" };
    let message = if timed_out && !current.registered && current.message.is_none() {
        Some("Агент не зарегистрировался в Центре за 15 минут. Проверьте журнал установки на сервере.".into())
    } else { current.message };
    if status != "running" {
        let mut tx = state.pool()?.begin().await?;
        sqlx::query("UPDATE server_bootstrap_jobs SET status=$2,message=$3,updated_at=now() WHERE server_id=$1 AND status='running'")
            .bind(server_id).bind(status).bind(&message).execute(&mut *tx).await?;
        sqlx::query("UPDATE servers SET status=$2,updated_at=now() WHERE server_id=$1")
            .bind(server_id).bind(if status == "succeeded" { "online" } else { "error" })
            .execute(&mut *tx).await?;
        tx.commit().await?;
    }
    Ok(Json(BootstrapProgress { server_id, agent_id, status: status.into(),
        registered: current.registered, message }))
}
