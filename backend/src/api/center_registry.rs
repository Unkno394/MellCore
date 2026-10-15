//! Center's authenticated bridge into the ordinary servers/traps registry.
//! No SSH credentials are accepted or persisted here.
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::{
    api::{AppState, telemetry::authorize_center},
    errors::AppError,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterTrap {
    pub agent_id: Uuid,
    pub server_id: Option<Uuid>,
    pub trap_id: Uuid,
    pub host: String,
    pub ssh_port: u16,
    pub tier: String,
    pub host_port: u16,
}

#[derive(Debug, Serialize)]
pub struct RegisteredTrap {
    pub agent_id: Uuid,
    pub server_id: Uuid,
    pub trap_id: Uuid,
    pub state: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoveTrapRegistration {
    pub agent_id: Uuid,
    pub trap_id: Uuid,
}

pub async fn mark_removed(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<RemoveTrapRegistration>,
) -> Result<StatusCode, AppError> {
    authorize_center(&state, &headers)?;
    let mut tx = state.pool()?.begin().await?;
    let bound: Option<Uuid> = sqlx::query_scalar(
        "SELECT trap_id FROM center_agent_traps WHERE trap_id=$1 AND agent_id=$2 FOR UPDATE",
    )
    .bind(input.trap_id)
    .bind(input.agent_id)
    .fetch_optional(&mut *tx)
    .await?;
    if bound.is_none() {
        return Err(AppError::not_found());
    }
    sqlx::query("UPDATE center_agent_traps SET state='removed',updated_at=now() WHERE trap_id=$1 AND agent_id=$2")
        .bind(input.trap_id).bind(input.agent_id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM server_ports WHERE trap_id=$1")
        .bind(input.trap_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE traps SET actual_state='removed',desired_state='stopped',updated_at=now() WHERE trap_id=$1")
        .bind(input.trap_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn register_trap(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<RegisterTrap>,
) -> Result<(StatusCode, Json<RegisteredTrap>), AppError> {
    authorize_center(&state, &headers)?;
    if input.agent_id.is_nil()
        || input.trap_id.is_nil()
        || input.server_id.is_some_and(|id| id.is_nil())
        || input.host.is_empty()
        || input.host.len() > 253
        || input.host.contains(char::is_whitespace)
        || input.host_port == 0
        || input.ssh_port == 0
    {
        return Err(AppError::invalid("Invalid Center trap registration"));
    }
    let kind = match input.tier.as_str() {
        "low" => "kozyavka",
        "middle" => "pritvoryashka",
        _ => {
            return Err(AppError::invalid(
                "Only Low and Middle traps may be registered",
            ));
        }
    };
    let mut tx = state.pool()?.begin().await?;
    // Existing agent mappings keep the authenticated owner's server identity.
    // Legacy direct Center installations still fall back to the bootstrap admin.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(input.agent_id.to_string())
        .execute(&mut *tx)
        .await?;
    let existing_server: Option<Uuid> =
        sqlx::query_scalar("SELECT server_id FROM center_agent_servers WHERE agent_id=$1")
            .bind(input.agent_id)
            .fetch_optional(&mut *tx)
            .await?;
    let trap_server: Option<Uuid> =
        sqlx::query_scalar("SELECT server_id FROM traps WHERE trap_id=$1")
            .bind(input.trap_id)
            .fetch_optional(&mut *tx)
            .await?;
    let requested_server = input.server_id.or(trap_server);
    let server_id = match (existing_server, requested_server) {
        (Some(existing), Some(requested)) if existing != requested => {
            return Err(AppError::conflict("Agent is bound to a different server"));
        }
        (Some(existing), _) => existing,
        (None, requested) => requested.unwrap_or_else(Uuid::new_v4),
    };
    let owner: Uuid = if existing_server.is_some() {
        sqlx::query_scalar("SELECT user_id FROM servers WHERE server_id=$1")
            .bind(server_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(AppError::not_found)?
    } else {
        // Legacy Center registrations may not carry a server ID. Bind them to
        // an active Owner rather than assuming the bootstrap username is
        // literally `admin`.
        sqlx::query_scalar(
            "SELECT u.id FROM users u JOIN user_role_assignments ur ON ur.user_id=u.id
             WHERE ur.role_id=$1 AND u.is_active ORDER BY u.created_at,u.id LIMIT 1",
        )
        .bind(crate::rbac::OWNER_ROLE_ID)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(AppError::unavailable)?
    };
    let server =
        sqlx::query("SELECT user_id,host,ssh_port FROM servers WHERE server_id=$1 FOR UPDATE")
            .bind(server_id)
            .fetch_optional(&mut *tx)
            .await?;
    if let Some(server) = server {
        let server_owner: Uuid = server.get("user_id");
        let host: String = server.get("host");
        let port: i32 = server.get("ssh_port");
        if server_owner != owner || host != input.host || port != i32::from(input.ssh_port) {
            return Err(AppError::conflict(
                "Server registration belongs to another target",
            ));
        }
    } else {
        sqlx::query("INSERT INTO servers(server_id,user_id,name,host,ssh_port,ssh_user) VALUES($1,$2,$3,$4,$5,'unknown')")
            .bind(server_id).bind(owner).bind(format!("Agent {}", input.agent_id))
            .bind(&input.host).bind(i32::from(input.ssh_port)).execute(&mut *tx).await?;
    }
    if existing_server.is_none() {
        sqlx::query("INSERT INTO center_agent_servers(agent_id,server_id) VALUES($1,$2)")
            .bind(input.agent_id)
            .bind(server_id)
            .execute(&mut *tx)
            .await?;
    }
    let profile = sqlx::query("SELECT id,version,to_jsonb(p) AS snapshot,config FROM trap_profiles p WHERE honeypot_type=$1 ORDER BY version DESC LIMIT 1")
        .bind(kind).fetch_optional(&mut *tx).await?.ok_or_else(AppError::unavailable)?;
    let profile_id: Uuid = profile.get("id");
    let profile_version: i64 = profile.get("version");
    let snapshot: serde_json::Value = profile.get("snapshot");
    let config: serde_json::Value = profile.get("config");
    let resources =
        snapshot
            .get("resources")
            .cloned()
            .unwrap_or_else(|| match input.tier.as_str() {
                "middle" => serde_json::json!({"cpu_cores":1.0,"memory_mb":512,"pids":256}),
                _ => serde_json::json!({"cpu_cores":0.5,"memory_mb":128,"pids":64}),
            });
    let existing_trap =
        sqlx::query("SELECT server_id,user_id,profile_id FROM traps WHERE trap_id=$1 FOR UPDATE")
            .bind(input.trap_id)
            .fetch_optional(&mut *tx)
            .await?;
    if let Some(trap) = existing_trap {
        let bound_agent: Option<Uuid> =
            sqlx::query_scalar("SELECT agent_id FROM center_agent_traps WHERE trap_id=$1")
                .bind(input.trap_id)
                .fetch_optional(&mut *tx)
                .await?;
        if trap.get::<Uuid, _>("server_id") != server_id
            || trap.get::<Uuid, _>("user_id") != owner
            || trap.get::<Uuid, _>("profile_id") != profile_id
            || bound_agent.is_some_and(|agent| agent != input.agent_id)
        {
            return Err(AppError::conflict(
                "Trap ID is already registered for another target",
            ));
        }
    } else {
        sqlx::query("INSERT INTO traps(trap_id,server_id,user_id,name,profile_id,profile_version,profile_snapshot,config,effective_config,resources,desired_state,actual_state) VALUES($1,$2,$3,$4,$5,$6,$7,'{}'::jsonb,$8,$9,'running','installing')")
            .bind(input.trap_id).bind(server_id).bind(owner).bind(format!("{} {}", kind, input.trap_id))
            .bind(profile_id).bind(profile_version).bind(snapshot).bind(config).bind(resources)
            .execute(&mut *tx).await?;
    }
    let previous_port: Option<i32> =
        sqlx::query_scalar("SELECT host_port FROM server_ports WHERE trap_id=$1")
            .bind(input.trap_id)
            .fetch_optional(&mut *tx)
            .await?;
    if previous_port.is_some_and(|port| port != i32::from(input.host_port)) {
        return Err(AppError::conflict("Trap already reserves a different port"));
    }
    if previous_port.is_none() {
        sqlx::query("INSERT INTO server_ports(server_id,user_id,transport,host_port,purpose,trap_id,target_port,route_mode) VALUES($1,$2,'tcp',$3,'trap',$4,2222,'direct')")
            .bind(server_id).bind(owner).bind(i32::from(input.host_port)).bind(input.trap_id)
            .execute(&mut *tx).await?;
    }
    sqlx::query("INSERT INTO center_agent_traps(trap_id,agent_id) VALUES($1,$2) ON CONFLICT (trap_id) DO NOTHING")
        .bind(input.trap_id).bind(input.agent_id).execute(&mut *tx).await?;
    sqlx::query("UPDATE center_agent_traps SET state='provisioning',updated_at=now() WHERE trap_id=$1 AND agent_id=$2 AND state='removed'")
        .bind(input.trap_id).bind(input.agent_id).execute(&mut *tx).await?;
    sqlx::query("UPDATE traps SET desired_state='running',actual_state='installing',updated_at=now() WHERE trap_id=$1 AND actual_state='removed'")
        .bind(input.trap_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(RegisteredTrap {
            agent_id: input.agent_id,
            server_id,
            trap_id: input.trap_id,
            state: "provisioning",
        }),
    ))
}
