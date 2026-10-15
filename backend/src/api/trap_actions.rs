use crate::{
    api::AppState,
    auth::Principal,
    errors::{AppError, RequestId},
    management,
    resources::{self, Trap},
};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use hf_core::{AgentCommand, PritvoryashkaDeployment, SharedTcpTrapKind, TcpPortGroup};
use serde::{Deserialize, Serialize};
use sqlx::{Row, types::Json as SqlxJson};
use std::collections::{HashMap, HashSet};
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
struct QueuedCommand {
    message_id: Uuid,
}

#[derive(Deserialize)]
struct CenterCommandStatus {
    status: String,
    detail: Option<String>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedPortMember {
    pub trap_id: Uuid,
    pub weight: u8,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SharePortRequest {
    pub listener_port: u16,
    pub members: Vec<SharedPortMember>,
}

fn shared_trap_kind(profile: &crate::management::Profile) -> Result<SharedTcpTrapKind, AppError> {
    crate::dispatcher::compatible_ssh_trap_kind(
        &profile.service_type,
        &profile.honeypot_type,
        profile.level,
    )
    .ok_or_else(|| {
        AppError::conflict("Only compatible SSH Low and Middle traps can join the Dispatcher")
    })
}

/// Replaces direct publications with loopback backends after the agent confirms that
/// the dispatcher is listening. The caller supplies the full desired member list.
#[utoipa::path(post,path="/api/v1/traps/{trap_id}/share-port",tag="traps",security(("bearer"=[])),params(("trap_id"=Uuid,Path)),request_body=SharePortRequest,responses((status=202,body=TrapActionProgress),(status=409,body=crate::errors::ErrorResponse)))]
pub async fn share_port(
    State(state): State<AppState>,
    principal: Principal,
    Path(trap_id): Path<Uuid>,
    Json(input): Json<SharePortRequest>,
) -> Result<(StatusCode, Json<TrapActionProgress>), AppError> {
    resources::owned_tx(state.pool()?, &principal)
        .await?
        .commit()
        .await?;
    if input.listener_port == 0
        || input.members.len() < 2
        || input.members.len() > 100
        || !input.members.iter().any(|member| member.trap_id == trap_id)
        || input
            .members
            .iter()
            .map(|member| u16::from(member.weight))
            .sum::<u16>()
            != 100
        || input.members.iter().any(|member| member.weight == 0)
    {
        return Err(AppError::invalid(
            "Provide two or more traps and weights totaling 100",
        ));
    }
    let unique: HashSet<_> = input.members.iter().map(|member| member.trap_id).collect();
    if unique.len() != input.members.len() {
        return Err(AppError::invalid("Duplicate trap in shared listener"));
    }
    let target = resources::traps::get(state.pool()?, &principal, trap_id).await?;
    let server = resources::servers::get(state.pool()?, &principal, target.server_id).await?;
    if server.status != resources::ServerStatus::Online
        || server.ssh_port == i32::from(input.listener_port)
        || server
            .dispatcher_port
            .is_some_and(|port| port != i32::from(input.listener_port))
    {
        return Err(AppError::conflict(
            "The server cannot use this shared TCP port",
        ));
    }
    let mut candidates = Vec::with_capacity(input.members.len());
    for member in &input.members {
        let trap = resources::traps::get(state.pool()?, &principal, member.trap_id).await?;
        let ssh_binding = trap.ports.iter().find(|port| {
            port.transport == resources::Transport::Tcp
                && (port.target_port == 2222
                    || port.route_mode == resources::RouteMode::DispatcherBackend)
        });
        if trap.server_id != server.server_id
            || trap.actual_state != crate::models::ActualState::Running
            || ssh_binding.is_none()
            || ssh_binding.is_some_and(|port| {
                port.route_mode == resources::RouteMode::DispatcherBackend
                    && port.host_port != input.listener_port
            })
        {
            return Err(AppError::conflict(
                "Every shared-port trap must be running on this server",
            ));
        }
        let trap_kind = shared_trap_kind(&trap.profile_snapshot)?;
        candidates.push(crate::dispatcher::GroupCandidate {
            trap_id: trap.trap_id,
            weight: member.weight,
            trap_kind,
            service_type: trap.profile_snapshot.service_type.clone(),
        });
    }
    candidates.sort_by_key(|candidate| candidate.trap_id);
    let reservations =
        resources::servers::ports(state.pool()?, &principal, server.server_id).await?;
    let current_members: HashSet<_> = reservations
        .iter()
        .filter(|port| {
            port.transport == resources::Transport::Tcp
                && port.host_port == i32::from(input.listener_port)
                && port.route_mode == Some(resources::RouteMode::DispatcherBackend)
        })
        .filter_map(|port| port.trap_id)
        .collect();
    if !current_members.is_subset(&unique) {
        return Err(AppError::conflict(
            "Include every existing member of this shared port",
        ));
    }
    let listener_owner = reservations.iter().find(|port| {
        port.transport == resources::Transport::Tcp
            && port.host_port == i32::from(input.listener_port)
            && port.route_mode != Some(resources::RouteMode::DispatcherBackend)
    });
    if let Some(owner) = listener_owner {
        if owner.purpose != resources::PortPurpose::Dispatcher
            && !owner.trap_id.is_some_and(|id| unique.contains(&id))
        {
            return Err(AppError::conflict(
                "This TCP port belongs to SSH or another trap",
            ));
        }
    } else if current_members.is_empty() {
        return Err(AppError::conflict(
            "Select a port already published by one of these traps",
        ));
    }
    let occupied: HashSet<u16> = reservations
        .iter()
        .filter_map(|port| {
            if port.route_mode == Some(resources::RouteMode::DispatcherBackend) {
                port.target_port
            } else {
                Some(port.host_port)
            }
        })
        .filter_map(|port| u16::try_from(port).ok())
        .collect();
    let existing: HashMap<Uuid, u16> = reservations
        .iter()
        .filter(|port| port.route_mode == Some(resources::RouteMode::DispatcherBackend))
        .filter_map(|port| Some((port.trap_id?, u16::try_from(port.target_port?).ok()?)))
        .collect();
    let command = crate::dispatcher::plan_tcp_port_group(
        input.listener_port,
        &candidates,
        &occupied,
        &existing,
    )
    .map_err(AppError::conflict)?;
    let AgentCommand::ReconcileTcpPortGroup(ref group) = command else {
        return Err(AppError::internal());
    };
    let agent_id: Uuid =
        sqlx::query_scalar("SELECT agent_id FROM center_agent_servers WHERE server_id=$1")
            .bind(server.server_id)
            .fetch_one(state.pool()?)
            .await?;
    let presence = crate::api::servers::agent_presence(&state, agent_id).await?;
    if !presence.connected {
        return Err(AppError::conflict(
            "Агент не отвечает Центру; общий SSH-порт не изменён.",
        ));
    }
    if !presence.can_share_tcp_ports {
        return Err(AppError::conflict(
            "Агент не подтвердил поддержку Dispatcher. Обновите на нём hf-agent и hf-dispatcher, затем повторите подключение к общему порту.",
        ));
    }
    let queued: QueuedCommand = serde_json::from_slice(
        &crate::api::server_bootstrap::center_request(
            &state,
            "POST",
            format!("/v1/agents/{agent_id}/commands"),
            Some(serde_json::to_vec(&command).map_err(|_| AppError::internal())?),
        )
        .await?,
    )
    .map_err(|_| AppError::unavailable())?;
    let action_id = Uuid::new_v4();
    sqlx::query("INSERT INTO trap_action_jobs(action_id,trap_id,agent_id,action,command_ids,dispatcher_plan) VALUES($1,$2,$3,'share_port',$4,$5)")
        .bind(action_id).bind(trap_id).bind(agent_id).bind(vec![queued.message_id])
        .bind(sqlx::types::Json(group)).execute(state.pool()?).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(TrapActionProgress {
            action_id,
            status: "queued".into(),
            detail: None,
        }),
    ))
}

async fn complete_shared_port(
    state: &AppState,
    plan: TcpPortGroup,
    user_id: Uuid,
) -> Result<(), AppError> {
    if plan.members.is_empty()
        || plan.members.len() > 100
        || plan
            .members
            .iter()
            .map(|member| u16::from(member.weight))
            .sum::<u16>()
            != 100
        || plan
            .members
            .iter()
            .any(|member| member.weight == 0 || member.backend_port == 0)
    {
        return Err(AppError::conflict(
            "Dispatcher plan has invalid members or weights",
        ));
    }
    let member_ids: Vec<_> = plan.members.iter().map(|member| member.trap_id).collect();
    if member_ids.iter().copied().collect::<HashSet<_>>().len() != member_ids.len() {
        return Err(AppError::conflict(
            "Dispatcher plan contains a duplicate trap",
        ));
    }
    let mut tx = state.pool()?.begin().await?;
    let server_id: Uuid =
        sqlx::query_scalar("SELECT server_id FROM traps WHERE trap_id=$1 AND user_id=$2")
            .bind(member_ids[0])
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
    let server: resources::Server = resources::servers::lock(&mut tx, user_id, server_id).await?;
    if plan.listener_port == 0
        || server.ssh_port == i32::from(plan.listener_port)
        || server
            .dispatcher_port
            .is_some_and(|port| port != i32::from(plan.listener_port))
    {
        return Err(AppError::conflict(
            "Server dispatcher port changed during transition",
        ));
    }

    // Revalidate the persisted profile snapshot after the agent ACK, before recording this
    // endpoint in the port registry. This protects reconciliation from stale or altered plans.
    let rows = sqlx::query(
        "SELECT trap_id,server_id,profile_snapshot FROM traps WHERE user_id=$1 AND trap_id=ANY($2)",
    )
    .bind(user_id)
    .bind(&member_ids)
    .fetch_all(&mut *tx)
    .await?;
    if rows.len() != plan.members.len() {
        return Err(AppError::conflict(
            "A Dispatcher trap was removed during transition",
        ));
    }
    let profiles: HashMap<Uuid, (Uuid, crate::management::Profile)> = rows
        .into_iter()
        .map(|row| {
            let trap_id: Uuid = row.get("trap_id");
            let member_server_id: Uuid = row.get("server_id");
            let profile: SqlxJson<crate::management::Profile> = row.get("profile_snapshot");
            (trap_id, (member_server_id, profile.0))
        })
        .collect();
    let mut candidates = Vec::with_capacity(plan.members.len());
    for member in &plan.members {
        let Some((member_server_id, profile)) = profiles.get(&member.trap_id) else {
            return Err(AppError::conflict(
                "A Dispatcher trap was removed during transition",
            ));
        };
        if *member_server_id != server_id || shared_trap_kind(profile)? != member.trap_kind {
            return Err(AppError::conflict(
                "Dispatcher members no longer match compatible SSH profiles",
            ));
        }
        candidates.push(crate::dispatcher::GroupCandidate {
            trap_id: member.trap_id,
            weight: member.weight,
            trap_kind: member.trap_kind,
            service_type: profile.service_type.clone(),
        });
    }
    crate::dispatcher::validate_group_compatibility(&candidates).map_err(AppError::conflict)?;

    for member in &plan.members {
        let changed = sqlx::query("UPDATE server_ports SET host_port=$3,target_port=$4,route_mode='dispatcher_backend',weight=$5 WHERE server_id=$1 AND trap_id=$2 AND transport='tcp' AND (target_port=2222 OR route_mode='dispatcher_backend')")
            .bind(server_id).bind(member.trap_id).bind(i32::from(plan.listener_port))
            .bind(i32::from(member.backend_port)).bind(i32::from(member.weight))
            .execute(&mut *tx).await?;
        if changed.rows_affected() != 1 {
            return Err(AppError::conflict(
                "Trap port reservation changed during transition",
            ));
        }
    }
    if server.dispatcher_port.is_none() {
        sqlx::query("INSERT INTO server_ports(server_id,user_id,transport,host_port,purpose) VALUES($1,$2,'tcp',$3,'dispatcher')")
            .bind(server_id).bind(user_id).bind(i32::from(plan.listener_port)).execute(&mut *tx).await?;
        sqlx::query("UPDATE servers SET dispatcher_port=$2,version=version+1,updated_at=now() WHERE server_id=$1")
            .bind(server_id).bind(i32::from(plan.listener_port)).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

const LOST_CENTER_COMMAND: &str = "Центр больше не хранит команду, вероятно после перезапуска. Её выполнение не подтверждено. Проверьте ловушку и повторите действие.";

/// Finish acknowledged trap actions even if the browser was closed.
pub async fn reconcile_shared_jobs(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
    loop {
        interval.tick().await;
        let Some(pool) = state.database.as_ref() else {
            return;
        };
        let jobs = sqlx::query("SELECT j.action_id,j.trap_id,j.agent_id,j.action,j.command_ids,j.dispatcher_plan,t.user_id FROM trap_action_jobs j JOIN traps t ON t.trap_id=j.trap_id WHERE j.status='queued' ORDER BY j.created_at LIMIT 50")
            .fetch_all(pool).await;
        let Ok(jobs) = jobs else {
            continue;
        };
        for job in jobs {
            let action_id: Uuid = job.get("action_id");
            let trap_id: Uuid = job.get("trap_id");
            let agent_id: Uuid = job.get("agent_id");
            let action: String = job.get("action");
            let command_ids: Vec<Uuid> = job.get("command_ids");
            let mut statuses = Vec::with_capacity(command_ids.len());
            let mut center_lost_command = false;
            for message_id in command_ids {
                let response = crate::api::server_bootstrap::center_request(
                    &state,
                    "GET",
                    format!("/v1/agents/{agent_id}/commands/{message_id}"),
                    None,
                )
                .await
                .and_then(|bytes| {
                    serde_json::from_slice::<CenterCommandStatus>(&bytes)
                        .map_err(|_| AppError::unavailable())
                });
                match response {
                    Ok(value) => statuses.push(value),
                    Err(error) if error.status == StatusCode::NOT_FOUND => {
                        center_lost_command = true;
                        break;
                    }
                    Err(_) => break,
                }
            }
            if center_lost_command {
                let _ = sqlx::query("UPDATE trap_action_jobs SET status='failed',detail=$2,updated_at=now() WHERE action_id=$1 AND status='queued'")
                    .bind(action_id).bind(LOST_CENTER_COMMAND).execute(pool).await;
                tracing::warn!(%action_id, %trap_id, "Center lost a queued trap command");
                continue;
            }
            if statuses.is_empty() {
                continue;
            }
            if let Some(rejected) = statuses.iter().find(|status| status.status == "rejected") {
                let _ = sqlx::query("UPDATE trap_action_jobs SET status='failed',detail=$2,updated_at=now() WHERE action_id=$1 AND status='queued'")
                    .bind(action_id).bind(&rejected.detail).execute(pool).await;
                continue;
            }
            if statuses.len() != job.get::<Vec<Uuid>, _>("command_ids").len()
                || !statuses.iter().all(|status| status.status == "applied")
            {
                continue;
            }
            if let Some(plan) = job.get::<Option<serde_json::Value>, _>("dispatcher_plan") {
                let Ok(plan) = serde_json::from_value::<TcpPortGroup>(plan) else {
                    tracing::error!(%action_id, "stored Dispatcher plan cannot be decoded");
                    continue;
                };
                if let Err(error) = complete_shared_port(&state, plan, job.get("user_id")).await {
                    tracing::warn!(?error, %action_id, "shared port registry reconciliation failed");
                    continue;
                }
            }
            let update = match action.as_str() {
                "start" | "restart" => {
                    match sqlx::query("UPDATE traps SET desired_state='running',actual_state='running',updated_at=now() WHERE trap_id=$1")
                        .bind(trap_id).execute(pool).await {
                        Ok(_) => sqlx::query("UPDATE center_agent_traps SET state='running',updated_at=now() WHERE trap_id=$1")
                            .bind(trap_id).execute(pool).await.map(|_| ()),
                        Err(error) => Err(error),
                    }
                }
                "stop" => sqlx::query("UPDATE traps SET desired_state='stopped',actual_state='stopped',updated_at=now() WHERE trap_id=$1")
                    .bind(trap_id).execute(pool).await.map(|_| ()),
                "remove" => {
                    // The Center only reports a RemoveTrap as applied after the agent
                    // has stopped the runtime and removed its local project. Keep the
                    // registration in the panel so the operator can remove that row
                    // after the background reconciliation completes.
                    match sqlx::query("UPDATE traps SET desired_state='stopped',actual_state='removed',updated_at=now() WHERE trap_id=$1")
                        .bind(trap_id).execute(pool).await {
                        Ok(_) => sqlx::query("DELETE FROM server_ports WHERE trap_id=$1")
                            .bind(trap_id).execute(pool).await.map(|_| ()),
                        Err(error) => Err(error),
                    }
                }
                "share_port" => Ok(()),
                _ => continue,
            };
            if let Err(error) = update {
                tracing::warn!(?error, %action_id, "trap state reconciliation failed");
                continue;
            }
            let _ = sqlx::query("UPDATE trap_action_jobs SET status='succeeded',updated_at=now() WHERE action_id=$1 AND status='queued'")
                .bind(action_id).execute(pool).await;
        }
    }
}
async fn shared_start_plan(
    state: &AppState,
    principal: &Principal,
    trap: &Trap,
) -> Result<Option<AgentCommand>, AppError> {
    let Some(binding) = trap.ports.first() else {
        return Ok(None);
    };
    if binding.route_mode != resources::RouteMode::DispatcherBackend {
        return Ok(None);
    }
    let listener_port = binding.host_port;
    let reservations = resources::servers::ports(state.pool()?, principal, trap.server_id).await?;
    let member_ids: Vec<_> = reservations
        .iter()
        .filter(|port| {
            port.host_port == i32::from(listener_port)
                && port.route_mode == Some(resources::RouteMode::DispatcherBackend)
        })
        .filter_map(|port| {
            port.trap_id
                .map(|id| (id, port.weight.unwrap_or(1).max(1) as u32))
        })
        .collect();
    let mut active = Vec::new();
    for (id, weight) in member_ids {
        let member = resources::traps::get(state.pool()?, principal, id).await?;
        if id != trap.trap_id && member.actual_state != crate::models::ActualState::Running {
            continue;
        }
        let trap_kind = shared_trap_kind(&member.profile_snapshot)?;
        active.push((
            id,
            weight,
            trap_kind,
            member.profile_snapshot.service_type.clone(),
        ));
    }
    if active.is_empty() {
        return Err(AppError::conflict("Shared-port trap has no reservation"));
    }
    let total: u32 = active.iter().map(|(_, weight, _, _)| *weight).sum();
    let mut remaining = 100_u16;
    let count = active.len();
    active.sort_by_key(|(trap_id, _, _, _)| *trap_id);
    let candidates = active
        .into_iter()
        .enumerate()
        .map(|(index, (trap_id, weight, trap_kind, service_type))| {
            let share = if index + 1 == count {
                remaining as u8
            } else {
                let share = ((weight * 100 / total).max(1) as u16)
                    .min(remaining - (count - index - 1) as u16);
                remaining -= share;
                share as u8
            };
            crate::dispatcher::GroupCandidate {
                trap_id,
                weight: share,
                trap_kind,
                service_type,
            }
        })
        .collect::<Vec<_>>();
    let occupied: HashSet<u16> = reservations
        .iter()
        .filter_map(|port| {
            if port.route_mode == Some(resources::RouteMode::DispatcherBackend) {
                port.target_port
            } else {
                Some(port.host_port)
            }
        })
        .filter_map(|port| u16::try_from(port).ok())
        .collect();
    let existing: HashMap<Uuid, u16> = reservations
        .iter()
        .filter(|port| port.route_mode == Some(resources::RouteMode::DispatcherBackend))
        .filter_map(|port| Some((port.trap_id?, u16::try_from(port.target_port?).ok()?)))
        .collect();
    Ok(Some(
        crate::dispatcher::plan_tcp_port_group(listener_port, &candidates, &occupied, &existing)
            .map_err(AppError::conflict)?,
    ))
}

#[utoipa::path(post, path="/api/v1/traps/{trap_id}/actions", tag="traps", security(("bearer"=[])), params(("trap_id"=Uuid, Path)), request_body=TrapActionRequest, responses((status=202, body=TrapActionProgress), (status=401, body=crate::errors::ErrorResponse), (status=404, body=crate::errors::ErrorResponse), (status=409, body=crate::errors::ErrorResponse), (status=503, body=crate::errors::ErrorResponse)))]
pub async fn start(
    State(state): State<AppState>,
    principal: Principal,
    Path(trap_id): Path<Uuid>,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<TrapActionRequest>,
) -> Result<(StatusCode, Json<TrapActionProgress>), AppError> {
    resources::owned_tx(state.pool()?, &principal)
        .await?
        .commit()
        .await?;
    let trap = resources::traps::get(state.pool()?, &principal, trap_id).await?;
    let agent_id: Uuid = sqlx::query_scalar("SELECT cas.agent_id FROM traps t JOIN center_agent_servers cas ON cas.server_id=t.server_id JOIN servers s ON s.server_id=t.server_id AND s.user_id=t.user_id WHERE t.trap_id=$1 AND t.user_id=$2")
        .bind(trap_id).bind(principal.user.id).fetch_optional(state.pool()?).await?.ok_or_else(AppError::not_found)?;
    if !crate::api::servers::agent_presence(&state, agent_id)
        .await?
        .connected
    {
        return Err(AppError::conflict(
            "Агент сейчас не отвечает Центру; команда ловушке не отправлена.",
        ));
    }

    let action_id = Uuid::new_v4();
    let mut commands = commands_for(input.action, &trap)?;
    let group_command = if matches!(input.action, TrapAction::Start | TrapAction::Restart) {
        shared_start_plan(&state, &principal, &trap).await?
    } else {
        None
    };
    if let Some(command) = &group_command {
        commands.push(command.clone());
    }
    // Keep a transaction-scoped operation lock while talking to Center. Do not
    // hold the server row lock here: Center's deployment handler calls back into
    // /internal/v1/center/traps and must lock this same server row before it can
    // queue the command.
    let mut tx = resources::owned_tx(state.pool()?, &principal).await?;
    resources::servers::lock_operation(&mut tx, trap.server_id).await?;
    let deletion_pending: bool = sqlx::query_scalar(
        "SELECT deletion_pending FROM servers WHERE server_id=$1 AND user_id=$2",
    )
    .bind(trap.server_id)
    .bind(principal.user.id)
    .fetch_one(&mut *tx)
    .await?;
    if deletion_pending {
        return Err(AppError::conflict(
            "This server is being deleted; trap actions are disabled.",
        ));
    }
    let current_trap = resources::traps::in_tx(&mut tx, principal.user.id, trap_id).await?;
    if current_trap.version != trap.version {
        return Err(AppError::conflict(
            "The trap changed while preparing the command. Refresh and retry.",
        ));
    }
    if matches!(input.action, TrapAction::Start | TrapAction::Restart)
        && current_trap.actual_state == crate::models::ActualState::Removed
    {
        return Err(AppError::conflict(
            "A removed trap registration cannot be started.",
        ));
    }
    let dispatcher_plan = match &group_command {
        Some(AgentCommand::ReconcileTcpPortGroup(plan)) => Some(sqlx::types::Json(plan)),
        _ => None,
    };
    let mut message_ids = Vec::with_capacity(commands.len());
    for command in commands {
        let body = serde_json::to_vec(&command).map_err(|_| AppError::internal())?;
        let queued: QueuedCommand = serde_json::from_slice(
            &crate::api::server_bootstrap::center_request(
                &state,
                "POST",
                format!("/v1/agents/{agent_id}/commands"),
                Some(body),
            )
            .await?,
        )
        .map_err(|_| AppError::unavailable())?;
        message_ids.push(queued.message_id);
    }
    let action_name = match input.action {
        TrapAction::Start => "start",
        TrapAction::Stop => "stop",
        TrapAction::Restart => "restart",
        TrapAction::Remove => "remove",
    };
    sqlx::query("INSERT INTO trap_action_jobs(action_id,trap_id,agent_id,action,command_ids,dispatcher_plan) VALUES($1,$2,$3,$4,$5,$6)")
        .bind(action_id).bind(trap_id).bind(agent_id).bind(action_name).bind(&message_ids)
        .bind(dispatcher_plan)
        .execute(&mut *tx).await?;
    management::audit(
        &mut tx,
        principal.user.id,
        "trap.action_queued",
        trap_id,
        request_id.0,
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(TrapActionProgress {
            action_id,
            status: "queued".into(),
            detail: None,
        }),
    ))
}

#[utoipa::path(get, path="/api/v1/traps/{trap_id}/actions/{action_id}", tag="traps", security(("bearer"=[])), params(("trap_id"=Uuid, Path), ("action_id"=Uuid, Path)), responses((status=200, body=TrapActionProgress), (status=401, body=crate::errors::ErrorResponse), (status=404, body=crate::errors::ErrorResponse), (status=503, body=crate::errors::ErrorResponse)))]
pub async fn status(
    State(state): State<AppState>,
    principal: Principal,
    Path((trap_id, action_id)): Path<(Uuid, Uuid)>,
    Extension(request_id): Extension<RequestId>,
) -> Result<Json<TrapActionProgress>, AppError> {
    resources::owned_tx(state.pool()?, &principal)
        .await?
        .commit()
        .await?;
    let row = sqlx::query("SELECT j.agent_id,j.action,j.command_ids,j.status,j.detail,j.dispatcher_plan FROM trap_action_jobs j JOIN traps t ON t.trap_id=j.trap_id WHERE j.action_id=$1 AND j.trap_id=$2 AND t.user_id=$3")
        .bind(action_id).bind(trap_id).bind(principal.user.id).fetch_optional(state.pool()?).await?.ok_or_else(AppError::not_found)?;
    let agent_id: Uuid = row.get("agent_id");
    let action: String = row.get("action");
    let message_ids: Vec<Uuid> = row.get("command_ids");
    let previous: String = row.get("status");
    if previous != "queued" {
        return Ok(Json(TrapActionProgress {
            action_id,
            status: previous,
            detail: row.get("detail"),
        }));
    }

    let mut statuses = Vec::with_capacity(message_ids.len());
    for message_id in message_ids {
        let response_bytes = match crate::api::server_bootstrap::center_request(
            &state,
            "GET",
            format!("/v1/agents/{agent_id}/commands/{message_id}"),
            None,
        )
        .await
        {
            Ok(bytes) => bytes,
            Err(error) if error.status == StatusCode::NOT_FOUND => {
                sqlx::query("UPDATE trap_action_jobs SET status='failed',detail=$2,updated_at=now() WHERE action_id=$1 AND status='queued'")
                    .bind(action_id).bind(LOST_CENTER_COMMAND).execute(state.pool()?).await?;
                return Ok(Json(TrapActionProgress {
                    action_id,
                    status: "failed".into(),
                    detail: Some(LOST_CENTER_COMMAND.into()),
                }));
            }
            Err(error) => return Err(error),
        };
        let response: CenterCommandStatus =
            serde_json::from_slice(&response_bytes).map_err(|_| AppError::unavailable())?;
        statuses.push(response);
    }
    let rejected = statuses.iter().find(|status| status.status == "rejected");
    let all_applied =
        !statuses.is_empty() && statuses.iter().all(|status| status.status == "applied");
    let status = if rejected.is_some() {
        "failed"
    } else if all_applied {
        "succeeded"
    } else {
        "queued"
    };
    let detail = rejected.and_then(|item| item.detail.clone());
    if status != "queued" {
        if status == "succeeded"
            && !row
                .get::<Option<serde_json::Value>, _>("dispatcher_plan")
                .is_none()
        {
            let plan: serde_json::Value = row.get("dispatcher_plan");
            let plan: TcpPortGroup =
                serde_json::from_value(plan).map_err(|_| AppError::internal())?;
            complete_shared_port(&state, plan, principal.user.id).await?;
        }
        sqlx::query(
            "UPDATE trap_action_jobs SET status=$2,detail=$3,updated_at=now() WHERE action_id=$1",
        )
        .bind(action_id)
        .bind(status)
        .bind(&detail)
        .execute(state.pool()?)
        .await?;
        if status == "succeeded" {
            match action.as_str() {
                "start" | "restart" => {
                    sqlx::query("UPDATE traps SET desired_state='running',actual_state='running',updated_at=now() WHERE trap_id=$1")
                        .bind(trap_id).execute(state.pool()?).await?;
                    sqlx::query("UPDATE center_agent_traps SET state='running',updated_at=now() WHERE trap_id=$1")
                        .bind(trap_id).execute(state.pool()?).await?;
                }
                "stop" => {
                    sqlx::query("UPDATE traps SET desired_state='stopped',actual_state='stopped',updated_at=now() WHERE trap_id=$1")
                    .bind(trap_id).execute(state.pool()?).await?;
                }
                "remove" => {
                    // Center marks the trap removed only after the agent's ACK.
                    let server_id: Uuid =
                        sqlx::query_scalar("SELECT server_id FROM traps WHERE trap_id=$1")
                            .bind(trap_id)
                            .fetch_one(state.pool()?)
                            .await?;
                    sqlx::query("UPDATE traps SET desired_state='stopped',actual_state='removed',updated_at=now() WHERE trap_id=$1 AND user_id=$2")
                        .bind(trap_id).bind(principal.user.id).execute(state.pool()?).await?;
                    resources::traps::delete(state.pool()?, &principal, trap_id, request_id.0)
                        .await?;
                    let members: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM server_ports WHERE server_id=$1 AND route_mode='dispatcher_backend')")
                        .bind(server_id).fetch_one(state.pool()?).await?;
                    if !members {
                        sqlx::query(
                            "DELETE FROM server_ports WHERE server_id=$1 AND purpose='dispatcher'",
                        )
                        .bind(server_id)
                        .execute(state.pool()?)
                        .await?;
                        sqlx::query("UPDATE servers SET dispatcher_port=NULL,version=version+1,updated_at=now() WHERE server_id=$1 AND dispatcher_port IS NOT NULL")
                            .bind(server_id).execute(state.pool()?).await?;
                    }
                }
                _ => {}
            }
        }
    }
    Ok(Json(TrapActionProgress {
        action_id,
        status: status.into(),
        detail,
    }))
}

fn commands_for(action: TrapAction, trap: &Trap) -> Result<Vec<AgentCommand>, AppError> {
    let stop = || AgentCommand::StopTrap {
        command_id: Uuid::new_v4(),
        trap_id: trap.trap_id,
    };
    let remove = || AgentCommand::RemoveTrap {
        command_id: Uuid::new_v4(),
        trap_id: trap.trap_id,
    };
    let deploy = || -> Result<AgentCommand, AppError> {
        match trap.profile_snapshot.honeypot_type.as_str() {
            "kozyavka" => crate::kozyavka::deployment_command(trap),
            "high_ubuntu_ssh" => crate::high_ubuntu::deployment_command(trap),
            "high_vm" => crate::high_vm::deployment_command(trap),
            "pritvoryashka" => {
                let settings = crate::pritvoryashka::validate_profile(
                    trap.profile_snapshot.level,
                    &trap.profile_snapshot.service_type,
                    &trap.effective_config,
                )?;
                crate::pritvoryashka::validate_ports(
                    &trap.ports,
                    &settings.vulnerability_profiles,
                )?;
                let port = trap
                    .ports
                    .iter()
                    .find(|port| {
                        port.route_mode == crate::resources::RouteMode::DispatcherBackend
                            || port.target_port == 2222
                    })
                    .ok_or_else(AppError::internal)?;
                let host_port =
                    u16::try_from(if port.route_mode == crate::resources::RouteMode::Direct {
                        port.host_port
                    } else {
                        port.target_port
                    })
                    .map_err(|_| AppError::internal())?;
                let max_connections = u16::try_from(settings.max_connections.min(128))
                    .map_err(|_| AppError::internal())?;
                let expected_endpoints = crate::pritvoryashka::expected_service_endpoints(
                    &settings.vulnerability_profiles,
                )?;
                let endpoints = trap
                    .ports
                    .iter()
                    .filter(|binding| {
                        binding.target_port != 2222
                            && binding.route_mode == crate::resources::RouteMode::Direct
                    })
                    .map(|binding| {
                        let (service_type, _) = expected_endpoints
                            .iter()
                            .find(|(_, container_port)| *container_port == binding.target_port)
                            .ok_or_else(AppError::internal)?;
                        Ok(hf_core::PritvoryashkaEndpoint {
                            service_type: service_type.clone(),
                            host_port: binding.host_port,
                            container_port: binding.target_port,
                        })
                    })
                    .collect::<Result<Vec<_>, AppError>>()?;
                Ok(AgentCommand::DeployPritvoryashka(PritvoryashkaDeployment {
                    command_id: Uuid::new_v4(),
                    trap_id: trap.trap_id,
                    server_id: trap.server_id,
                    host_port,
                    public_ssh_port: port.host_port,
                    publish_address: if port.route_mode == crate::resources::RouteMode::Direct {
                        "0.0.0.0"
                    } else {
                        "127.0.0.1"
                    }
                    .into(),
                    hostname: settings.hostname,
                    username: settings.username,
                    distribution: settings.distribution,
                    ssh_auth_mode: match settings.ssh_auth_mode {
                        crate::pritvoryashka::SshAuthMode::Realistic => "realistic",
                        crate::pritvoryashka::SshAuthMode::Adaptive => "adaptive",
                    }
                    .into(),
                    ssh_credentials: settings
                        .ssh_credentials
                        .into_iter()
                        .map(|credential| hf_core::MiddleSshCredential {
                            username: credential.username,
                            password: credential.password,
                        })
                        .collect(),
                    dispatcher_proxy_secret: None,
                    max_connections,
                    resources: trap.resources.into(),
                    baits: settings.baits,
                    virtual_processes: settings.virtual_processes,
                    vulnerability_profiles: settings.vulnerability_profiles,
                    endpoints,
                }))
            }
            _ => Err(AppError::conflict(
                "No deployment recipe is available for this trap",
            )),
        }
    };
    match action {
        TrapAction::Start => Ok(vec![deploy()?]),
        TrapAction::Stop => Ok(vec![stop()]),
        TrapAction::Restart => Ok(vec![stop(), deploy()?]),
        TrapAction::Remove => Ok(vec![remove()]),
    }
}
