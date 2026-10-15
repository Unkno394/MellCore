use super::*;
use sqlx::types::Json;

// A single statement returns a consistent trap+ports snapshot even during updates.
const SELECT_ONE: &str = "SELECT t.*,COALESCE((SELECT jsonb_agg(jsonb_build_object('transport',p.transport,'host_port',p.host_port,'target_port',p.target_port,'route_mode',p.route_mode,'weight',p.weight) ORDER BY p.transport,p.host_port) FROM server_ports p WHERE p.trap_id=t.trap_id),'[]'::jsonb) AS ports FROM traps t WHERE t.trap_id=$1 AND t.user_id=$2";
const SELECT_PAGE: &str = "SELECT t.*,COALESCE((SELECT jsonb_agg(jsonb_build_object('transport',p.transport,'host_port',p.host_port,'target_port',p.target_port,'route_mode',p.route_mode,'weight',p.weight) ORDER BY p.transport,p.host_port) FROM server_ports p WHERE p.trap_id=t.trap_id),'[]'::jsonb) AS ports FROM traps t WHERE t.user_id=$1 AND ($2::uuid IS NULL OR t.server_id=$2) AND ($3::uuid IS NULL OR t.trap_id>$3) ORDER BY t.trap_id LIMIT $4";
async fn snapshot(
    tx: &mut Transaction<'_, Postgres>,
    input: &TrapInput,
) -> Result<(Profile, Value, ContainerResourceLimits), AppError> {
    let profile: Profile = sqlx::query_as("SELECT * FROM trap_profiles WHERE id=$1 FOR SHARE")
        .bind(input.profile_id)
        .fetch_one(&mut **tx)
        .await?;
    let mut effective = profile.config.clone();
    effective
        .as_object_mut()
        .ok_or_else(AppError::internal)?
        .extend(
            input
                .config
                .as_object()
                .ok_or_else(AppError::internal)?
                .clone(),
        );
    management::validate_config(&effective)?;
    let resources = if profile.level == crate::models::TrapLevel::High {
        ContainerResourceLimits::low_default()
    } else {
        input.resources.unwrap_or(profile.resources)
    };
    if profile.level != crate::models::TrapLevel::High {
        resources.validate_for_level(profile.level)?;
    }
    if profile.honeypot_type == "kozyavka" {
        crate::kozyavka::validate_profile(profile.level, &profile.service_type, &effective)?;
        crate::kozyavka::validate_ports(&input.ports)?;
    }
    if profile.honeypot_type == "pritvoryashka" {
        let settings = crate::pritvoryashka::validate_profile(
            profile.level,
            &profile.service_type,
            &effective,
        )?;
        crate::pritvoryashka::validate_ports(&input.ports, &settings.vulnerability_profiles)?;
    }
    if profile.honeypot_type == "high_ubuntu_ssh" {
        crate::high_ubuntu::validate_profile(profile.level, &profile.service_type, &effective)?;
        if input.ports.len() != 1
            || input.ports[0].transport != Transport::Tcp
            || input.ports[0].route_mode != RouteMode::Direct
        {
            return Err(AppError::invalid(
                "High SSH requires exactly one direct TCP port",
            ));
        }
    }
    if profile.honeypot_type == "high_vm" {
        let configured_os = crate::high_vm::validate_profile(
            profile.level,
            &profile.service_type,
            &profile.config,
        )?;
        let requested_os =
            crate::high_vm::validate_profile(profile.level, &profile.service_type, &effective)?;
        if configured_os != requested_os {
            return Err(AppError::invalid(
                "A trap cannot override the operating system selected by its High profile",
            ));
        }
        if input.ports.len() != 1
            || input.ports[0].transport != Transport::Tcp
            || input.ports[0].route_mode != RouteMode::Direct
        {
            return Err(AppError::invalid(
                "High SSH requires exactly one direct TCP port",
            ));
        }
        let guest_port = match crate::high_vm::os_profile(&effective)?.connection {
            hf_core::HighGuestConnection::Ssh { guest_port } => guest_port,
            hf_core::HighGuestConnection::Rdp { .. } => {
                return Err(AppError::invalid(
                    "high_vm currently supports SSH profiles only",
                ));
            }
        };
        if input.ports[0].target_port != guest_port {
            return Err(AppError::invalid(
                "High SSH guest port does not match the selected OS profile",
            ));
        }
    }
    Ok((profile, effective, resources))
}
async fn reserve(
    tx: &mut Transaction<'_, Postgres>,
    server: &Server,
    trap: Uuid,
    ports: &[PortBinding],
    profile: &Profile,
) -> Result<(), AppError> {
    if server.dispatcher_port.is_none()
        && ports
            .iter()
            .any(|p| p.route_mode == RouteMode::DispatcherBackend)
    {
        return Err(AppError::conflict(
            "Configure a dispatcher listener on this server first",
        ));
    }
    for port in ports
        .iter()
        .filter(|port| port.route_mode == RouteMode::DispatcherBackend)
    {
        if server.dispatcher_port != Some(i32::from(port.host_port)) {
            return Err(AppError::conflict(
                "A Dispatcher backend reservation must use the server's configured listener port",
            ));
        }
        if port.transport != Transport::Tcp
            || crate::dispatcher::compatible_ssh_trap_kind(
                &profile.service_type,
                &profile.honeypot_type,
                profile.level,
            )
            .is_none()
        {
            return Err(AppError::conflict(
                "The current Dispatcher accepts compatible SSH Low and Middle traps only",
            ));
        }
        let existing_profiles: Vec<Json<Profile>> = sqlx::query_scalar(
            "SELECT t.profile_snapshot FROM server_ports p JOIN traps t ON t.trap_id=p.trap_id WHERE p.server_id=$1 AND p.transport=$2 AND p.host_port=$3 AND p.route_mode='dispatcher_backend' AND p.trap_id<>$4",
        )
        .bind(server.server_id)
        .bind(port.transport)
        .bind(i32::from(port.host_port))
        .bind(trap)
        .fetch_all(&mut **tx)
        .await?;
        if existing_profiles.iter().any(|existing| {
            existing.0.service_type.as_str() != profile.service_type.as_str()
                || crate::dispatcher::compatible_ssh_trap_kind(
                    &existing.0.service_type,
                    &existing.0.honeypot_type,
                    existing.0.level,
                )
                .is_none()
        }) {
            return Err(AppError::conflict(
                "A shared endpoint requires one protocol and compatible SSH Low or Middle traps",
            ));
        }
    }
    sqlx::query("DELETE FROM server_ports WHERE trap_id=$1 AND user_id=$2")
        .bind(trap)
        .bind(server.user_id)
        .execute(&mut **tx)
        .await?;
    for port in ports {
        if port.route_mode != RouteMode::DispatcherBackend {
            let occupied: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM server_ports WHERE server_id=$1 AND transport=$2 AND host_port=$3 AND route_mode IS DISTINCT FROM 'dispatcher_backend')",
            )
            .bind(server.server_id)
            .bind(port.transport)
            .bind(i32::from(port.host_port))
            .fetch_one(&mut **tx)
            .await?;
            if occupied {
                return Err(AppError::conflict(
                    "Public port is already reserved on this server",
                ));
            }
        }
        sqlx::query("INSERT INTO server_ports(server_id,user_id,transport,host_port,purpose,trap_id,target_port,route_mode,weight) VALUES ($1,$2,$3,$4,'trap',$5,$6,$7,$8)")
            .bind(server.server_id).bind(server.user_id).bind(port.transport).bind(i32::from(port.host_port)).bind(trap).bind(i32::from(port.target_port)).bind(port.route_mode).bind(port.weight.map(i32::from)).execute(&mut **tx).await?;
    }
    Ok(())
}
pub(crate) async fn in_tx(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    id: Uuid,
) -> Result<Trap, AppError> {
    Ok(sqlx::query_as(SELECT_ONE)
        .bind(id)
        .bind(user)
        .fetch_one(&mut **tx)
        .await?)
}
pub async fn create(
    pool: &PgPool,
    principal: &Principal,
    request: Uuid,
    mut input: CreateTrap,
) -> Result<Trap, AppError> {
    input.trap.validate()?;
    let mut tx = owned_tx(pool, principal).await?;
    let server = servers::lock(&mut tx, principal.user.id, input.server_id).await?;
    let deletion_pending: bool =
        sqlx::query_scalar("SELECT deletion_pending FROM servers WHERE server_id=$1")
            .bind(server.server_id)
            .fetch_one(&mut *tx)
            .await?;
    if deletion_pending {
        return Err(AppError::conflict(
            "This server is being deleted; trap creation is disabled.",
        ));
    }
    let agent_registered: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM center_agent_servers WHERE server_id=$1)")
            .bind(server.server_id)
            .fetch_one(&mut *tx)
            .await?;
    if !agent_registered {
        return Err(AppError::conflict(
            "The connected server has no registered agent",
        ));
    }
    let (profile, effective, resources) = snapshot(&mut tx, &input.trap).await?;
    let id = Uuid::new_v4();
    let t = input.trap;
    sqlx::query("INSERT INTO traps(trap_id,server_id,user_id,name,profile_id,profile_version,profile_snapshot,config,effective_config,resources,desired_state) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
        .bind(id).bind(server.server_id).bind(principal.user.id).bind(t.name).bind(t.profile_id).bind(profile.version).bind(Json(profile.clone())).bind(t.config).bind(effective).bind(Json(resources)).bind(t.desired_state).execute(&mut *tx).await?;
    reserve(&mut tx, &server, id, &t.ports, &profile).await?;
    let trap = in_tx(&mut tx, principal.user.id, id).await?;
    management::audit(&mut tx, principal.user.id, "trap.create", id, request).await?;
    tx.commit().await?;
    Ok(trap)
}
pub async fn get(pool: &PgPool, principal: &Principal, id: Uuid) -> Result<Trap, AppError> {
    Ok(sqlx::query_as(SELECT_ONE)
        .bind(id)
        .bind(principal.user.id)
        .fetch_one(pool)
        .await?)
}
pub async fn list(
    pool: &PgPool,
    principal: &Principal,
    query: TrapQuery,
) -> Result<TrapPage, AppError> {
    let limit = query.page().size()?;
    if let Some(server) = query.server_id {
        servers::get(pool, principal, server).await?;
    }
    let mut items: Vec<Trap> = sqlx::query_as(SELECT_PAGE)
        .bind(principal.user.id)
        .bind(query.server_id)
        .bind(query.after)
        .bind((limit + 1) as i64)
        .fetch_all(pool)
        .await?;
    let next_cursor = if items.len() > limit {
        items.truncate(limit);
        items.last().map(|t| t.trap_id)
    } else {
        None
    };
    Ok(TrapPage { items, next_cursor })
}
async fn lock_parent(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    id: Uuid,
) -> Result<Server, AppError> {
    let server: Uuid =
        sqlx::query_scalar("SELECT server_id FROM traps WHERE trap_id=$1 AND user_id=$2")
            .bind(id)
            .bind(user)
            .fetch_one(&mut **tx)
            .await?;
    // All mutations take the parent first, avoiding deadlocks and port races.
    servers::lock(tx, user, server).await
}
pub async fn update(
    pool: &PgPool,
    principal: &Principal,
    id: Uuid,
    request: Uuid,
    mut input: UpdateTrap,
) -> Result<Trap, AppError> {
    input.trap.validate()?;
    let mut tx = owned_tx(pool, principal).await?;
    let server = lock_parent(&mut tx, principal.user.id, id).await?;
    let deletion_pending: bool =
        sqlx::query_scalar("SELECT deletion_pending FROM servers WHERE server_id=$1")
            .bind(server.server_id)
            .fetch_one(&mut *tx)
            .await?;
    if deletion_pending {
        return Err(AppError::conflict(
            "This server is being deleted; trap changes are disabled.",
        ));
    }
    let previous = in_tx(&mut tx, principal.user.id, id).await?;
    check_version(previous.version, input.expected_version)?;
    let (profile, effective, resources) = snapshot(&mut tx, &input.trap).await?;
    let t = input.trap;
    sqlx::query("UPDATE traps SET name=$3,profile_id=$4,profile_version=$5,profile_snapshot=$6,config=$7,effective_config=$8,resources=$9,desired_state=$10,version=version+1,updated_at=now() WHERE trap_id=$1 AND user_id=$2")
        .bind(id).bind(principal.user.id).bind(t.name).bind(t.profile_id).bind(profile.version).bind(Json(profile.clone())).bind(t.config).bind(effective).bind(Json(resources)).bind(t.desired_state).execute(&mut *tx).await?;
    reserve(&mut tx, &server, id, &t.ports, &profile).await?;
    let trap = in_tx(&mut tx, principal.user.id, id).await?;
    management::audit(&mut tx, principal.user.id, "trap.update", id, request).await?;
    tx.commit().await?;
    Ok(trap)
}
pub async fn delete(
    pool: &PgPool,
    principal: &Principal,
    id: Uuid,
    request: Uuid,
) -> Result<(), AppError> {
    let mut tx = owned_tx(pool, principal).await?;
    lock_parent(&mut tx, principal.user.id, id).await?;
    let trap = in_tx(&mut tx, principal.user.id, id).await?;
    if !matches!(
        trap.actual_state,
        ActualState::Unknown | ActualState::Removed
    ) {
        return Err(AppError::conflict(
            "Remove the deployed trap through the agent before deleting its registration",
        ));
    }
    sqlx::query("DELETE FROM traps WHERE trap_id=$1 AND user_id=$2")
        .bind(id)
        .bind(principal.user.id)
        .execute(&mut *tx)
        .await?;
    management::audit(&mut tx, principal.user.id, "trap.delete", id, request).await?;
    tx.commit().await?;
    Ok(())
}
