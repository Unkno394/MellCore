use super::*;
use sqlx::types::Json;

pub async fn lock(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    id: Uuid,
) -> Result<Server, AppError> {
    lock_operation(tx, id).await?;
    Ok(
        sqlx::query_as("SELECT * FROM servers WHERE server_id=$1 AND user_id=$2 FOR UPDATE")
            .bind(id)
            .bind(user)
            .fetch_one(&mut **tx)
            .await?,
    )
}

/// Serialize panel-side server mutations without holding the server row lock
/// across a request to Center. Center's trap registration callback needs that
/// row, so holding it while waiting for Center creates a lock cycle.
pub async fn lock_operation(tx: &mut Transaction<'_, Postgres>, id: Uuid) -> Result<(), AppError> {
    let key = format!("honeyforge:server-operation:{id}");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(key)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
async fn reserve_management(
    tx: &mut Transaction<'_, Postgres>,
    server: &Server,
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM server_ports WHERE server_id=$1 AND purpose IN ('ssh','dispatcher')")
        .bind(server.server_id)
        .execute(&mut **tx)
        .await?;
    for (purpose, port) in [
        (PortPurpose::Ssh, Some(server.ssh_port)),
        (PortPurpose::Dispatcher, server.dispatcher_port),
    ] {
        if let Some(port) = port {
            sqlx::query("INSERT INTO server_ports(server_id,user_id,transport,host_port,purpose) VALUES ($1,$2,'tcp',$3,$4)").bind(server.server_id).bind(server.user_id).bind(port).bind(purpose).execute(&mut **tx).await?;
        }
    }
    Ok(())
}
pub async fn create(
    pool: &PgPool,
    principal: &Principal,
    request: Uuid,
    mut input: ServerInput,
) -> Result<Server, AppError> {
    principal.require("servers.connect")?;
    input.validate()?;
    let mut tx = owned_tx(pool, principal, "servers.connect").await?;
    let server:Server=sqlx::query_as("INSERT INTO servers(server_id,user_id,name,host,ssh_port,ssh_user,credential_ref,dispatcher_port,settings) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *")
        .bind(Uuid::new_v4()).bind(principal.user.id).bind(input.name).bind(input.host).bind(i32::from(input.ssh_port)).bind(input.ssh_user).bind(input.credential_ref).bind(input.dispatcher_port.map(i32::from)).bind(Json(input.settings)).fetch_one(&mut *tx).await?;
    reserve_management(&mut tx, &server).await?;
    management::audit(
        &mut tx,
        principal.user.id,
        "server.create",
        server.server_id,
        request,
    )
    .await?;
    tx.commit().await?;
    Ok(server)
}
pub async fn get(pool: &PgPool, principal: &Principal, id: Uuid) -> Result<Server, AppError> {
    principal.require("servers.view")?;
    Ok(
        sqlx::query_as("SELECT * FROM servers WHERE server_id=$1 AND user_id=$2")
            .bind(id)
            .bind(principal.user.id)
            .fetch_one(pool)
            .await?,
    )
}
pub async fn list(
    pool: &PgPool,
    principal: &Principal,
    page: Page,
) -> Result<ServerPage, AppError> {
    principal.require("servers.view")?;
    let limit = page.size()?;
    let mut items:Vec<Server>=sqlx::query_as("SELECT * FROM servers WHERE user_id=$1 AND ($2::uuid IS NULL OR server_id>$2) ORDER BY server_id LIMIT $3").bind(principal.user.id).bind(page.after).bind((limit+1) as i64).fetch_all(pool).await?;
    let next_cursor = if items.len() > limit {
        items.truncate(limit);
        items.last().map(|s| s.server_id)
    } else {
        None
    };
    Ok(ServerPage { items, next_cursor })
}
pub async fn update(
    pool: &PgPool,
    principal: &Principal,
    id: Uuid,
    request: Uuid,
    mut input: UpdateServer,
) -> Result<Server, AppError> {
    principal.require("servers.manage")?;
    input.server.validate()?;
    let mut tx = owned_tx(pool, principal, "servers.manage").await?;
    let previous = lock(&mut tx, principal.user.id, id).await?;
    let deletion_pending: bool =
        sqlx::query_scalar("SELECT deletion_pending FROM servers WHERE server_id=$1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    if deletion_pending {
        return Err(AppError::conflict("This server is being deleted."));
    }
    check_version(previous.version, input.expected_version)?;
    if input.server.dispatcher_port.is_none() {
        let backends:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM server_ports WHERE server_id=$1 AND route_mode='dispatcher_backend')").bind(id).fetch_one(&mut *tx).await?;
        if backends {
            return Err(AppError::conflict("Dispatcher still has reserved backends"));
        }
    }
    let s = input.server;
    let server:Server=sqlx::query_as("UPDATE servers SET name=$3,host=$4,ssh_port=$5,ssh_user=$6,credential_ref=$7,dispatcher_port=$8,settings=$9,version=version+1,updated_at=now() WHERE server_id=$1 AND user_id=$2 RETURNING *")
        .bind(id).bind(principal.user.id).bind(s.name).bind(s.host).bind(i32::from(s.ssh_port)).bind(s.ssh_user).bind(s.credential_ref).bind(s.dispatcher_port.map(i32::from)).bind(Json(s.settings)).fetch_one(&mut *tx).await?;
    reserve_management(&mut tx, &server).await?;
    management::audit(&mut tx, principal.user.id, "server.update", id, request).await?;
    tx.commit().await?;
    Ok(server)
}
pub async fn delete(
    pool: &PgPool,
    principal: &Principal,
    id: Uuid,
    request: Uuid,
) -> Result<(), AppError> {
    principal.require("servers.disconnect")?;
    let mut tx = owned_tx(pool, principal, "servers.disconnect").await?;
    lock(&mut tx, principal.user.id, id).await?;
    // FK RESTRICT prevents implicit deletion of traps and external resources.
    sqlx::query("DELETE FROM servers WHERE server_id=$1 AND user_id=$2")
        .bind(id)
        .bind(principal.user.id)
        .execute(&mut *tx)
        .await?;
    management::audit(&mut tx, principal.user.id, "server.delete", id, request).await?;
    tx.commit().await?;
    Ok(())
}
pub async fn ports(
    pool: &PgPool,
    principal: &Principal,
    id: Uuid,
) -> Result<Vec<PortReservation>, AppError> {
    principal.require("servers.view")?;
    get(pool, principal, id).await?;
    Ok(sqlx::query_as("SELECT server_id,transport,host_port,purpose,trap_id,target_port,route_mode,weight FROM server_ports WHERE server_id=$1 AND user_id=$2 ORDER BY transport,host_port").bind(id).bind(principal.user.id).fetch_all(pool).await?)
}
