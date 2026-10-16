use std::collections::HashSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{auth::Principal, errors::AppError, management};

pub const OWNER_ROLE_ID: Uuid = Uuid::from_u128(0x00000000000040008000000000000001);

#[derive(Clone, Serialize, FromRow, ToSchema)]
pub struct RbacRole {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub system_key: Option<String>,
    pub is_system: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Serialize, ToSchema)]
pub struct RoleView {
    #[serde(flatten)]
    pub role: RbacRole,
    pub permissions: Vec<String>,
    pub user_count: i64,
}

#[derive(Serialize, FromRow, ToSchema)]
pub struct PermissionInfo {
    pub key: String,
    pub category: String,
    pub description: String,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RoleInput {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub permissions: Vec<String>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CopyRoleInput {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AssignRoles {
    pub role_ids: Vec<Uuid>,
}

#[derive(Serialize, ToSchema)]
pub struct EffectiveAccess {
    pub user_id: Uuid,
    pub roles: Vec<RbacRole>,
    pub permissions: Vec<String>,
}

pub fn validate_role(input: &RoleInput) -> Result<(), AppError> {
    let name = input.name.trim();
    if name.is_empty() || name.len() > 80 || name.chars().any(char::is_control) {
        return Err(AppError::invalid(
            "Role name must contain 1-80 bytes without control characters",
        ));
    }
    if input.description.len() > 2048 || input.description.chars().any(char::is_control) {
        return Err(AppError::invalid(
            "Role description is too long or contains control characters",
        ));
    }
    if input.permissions.len() > 64 {
        return Err(AppError::invalid("Too many permissions"));
    }
    let unique: HashSet<_> = input.permissions.iter().collect();
    if unique.len() != input.permissions.len() {
        return Err(AppError::invalid("Duplicate permissions"));
    }
    Ok(())
}

pub async fn permissions(pool: &PgPool) -> Result<Vec<PermissionInfo>, AppError> {
    Ok(sqlx::query_as(
        "SELECT key,category,description FROM rbac_permissions ORDER BY category,key",
    )
    .fetch_all(pool)
    .await?)
}

pub async fn effective_permissions(pool: &PgPool, user: Uuid) -> Result<HashSet<String>, AppError> {
    Ok(sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT rp.permission_key FROM user_role_assignments ur JOIN rbac_role_permissions rp ON rp.role_id=ur.role_id WHERE ur.user_id=$1"
    ).bind(user).fetch_all(pool).await?.into_iter().collect())
}

pub async fn effective_access(
    pool: &PgPool,
    actor: &Principal,
    user: Uuid,
) -> Result<EffectiveAccess, AppError> {
    if actor.user.id != user {
        actor.require("users.view")?;
    }
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)")
        .bind(user)
        .fetch_one(pool)
        .await?;
    if !exists {
        return Err(AppError::not_found());
    }
    let roles = sqlx::query_as::<_, RbacRole>(
        "SELECT r.* FROM rbac_roles r JOIN user_role_assignments ur ON ur.role_id=r.id WHERE ur.user_id=$1 ORDER BY r.is_system DESC,r.name"
    ).bind(user).fetch_all(pool).await?;
    let mut permissions: Vec<_> = effective_permissions(pool, user)
        .await?
        .into_iter()
        .collect();
    permissions.sort();
    Ok(EffectiveAccess {
        user_id: user,
        roles,
        permissions,
    })
}

pub async fn list(pool: &PgPool, principal: &Principal) -> Result<Vec<RoleView>, AppError> {
    principal.require("roles.view")?;
    let roles =
        sqlx::query_as::<_, RbacRole>("SELECT * FROM rbac_roles ORDER BY is_system DESC,name")
            .fetch_all(pool)
            .await?;
    let mut result = Vec::with_capacity(roles.len());
    for role in roles {
        let permissions = sqlx::query_scalar("SELECT permission_key FROM rbac_role_permissions WHERE role_id=$1 ORDER BY permission_key")
            .bind(role.id).fetch_all(pool).await?;
        let user_count =
            sqlx::query_scalar("SELECT count(*) FROM user_role_assignments WHERE role_id=$1")
                .bind(role.id)
                .fetch_one(pool)
                .await?;
        result.push(RoleView {
            role,
            permissions,
            user_count,
        });
    }
    Ok(result)
}

pub(crate) async fn validate_grant(
    tx: &mut Transaction<'_, Postgres>,
    actor: Uuid,
    requested: &[String],
) -> Result<(), AppError> {
    let known: i64 = sqlx::query_scalar("SELECT count(*) FROM rbac_permissions WHERE key=ANY($1)")
        .bind(requested)
        .fetch_one(&mut **tx)
        .await?;
    if known != requested.len() as i64 {
        return Err(AppError::invalid("Unknown permission"));
    }
    let allowed: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT rp.permission_key) FROM user_role_assignments ur JOIN rbac_role_permissions rp ON rp.role_id=ur.role_id WHERE ur.user_id=$1 AND rp.permission_key=ANY($2)"
    ).bind(actor).bind(requested).fetch_one(&mut **tx).await?;
    if allowed != requested.len() as i64 {
        return Err(AppError::forbidden());
    }
    Ok(())
}

pub async fn permission_tx<'a>(
    pool: &'a PgPool,
    actor: Uuid,
    permission: &str,
) -> Result<Transaction<'a, Postgres>, AppError> {
    let mut tx = pool.begin().await?;
    let allowed: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users u JOIN user_role_assignments ur ON ur.user_id=u.id JOIN rbac_role_permissions rp ON rp.role_id=ur.role_id WHERE u.id=$1 AND u.is_active AND rp.permission_key=$2)"
    ).bind(actor).bind(permission).fetch_one(&mut *tx).await?;
    if !allowed {
        return Err(AppError::forbidden());
    }
    Ok(tx)
}

pub async fn protect_last_owner(
    tx: &mut Transaction<'_, Postgres>,
    target: Uuid,
) -> Result<(), AppError> {
    let last: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users u JOIN user_role_assignments ur ON ur.user_id=u.id WHERE u.id=$1 AND u.is_active AND ur.role_id=$2) AND (SELECT count(*) FROM users u JOIN user_role_assignments ur ON ur.user_id=u.id WHERE u.is_active AND ur.role_id=$2)=1"
    ).bind(target).bind(OWNER_ROLE_ID).fetch_one(&mut **tx).await?;
    if last {
        return Err(AppError::conflict(
            "Cannot remove, disable or demote the last active Owner",
        ));
    }
    Ok(())
}

pub async fn create(
    pool: &PgPool,
    principal: &Principal,
    request: Uuid,
    input: RoleInput,
) -> Result<RoleView, AppError> {
    principal.require("roles.create")?;
    validate_role(&input)?;
    let mut tx = permission_tx(pool, principal.user.id, "roles.create").await?;
    validate_grant(&mut tx, principal.user.id, &input.permissions).await?;
    let role = sqlx::query_as::<_, RbacRole>(
        "INSERT INTO rbac_roles(id,name,description) VALUES($1,$2,$3) RETURNING *",
    )
    .bind(Uuid::new_v4())
    .bind(input.name.trim())
    .bind(input.description.trim())
    .fetch_one(&mut *tx)
    .await?;
    for permission in &input.permissions {
        sqlx::query("INSERT INTO rbac_role_permissions(role_id,permission_key) VALUES($1,$2)")
            .bind(role.id)
            .bind(permission)
            .execute(&mut *tx)
            .await?;
    }
    management::audit_with_details(
        &mut tx,
        principal.user.id,
        "role.create",
        role.id,
        request,
        serde_json::json!({
            "name": &role.name,
            "permissions": &input.permissions,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(RoleView {
        role,
        permissions: input.permissions,
        user_count: 0,
    })
}

pub async fn update(
    pool: &PgPool,
    principal: &Principal,
    id: Uuid,
    request: Uuid,
    input: RoleInput,
) -> Result<RoleView, AppError> {
    principal.require("roles.edit")?;
    validate_role(&input)?;
    let mut tx = permission_tx(pool, principal.user.id, "roles.edit").await?;
    validate_grant(&mut tx, principal.user.id, &input.permissions).await?;
    let previous_permissions: Vec<String> = sqlx::query_scalar(
        "SELECT permission_key FROM rbac_role_permissions WHERE role_id=$1 ORDER BY permission_key",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    let role = sqlx::query_as::<_, RbacRole>("UPDATE rbac_roles SET name=$2,description=$3,updated_at=now() WHERE id=$1 AND NOT is_system RETURNING *")
        .bind(id).bind(input.name.trim()).bind(input.description.trim()).fetch_optional(&mut *tx).await?
        .ok_or_else(AppError::not_found)?;
    sqlx::query("DELETE FROM rbac_role_permissions WHERE role_id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    for permission in &input.permissions {
        sqlx::query("INSERT INTO rbac_role_permissions(role_id,permission_key) VALUES($1,$2)")
            .bind(id)
            .bind(permission)
            .execute(&mut *tx)
            .await?;
    }
    management::audit_with_details(
        &mut tx,
        principal.user.id,
        "role.update",
        id,
        request,
        serde_json::json!({
            "name": &role.name,
            "previous_permissions": previous_permissions,
            "permissions": &input.permissions,
        }),
    )
    .await?;
    let user_count =
        sqlx::query_scalar("SELECT count(*) FROM user_role_assignments WHERE role_id=$1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    tx.commit().await?;
    Ok(RoleView {
        role,
        permissions: input.permissions,
        user_count,
    })
}

pub async fn copy(
    pool: &PgPool,
    principal: &Principal,
    id: Uuid,
    request: Uuid,
    input: CopyRoleInput,
) -> Result<RoleView, AppError> {
    principal.require("roles.create")?;
    let source: RbacRole = sqlx::query_as("SELECT * FROM rbac_roles WHERE id=$1")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(AppError::not_found)?;
    let permissions = sqlx::query_scalar(
        "SELECT permission_key FROM rbac_role_permissions WHERE role_id=$1 ORDER BY permission_key",
    )
    .bind(id)
    .fetch_all(pool)
    .await?;
    create(
        pool,
        principal,
        request,
        RoleInput {
            name: input.name,
            description: input.description.unwrap_or(source.description),
            permissions,
        },
    )
    .await
}

pub async fn delete(
    pool: &PgPool,
    principal: &Principal,
    id: Uuid,
    request: Uuid,
) -> Result<(), AppError> {
    principal.require("roles.delete")?;
    let mut tx = permission_tx(pool, principal.user.id, "roles.delete").await?;
    let existing: Option<(bool, String)> =
        sqlx::query_as("SELECT is_system,name FROM rbac_roles WHERE id=$1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let name = match existing {
        None => return Err(AppError::not_found()),
        Some((true, _)) => return Err(AppError::conflict("System roles cannot be deleted")),
        Some((false, name)) => name,
    };
    let permissions: Vec<String> = sqlx::query_scalar(
        "SELECT permission_key FROM rbac_role_permissions WHERE role_id=$1 ORDER BY permission_key",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    management::audit_with_details(
        &mut tx,
        principal.user.id,
        "role.delete",
        id,
        request,
        serde_json::json!({ "name": name, "permissions": permissions }),
    )
    .await?;
    sqlx::query("DELETE FROM rbac_roles WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn assign(
    pool: &PgPool,
    principal: &Principal,
    target: Uuid,
    request: Uuid,
    input: AssignRoles,
) -> Result<EffectiveAccess, AppError> {
    principal.require("users.assign_roles")?;
    if target == principal.user.id {
        return Err(AppError::forbidden());
    }
    let requested: HashSet<_> = input.role_ids.iter().copied().collect();
    if requested.len() != input.role_ids.len() || requested.is_empty() {
        return Err(AppError::invalid("At least one unique role is required"));
    }
    let mut tx = permission_tx(pool, principal.user.id, "users.assign_roles").await?;
    sqlx::query("SELECT pg_advisory_xact_lock(72146020)")
        .execute(&mut *tx)
        .await?;
    let target_active: bool =
        sqlx::query_scalar("SELECT is_active FROM users WHERE id=$1 FOR UPDATE")
            .bind(target)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(AppError::not_found)?;
    let roles: Vec<(Uuid, Option<String>)> =
        sqlx::query_as("SELECT id,system_key FROM rbac_roles WHERE id=ANY($1)")
            .bind(&input.role_ids)
            .fetch_all(&mut *tx)
            .await?;
    if roles.len() != input.role_ids.len() {
        return Err(AppError::invalid("Unknown role"));
    }
    let actor_owner: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_role_assignments WHERE user_id=$1 AND role_id=$2)",
    )
    .bind(principal.user.id)
    .bind(OWNER_ROLE_ID)
    .fetch_one(&mut *tx)
    .await?;
    if requested.contains(&OWNER_ROLE_ID) && !actor_owner {
        return Err(AppError::forbidden());
    }
    let requested_permissions: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT permission_key FROM rbac_role_permissions WHERE role_id=ANY($1)",
    )
    .bind(&input.role_ids)
    .fetch_all(&mut *tx)
    .await?;
    validate_grant(&mut tx, principal.user.id, &requested_permissions).await?;
    let had_owner: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_role_assignments WHERE user_id=$1 AND role_id=$2)",
    )
    .bind(target)
    .bind(OWNER_ROLE_ID)
    .fetch_one(&mut *tx)
    .await?;
    if target_active && had_owner && !requested.contains(&OWNER_ROLE_ID) {
        protect_last_owner(&mut tx, target).await?;
    }
    let previous_role_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT role_id FROM user_role_assignments WHERE user_id=$1 ORDER BY role_id",
    )
    .bind(target)
    .fetch_all(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM user_role_assignments WHERE user_id=$1")
        .bind(target)
        .execute(&mut *tx)
        .await?;
    for role in &input.role_ids {
        sqlx::query(
            "INSERT INTO user_role_assignments(user_id,role_id,assigned_by) VALUES($1,$2,$3)",
        )
        .bind(target)
        .bind(role)
        .bind(principal.user.id)
        .execute(&mut *tx)
        .await?;
    }
    management::audit_with_details(
        &mut tx,
        principal.user.id,
        "user.roles_assigned",
        target,
        request,
        serde_json::json!({
            "previous_role_ids": previous_role_ids,
            "role_ids": &input.role_ids,
        }),
    )
    .await?;
    tx.commit().await?;
    effective_access(pool, principal, target).await
}
