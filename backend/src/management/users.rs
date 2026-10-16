use crate::{
    auth::{AuthRuntime, Principal},
    errors::AppError,
    management::{self, CreateUser, Page, UpdateUser, User, UserPage},
    models::Role,
};
use sqlx::PgPool;
use uuid::Uuid;

pub async fn create(
    pool: &PgPool,
    runtime: &AuthRuntime,
    principal: &Principal,
    request_id: Uuid,
    input: CreateUser,
) -> Result<User, AppError> {
    principal.require("users.manage")?;
    if input.role == Role::Admin && !principal.permissions.contains("settings.change") {
        return Err(AppError::forbidden());
    }
    let username = management::username(&input.username)?;
    let name = management::display_name(input.name.as_deref().unwrap_or(&username))?;
    let email = input.email.as_deref().map(management::email).transpose()?;
    management::password(&input.password)?;
    let hash = runtime.hash(input.password).await?;
    let mut tx = crate::rbac::permission_tx(pool, principal.user.id, "users.manage").await?;
    let user = sqlx::query_as::<_, User>("INSERT INTO users(id, username, password_hash, role, name, email) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, username, name, email, email_verified_at, role, is_active, created_at, updated_at")
        .bind(Uuid::new_v4()).bind(username).bind(hash).bind(input.role).bind(name).bind(email).fetch_one(&mut *tx).await?;
    let role_id = match input.role {
        Role::Admin => crate::rbac::OWNER_ROLE_ID,
        Role::Viewer => Uuid::from_u128(0x00000000000040008000000000000005),
        Role::User => Uuid::from_u128(0x00000000000040008000000000000004),
    };
    sqlx::query("INSERT INTO user_role_assignments(user_id,role_id,assigned_by) VALUES($1,$2,$3)")
        .bind(user.id)
        .bind(role_id)
        .bind(principal.user.id)
        .execute(&mut *tx)
        .await?;
    management::audit(
        &mut tx,
        principal.user.id,
        "user.create",
        user.id,
        request_id,
    )
    .await?;
    tx.commit().await?;
    Ok(user)
}

pub async fn list(pool: &PgPool, principal: &Principal, page: Page) -> Result<UserPage, AppError> {
    principal.require("users.view")?;
    let limit = page.size()?;
    let mut items = sqlx::query_as::<_, User>("SELECT id, username, name, email, email_verified_at, role, is_active, created_at, updated_at FROM users WHERE ($1::uuid IS NULL OR id>$1) ORDER BY id LIMIT $2")
        .bind(page.after).bind((limit + 1) as i64).fetch_all(pool).await?;
    let next_cursor = if items.len() > limit {
        items.truncate(limit);
        items.last().map(|u| u.id)
    } else {
        None
    };
    Ok(UserPage { items, next_cursor })
}

pub async fn get(pool: &PgPool, principal: &Principal, id: Uuid) -> Result<User, AppError> {
    principal.require("users.view")?;
    Ok(sqlx::query_as(
        "SELECT id, username, name, email, email_verified_at, role, is_active, created_at, updated_at FROM users WHERE id=$1",
    )
    .bind(id)
    .fetch_one(pool)
    .await?)
}

pub async fn update(
    pool: &PgPool,
    runtime: &AuthRuntime,
    principal: &Principal,
    target: Uuid,
    request_id: Uuid,
    input: UpdateUser,
) -> Result<User, AppError> {
    principal.require("users.manage")?;
    if input.role == Role::Admin && !principal.permissions.contains("settings.change") {
        return Err(AppError::forbidden());
    }
    let username = management::username(&input.username)?;
    let name = input
        .name
        .as_deref()
        .map(management::display_name)
        .transpose()?;
    let email = input.email.as_deref().map(management::email).transpose()?;
    let hash = if let Some(password) = input.password {
        management::password(&password)?;
        Some(runtime.hash(password).await?)
    } else {
        None
    };
    let mut tx = crate::rbac::permission_tx(pool, principal.user.id, "users.manage").await?;
    let previous_role: Role = sqlx::query_scalar("SELECT role FROM users WHERE id=$1 FOR UPDATE")
        .bind(target)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(AppError::not_found)?;
    if input.role != previous_role {
        principal.require("users.assign_roles")?;
        if target == principal.user.id {
            return Err(AppError::forbidden());
        }
    }
    if input.role != Role::Admin || !input.is_active {
        management::protect_last_admin(&mut tx, target).await?;
    }
    if !input.is_active || input.role != previous_role {
        crate::rbac::protect_last_owner(&mut tx, target).await?;
    }
    let user = sqlx::query_as::<_, User>("UPDATE users SET username=$2, role=$3, is_active=$4, password_hash=COALESCE($5,password_hash), name=COALESCE($6,name), email_verified_at=CASE WHEN $7::text IS NOT NULL AND $7 IS DISTINCT FROM email THEN NULL ELSE email_verified_at END, email=COALESCE($7,email), updated_at=now() WHERE id=$1 RETURNING id, username, name, email, email_verified_at, role, is_active, created_at, updated_at")
        .bind(target).bind(username).bind(input.role).bind(input.is_active).bind(hash).bind(name).bind(email).fetch_one(&mut *tx).await?;
    if input.role != previous_role {
        // Legacy single-role changes translate into the corresponding built-in
        // assignment. Ordinary account edits preserve multi-role assignments.
        let role_id = match input.role {
            Role::Admin => crate::rbac::OWNER_ROLE_ID,
            Role::Viewer => Uuid::from_u128(0x00000000000040008000000000000005),
            Role::User => Uuid::from_u128(0x00000000000040008000000000000004),
        };
        sqlx::query("DELETE FROM user_role_assignments WHERE user_id=$1")
            .bind(target)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO user_role_assignments(user_id,role_id,assigned_by) VALUES($1,$2,$3)")
            .bind(target)
            .bind(role_id)
            .bind(principal.user.id)
            .execute(&mut *tx)
            .await?;
    }
    // Reauthentication after any account change avoids retaining stale access.
    management::revoke_credentials(&mut tx, target).await?;
    management::audit(
        &mut tx,
        principal.user.id,
        "user.update",
        target,
        request_id,
    )
    .await?;
    tx.commit().await?;
    Ok(user)
}

pub async fn delete(
    pool: &PgPool,
    principal: &Principal,
    target: Uuid,
    request_id: Uuid,
) -> Result<(), AppError> {
    principal.require("users.manage")?;
    let mut tx = crate::rbac::permission_tx(pool, principal.user.id, "users.manage").await?;
    management::protect_last_admin(&mut tx, target).await?;
    crate::rbac::protect_last_owner(&mut tx, target).await?;
    management::audit(
        &mut tx,
        principal.user.id,
        "user.delete",
        target,
        request_id,
    )
    .await?;
    if sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(target)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        == 0
    {
        return Err(AppError::not_found());
    }
    tx.commit().await?;
    Ok(())
}
