use std::collections::HashSet;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{FromRow, PgPool};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::{
    auth::{self, AuthRuntime, Principal},
    errors::AppError,
    management::{self, User},
    models::Role,
    rbac::{self, OWNER_ROLE_ID, RbacRole},
};

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateInvitation {
    pub email: String,
    pub role_ids: Vec<Uuid>,
    #[serde(default)]
    #[schema(minimum = 1, maximum = 168, default = 72)]
    pub expires_in_hours: Option<u32>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AcceptInvitation {
    pub token: String,
    pub name: String,
    #[schema(write_only)]
    pub password: String,
}

#[derive(Serialize, ToSchema)]
pub struct InvitationView {
    pub id: Uuid,
    pub email: String,
    pub created_by: Uuid,
    pub creator_name: String,
    pub roles: Vec<RbacRole>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, ToSchema)]
pub struct InvitationCreated {
    pub invitation: InvitationView,
    /// One-time bearer URL. It is returned only at creation and is never stored in plaintext.
    pub invite_url: String,
}

#[derive(FromRow)]
struct InvitationRow {
    id: Uuid,
    email: String,
    created_by: Uuid,
    creator_name: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    accepted_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

impl InvitationRow {
    fn status(&self) -> String {
        if self.accepted_at.is_some() {
            "accepted"
        } else if self.revoked_at.is_some() {
            "revoked"
        } else if self.expires_at <= Utc::now() {
            "expired"
        } else {
            "pending"
        }
        .into()
    }
}

async fn invitation_view(pool: &PgPool, id: Uuid) -> Result<InvitationView, AppError> {
    let row = sqlx::query_as::<_, InvitationRow>(
        "SELECT i.id,i.email,i.created_by,u.name AS creator_name,i.created_at,i.expires_at,i.accepted_at,i.revoked_at
         FROM user_invitations i JOIN users u ON u.id=i.created_by WHERE i.id=$1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(AppError::not_found)?;
    let roles = sqlx::query_as::<_, RbacRole>(
        "SELECT r.* FROM rbac_roles r JOIN user_invitation_roles ir ON ir.role_id=r.id
         WHERE ir.invitation_id=$1 ORDER BY r.is_system DESC,r.name",
    )
    .bind(id)
    .fetch_all(pool)
    .await?;
    let status = row.status();
    Ok(InvitationView {
        id: row.id,
        email: row.email,
        created_by: row.created_by,
        creator_name: row.creator_name,
        roles,
        status,
        created_at: row.created_at,
        expires_at: row.expires_at,
        accepted_at: row.accepted_at,
        revoked_at: row.revoked_at,
    })
}

pub async fn create_invitation(
    pool: &PgPool,
    principal: &Principal,
    request: Uuid,
    input: CreateInvitation,
    frontend_origin: &str,
) -> Result<InvitationCreated, AppError> {
    principal.require("users.manage")?;
    principal.require("users.assign_roles")?;
    let email = management::email(&input.email)?;
    let hours = input.expires_in_hours.unwrap_or(72);
    if !(1..=168).contains(&hours) {
        return Err(AppError::invalid(
            "Invitation lifetime must be between 1 and 168 hours",
        ));
    }
    let requested: HashSet<_> = input.role_ids.iter().copied().collect();
    if requested.is_empty() || requested.len() != input.role_ids.len() {
        return Err(AppError::invalid("At least one unique role is required"));
    }

    let mut tx = rbac::permission_tx(pool, principal.user.id, "users.assign_roles").await?;
    sqlx::query("SELECT pg_advisory_xact_lock(72146020)")
        .execute(&mut *tx)
        .await?;
    let email_used: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)")
        .bind(&email)
        .fetch_one(&mut *tx)
        .await?;
    if email_used {
        return Err(AppError::conflict("A user with this email already exists"));
    }
    sqlx::query("UPDATE user_invitations SET revoked_at=now() WHERE lower(email)=lower($1) AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at<=now()")
        .bind(&email).execute(&mut *tx).await?;
    let pending: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_invitations WHERE lower(email)=lower($1) AND accepted_at IS NULL AND revoked_at IS NULL)")
        .bind(&email).fetch_one(&mut *tx).await?;
    if pending {
        return Err(AppError::conflict(
            "A pending invitation already exists for this email",
        ));
    }
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
    let permissions: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT permission_key FROM rbac_role_permissions WHERE role_id=ANY($1)",
    )
    .bind(&input.role_ids)
    .fetch_all(&mut *tx)
    .await?;
    rbac::validate_grant(&mut tx, principal.user.id, &permissions).await?;

    let id = Uuid::new_v4();
    let token = auth::new_token();
    let token_hash = auth::digest(&token);
    let expires_at = Utc::now() + Duration::hours(i64::from(hours));
    sqlx::query("INSERT INTO user_invitations(id,email,token_hash,created_by,expires_at) VALUES($1,$2,$3,$4,$5)")
        .bind(id).bind(&email).bind(token_hash).bind(principal.user.id).bind(expires_at).execute(&mut *tx).await?;
    for role_id in &input.role_ids {
        sqlx::query("INSERT INTO user_invitation_roles(invitation_id,role_id) VALUES($1,$2)")
            .bind(id)
            .bind(role_id)
            .execute(&mut *tx)
            .await?;
    }
    management::audit_with_details(
        &mut tx,
        principal.user.id,
        "invitation.create",
        id,
        request,
        serde_json::json!({ "email": email, "role_ids": &input.role_ids, "expires_at": expires_at }),
    )
    .await?;
    tx.commit().await?;
    let invitation = invitation_view(pool, id).await?;
    Ok(InvitationCreated {
        invitation,
        invite_url: format!(
            "{}/invite#token={token}",
            frontend_origin.trim_end_matches('/')
        ),
    })
}

pub async fn list_invitations(
    pool: &PgPool,
    principal: &Principal,
) -> Result<Vec<InvitationView>, AppError> {
    principal.require("users.view")?;
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM user_invitations ORDER BY created_at DESC,id DESC LIMIT 100",
    )
    .fetch_all(pool)
    .await?;
    let mut result = Vec::with_capacity(ids.len());
    for id in ids {
        result.push(invitation_view(pool, id).await?);
    }
    Ok(result)
}

pub async fn revoke_invitation(
    pool: &PgPool,
    principal: &Principal,
    id: Uuid,
    request: Uuid,
) -> Result<(), AppError> {
    principal.require("users.manage")?;
    let mut tx = rbac::permission_tx(pool, principal.user.id, "users.manage").await?;
    let email: String = sqlx::query_scalar(
        "UPDATE user_invitations SET revoked_at=now() WHERE id=$1 AND accepted_at IS NULL AND revoked_at IS NULL RETURNING email",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| AppError::conflict("Invitation is already accepted or revoked"))?;
    management::audit_with_details(
        &mut tx,
        principal.user.id,
        "invitation.revoke",
        id,
        request,
        serde_json::json!({ "email": email }),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn accept_invitation(
    pool: &PgPool,
    runtime: &AuthRuntime,
    request: Uuid,
    input: AcceptInvitation,
) -> Result<User, AppError> {
    let invalid = || AppError::invalid("Invalid, expired or already used invitation");
    if input.token.len() != 64 || !input.token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    let name = management::display_name(&input.name)?;
    management::password(&input.password)?;
    let password_hash = runtime.hash(input.password).await?;
    let token_hash = auth::digest(&input.token);
    let mut tx = pool.begin().await?;
    let invitation: Option<(Uuid, String, Uuid)> = sqlx::query_as(
        "SELECT id,email,created_by FROM user_invitations WHERE token_hash=$1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>now() FOR UPDATE",
    )
    .bind(token_hash)
    .fetch_optional(&mut *tx)
    .await?;
    let (invitation_id, email, inviter) = invitation.ok_or_else(invalid)?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)")
        .bind(&email)
        .fetch_one(&mut *tx)
        .await?;
    if exists {
        return Err(AppError::conflict("A user with this email already exists"));
    }
    let role_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT role_id FROM user_invitation_roles WHERE invitation_id=$1 ORDER BY role_id",
    )
    .bind(invitation_id)
    .fetch_all(&mut *tx)
    .await?;
    if role_ids.is_empty() {
        return Err(invalid());
    }
    let legacy_role = if role_ids.contains(&OWNER_ROLE_ID) {
        Role::Admin
    } else if role_ids == [Uuid::from_u128(0x00000000000040008000000000000005)] {
        Role::Viewer
    } else {
        Role::User
    };
    let user_id = Uuid::new_v4();
    let user = sqlx::query_as::<_, User>(
        "INSERT INTO users(id,username,name,email,email_verified_at,password_hash,role) VALUES($1,$2,$3,$4,now(),$5,$6)
         RETURNING id,username,name,email,email_verified_at,role,is_active,created_at,updated_at",
    )
    .bind(user_id)
    .bind(user_id.simple().to_string())
    .bind(name)
    .bind(&email)
    .bind(password_hash)
    .bind(legacy_role)
    .fetch_one(&mut *tx)
    .await?;
    for role_id in &role_ids {
        sqlx::query(
            "INSERT INTO user_role_assignments(user_id,role_id,assigned_by) VALUES($1,$2,$3)",
        )
        .bind(user_id)
        .bind(role_id)
        .bind(inviter)
        .execute(&mut *tx)
        .await?;
    }
    let consumed = sqlx::query("UPDATE user_invitations SET accepted_at=now(),accepted_user_id=$2 WHERE id=$1 AND accepted_at IS NULL AND revoked_at IS NULL")
        .bind(invitation_id).bind(user_id).execute(&mut *tx).await?.rows_affected();
    if consumed != 1 {
        return Err(invalid());
    }
    management::audit_with_details(
        &mut tx,
        user_id,
        "invitation.accept",
        invitation_id,
        request,
        serde_json::json!({ "email": email, "role_ids": role_ids }),
    )
    .await?;
    tx.commit().await?;
    Ok(user)
}

#[derive(Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct AuditQuery {
    pub limit: Option<u32>,
}

#[derive(Serialize, FromRow, ToSchema)]
pub struct AuditEntry {
    pub id: Uuid,
    pub actor_id: Option<Uuid>,
    pub actor_name: Option<String>,
    pub actor_email: Option<String>,
    pub action: String,
    pub object_id: Uuid,
    pub request_id: Uuid,
    pub details: Value,
    pub created_at: DateTime<Utc>,
}

pub async fn role_audit(
    pool: &PgPool,
    principal: &Principal,
    query: AuditQuery,
) -> Result<Vec<AuditEntry>, AppError> {
    principal.require("audit.view")?;
    let limit = match query.limit.unwrap_or(50) {
        value @ 1..=100 => value,
        _ => return Err(AppError::invalid("Limit must be between 1 and 100")),
    };
    Ok(sqlx::query_as::<_, AuditEntry>(
        "SELECT a.id,a.actor_id,u.name AS actor_name,u.email AS actor_email,a.action,a.object_id,a.request_id,a.details,a.created_at
         FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id
         WHERE a.action LIKE 'role.%' OR a.action='user.roles_assigned' OR a.action LIKE 'invitation.%'
         ORDER BY a.created_at DESC,a.id DESC LIMIT $1",
    )
    .bind(i64::from(limit))
    .fetch_all(pool)
    .await?)
}
