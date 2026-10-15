pub mod profiles;
pub mod users;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::{
    errors::AppError,
    models::{Role, TrapLevel},
};

#[derive(Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub name: String,
    pub email: Option<String>,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub role: Role,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateUser {
    pub username: String,
    pub name: Option<String>,
    pub email: Option<String>,
    #[schema(write_only)]
    pub password: String,
    pub role: Role,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateUser {
    pub username: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub role: Role,
    pub is_active: bool,
    #[schema(write_only)]
    pub password: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Profile {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub level: TrapLevel,
    pub honeypot_type: String,
    pub service_type: String,
    pub config: Value,
    #[sqlx(json)]
    #[serde(default)]
    pub resources: crate::resources::ContainerResourceLimits,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfileInput {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub level: TrapLevel,
    pub honeypot_type: String,
    pub service_type: String,
    pub config: Value,
    #[serde(default)]
    pub resources: Option<crate::resources::ContainerResourceLimits>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateProfile {
    pub expected_version: i64,
    pub profile: ProfileInput,
}

impl ProfileInput {
    pub fn validate(&self) -> Result<(), AppError> {
        if self.name.trim().is_empty()
            || self.name.len() > 128
            || self.name.chars().any(char::is_control)
            || self.description.len() > 4096
        {
            return Err(AppError::invalid("Invalid profile name or description"));
        }
        for label in [&self.honeypot_type, &self.service_type] {
            if label.is_empty()
                || label.len() > 128
                || !label
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(&c))
            {
                return Err(AppError::invalid("Invalid honeypot or service type"));
            }
        }
        validate_config(&self.config)?;
        if let Some(resources) = self.resources.filter(|_| self.level != TrapLevel::High) {
            resources.validate_for_level(self.level)?;
        }
        if self.honeypot_type == "kozyavka" {
            crate::kozyavka::validate_profile(self.level, &self.service_type, &self.config)?;
        }
        if self.honeypot_type == "pritvoryashka" {
            crate::pritvoryashka::validate_profile(self.level, &self.service_type, &self.config)?;
        }
        if self.honeypot_type == "high_ubuntu_ssh" {
            crate::high_ubuntu::validate_profile(self.level, &self.service_type, &self.config)?;
        } else if self.level == TrapLevel::High {
            return Err(AppError::invalid(
                "High interaction currently requires the high_ubuntu_ssh profile",
            ));
        }
        Ok(())
    }

    pub fn resolved_resources(&self) -> crate::resources::ContainerResourceLimits {
        if self.level == TrapLevel::High {
            return crate::resources::ContainerResourceLimits::low_default();
        }
        self.resources.unwrap_or_else(|| match self.level {
            TrapLevel::Low | TrapLevel::High => {
                crate::resources::ContainerResourceLimits::low_default()
            }
            TrapLevel::Medium => crate::resources::ContainerResourceLimits::middle_default(),
        })
    }
}

pub fn validate_config(config: &Value) -> Result<(), AppError> {
    if !config.is_object()
        || serde_json::to_vec(config)
            .map_err(|_| AppError::invalid("Invalid config"))?
            .len()
            > 65536
    {
        return Err(AppError::invalid(
            "Config must be a JSON object up to 64 KiB",
        ));
    }
    if contains_secret(config) {
        return Err(AppError::invalid(
            "Credentials must be supplied via secret references, not config",
        ));
    }
    Ok(())
}

// A guardrail, not a secret detector. Service-specific schemas follow when real
// infrastructure is connected. Arbitrary profiles are never executed in stage 2.
fn contains_secret(value: &Value) -> bool {
    let decoy_ssh_credentials = value.as_object().is_some_and(|object| {
        matches!(
            object.get("ssh_auth_mode").and_then(Value::as_str),
            Some("realistic" | "adaptive")
        ) && object
            .get("ssh_credentials")
            .and_then(Value::as_array)
            .is_some_and(|credentials| {
                !credentials.is_empty()
                    && credentials.iter().all(|credential| {
                        credential.as_object().is_some_and(|fields| {
                            fields.len() == 2
                                && fields.get("username").is_some_and(Value::is_string)
                                && fields.get("password").is_some_and(Value::is_string)
                        })
                    })
            })
    });
    contains_secret_inner(value, decoy_ssh_credentials, false)
}

fn contains_secret_inner(
    value: &Value,
    allow_decoy_ssh_credentials: bool,
    in_ssh_credential: bool,
) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, child)| {
            let allowed_weak_password = allow_decoy_ssh_credentials
                && in_ssh_credential
                && key == "password"
                && child.is_string();
            let contains_secret_key = matches!(
                key.to_ascii_lowercase().as_str(),
                "password" | "private_key" | "ssh_key" | "token" | "secret"
            );
            (contains_secret_key && !allowed_weak_password)
                || contains_secret_inner(
                    child,
                    allow_decoy_ssh_credentials,
                    allow_decoy_ssh_credentials && key == "ssh_credentials",
                )
        }),
        Value::Array(values) => values.iter().any(|child| {
            contains_secret_inner(child, allow_decoy_ssh_credentials, in_ssh_credential)
        }),
        _ => false,
    }
}

#[derive(Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub after: Option<Uuid>,
    pub limit: Option<u32>,
}

impl Page {
    pub fn size(&self) -> Result<usize, AppError> {
        match self.limit.unwrap_or(50) {
            n @ 1..=100 => Ok(n as usize),
            _ => Err(AppError::invalid("Limit must be between 1 and 100")),
        }
    }
}

#[derive(Serialize, ToSchema)]
pub struct UserPage {
    pub items: Vec<User>,
    pub next_cursor: Option<Uuid>,
}

#[derive(Serialize, ToSchema)]
pub struct ProfilePage {
    pub items: Vec<Profile>,
    pub next_cursor: Option<Uuid>,
}

pub fn username(value: &str) -> Result<String, AppError> {
    let value = value.trim().to_ascii_lowercase();
    if !(3..=64).contains(&value.len())
        || !value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"_.-".contains(&c))
    {
        return Err(AppError::invalid(
            "Username must have 3–64 ASCII letters, digits, dots, underscores or hyphens",
        ));
    }
    Ok(value)
}

pub fn email(value: &str) -> Result<String, AppError> {
    let value = value.trim().to_ascii_lowercase();
    if value.len() > 254 || !value.is_ascii() || value.parse::<lettre::Address>().is_err() {
        return Err(AppError::invalid("Invalid email address"));
    }
    Ok(value)
}

pub fn display_name(value: &str) -> Result<String, AppError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(AppError::invalid(
            "Name must contain 1–128 bytes without control characters",
        ));
    }
    Ok(value.to_owned())
}

pub async fn revoke_credentials(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
) -> Result<(), AppError> {
    for query in [
        "DELETE FROM sessions WHERE user_id=$1",
        "DELETE FROM access_tokens WHERE user_id=$1",
        "DELETE FROM refresh_sessions WHERE user_id=$1",
        "DELETE FROM password_resets WHERE user_id=$1",
        "DELETE FROM email_verifications WHERE user_id=$1",
    ] {
        sqlx::query(query).bind(user).execute(&mut **tx).await?;
    }
    Ok(())
}

pub fn password(value: &str) -> Result<(), AppError> {
    if value.chars().count() < 12 || value.len() > 256 {
        return Err(AppError::invalid(
            "Password must have at least 12 characters and at most 256 bytes",
        ));
    }
    Ok(())
}

/// Serialize management mutations and recheck the actor inside the transaction.
/// This also closes the last-admin and concurrent role-revocation races.
pub async fn admin_tx(pool: &PgPool, actor: Uuid) -> Result<Transaction<'_, Postgres>, AppError> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(72146020)")
        .execute(&mut *tx)
        .await?;
    let allowed: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND role='admin' AND is_active)",
    )
    .bind(actor)
    .fetch_one(&mut *tx)
    .await?;
    if !allowed {
        return Err(AppError::forbidden());
    }
    Ok(tx)
}

pub async fn protect_last_admin(
    tx: &mut Transaction<'_, Postgres>,
    target: Uuid,
) -> Result<(), AppError> {
    let last: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND role='admin' AND is_active) AND (SELECT count(*) FROM users WHERE role='admin' AND is_active)=1")
        .bind(target).fetch_one(&mut **tx).await?;
    if last {
        return Err(AppError::conflict(
            "Cannot remove, disable or demote the last active administrator",
        ));
    }
    Ok(())
}

pub async fn audit(
    tx: &mut Transaction<'_, Postgres>,
    actor: Uuid,
    action: &str,
    object: Uuid,
    request: Uuid,
) -> Result<(), AppError> {
    sqlx::query("INSERT INTO audit_logs(id, actor_id, action, object_id, request_id) VALUES ($1,$2,$3,$4,$5)")
        .bind(Uuid::new_v4()).bind(actor).bind(action).bind(object).bind(request).execute(&mut **tx).await?;
    Ok(())
}

/// One-time local bootstrap; never a public HTTP endpoint.
pub async fn bootstrap(
    pool: &PgPool,
    auth: &crate::auth::AuthRuntime,
    name: &str,
    address: &str,
    secret: String,
) -> Result<Uuid, AppError> {
    let name = username(name)?;
    let address = email(address)?;
    password(&secret)?;
    let hash = auth.hash(secret).await?;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(72146020)")
        .execute(&mut *tx)
        .await?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE role='admin')")
        .fetch_one(&mut *tx)
        .await?;
    if exists {
        return Err(AppError::conflict(
            "Bootstrap is only available when no administrator exists",
        ));
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id, username, name, email, password_hash, role) VALUES ($1,$2,$2,$4,$3,'admin')")
        .bind(id)
        .bind(name)
        .bind(hash)
        .bind(address)
        .execute(&mut *tx)
        .await?;
    audit(&mut tx, id, "user.bootstrap", id, Uuid::new_v4()).await?;
    tx.commit().await?;
    Ok(id)
}

/// Local migration tool: only attach an address to an existing email-less account.
pub async fn attach_email(
    pool: &PgPool,
    legacy_username: &str,
    address: &str,
) -> Result<(), AppError> {
    let address = email(address)?;
    let username = username(legacy_username)?;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(72146020)")
        .execute(&mut *tx)
        .await?;
    let id: Uuid = sqlx::query_scalar("UPDATE users SET email=$2, updated_at=now() WHERE username=$1 AND email IS NULL RETURNING id")
        .bind(username).bind(address).fetch_optional(&mut *tx).await?.ok_or_else(AppError::not_found)?;
    revoke_credentials(&mut tx, id).await?;
    audit(&mut tx, id, "user.attach_email", id, Uuid::new_v4()).await?;
    tx.commit().await?;
    Ok(())
}
