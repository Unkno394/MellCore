use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use axum::{
    extract::FromRequestParts,
    http::{HeaderMap, request::Parts},
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, Semaphore};
use uuid::Uuid;

use crate::{api::AppState, errors::AppError, management::User};

pub struct AuthRuntime {
    slots: Arc<Semaphore>,
    attempts: Mutex<(Instant, u32)>,
    per_minute: u32,
    pub dummy_hash: String,
}

impl AuthRuntime {
    pub async fn new(concurrency: usize, per_minute: u32) -> Result<Self, AppError> {
        let dummy_hash = tokio::task::spawn_blocking(|| hash_sync(&new_token()))
            .await
            .map_err(|_| AppError::internal())??;
        Ok(Self {
            slots: Arc::new(Semaphore::new(concurrency)),
            attempts: Mutex::new((Instant::now(), 0)),
            per_minute,
            dummy_hash,
        })
    }

    pub async fn allow_login(&self) -> Result<(), AppError> {
        let mut attempts = self.attempts.lock().await;
        if attempts.0.elapsed() >= Duration::from_secs(60) {
            *attempts = (Instant::now(), 0);
        }
        if attempts.1 >= self.per_minute {
            return Err(AppError::busy());
        }
        attempts.1 += 1;
        Ok(())
    }

    pub async fn hash(&self, password: String) -> Result<String, AppError> {
        let slot = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| AppError::busy())?;
        tokio::task::spawn_blocking(move || {
            let _slot = slot;
            hash_sync(&password)
        })
        .await
        .map_err(|_| AppError::internal())?
    }

    pub async fn verify(&self, password: String, hash: String) -> Result<bool, AppError> {
        let slot = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| AppError::busy())?;
        tokio::task::spawn_blocking(move || {
            let _slot = slot;
            let parsed = PasswordHash::new(&hash).map_err(|_| AppError::internal())?;
            Ok(Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok())
        })
        .await
        .map_err(|_| AppError::internal())?
    }
}

fn hash_sync(password: &str) -> Result<String, AppError> {
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|h| h.to_string())
        .map_err(|_| AppError::internal())
}

pub fn new_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}
pub fn digest(value: &str) -> Vec<u8> {
    Sha256::digest(value.as_bytes()).to_vec()
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub jti: Uuid,
    pub iat: i64,
    pub exp: i64,
    pub iss: String,
    pub aud: String,
}

pub struct Jwt {
    encoding: EncodingKey,
    decoding: DecodingKey,
    validation: Validation,
}

impl Jwt {
    pub fn new(secret: &str) -> Result<Self, AppError> {
        if secret.len() < 32 {
            return Err(AppError::invalid(
                "JWT_SECRET requires at least 32 random bytes",
            ));
        }
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_required_spec_claims(&["sub", "exp", "iss", "aud"]);
        validation.set_issuer(&["honeyforge"]);
        validation.set_audience(&["honeyforge-api"]);
        validation.leeway = 0;
        Ok(Self {
            encoding: EncodingKey::from_secret(secret.as_bytes()),
            decoding: DecodingKey::from_secret(secret.as_bytes()),
            validation,
        })
    }
    pub fn issue(&self, sub: Uuid, jti: Uuid, exp: i64) -> Result<String, AppError> {
        let claims = Claims {
            sub,
            jti,
            iat: chrono::Utc::now().timestamp(),
            exp,
            iss: "honeyforge".into(),
            aud: "honeyforge-api".into(),
        };
        jsonwebtoken::encode(&Header::new(Algorithm::HS256), &claims, &self.encoding)
            .map_err(|_| AppError::internal())
    }
    pub fn verify(&self, token: &str) -> Result<Claims, AppError> {
        let claims = jsonwebtoken::decode::<Claims>(token, &self.decoding, &self.validation)
            .map_err(|_| AppError::unauthorized())?
            .claims;
        if claims.iat > chrono::Utc::now().timestamp() || claims.exp <= claims.iat {
            return Err(AppError::unauthorized());
        }
        Ok(claims)
    }
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, AppError> {
    if headers.get_all("authorization").iter().count() != 1 {
        return Err(AppError::unauthorized());
    }
    let value = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(AppError::unauthorized)?;
    let (scheme, token) = value.split_once(' ').ok_or_else(AppError::unauthorized)?;
    if !scheme.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || token.len() > 4096
        || token.chars().any(char::is_whitespace)
    {
        return Err(AppError::unauthorized());
    }
    Ok(token)
}

pub struct Principal {
    pub user: User,
    pub token_id: Uuid,
    pub permissions: HashSet<String>,
}

impl Principal {
    pub fn require(&self, permission: &str) -> Result<(), AppError> {
        if !self.permissions.contains(permission) {
            return Err(AppError::forbidden());
        }
        Ok(())
    }

    pub fn require_admin(&self) -> Result<(), AppError> {
        self.require("users.manage")
    }
}

impl FromRequestParts<AppState> for Principal {
    type Rejection = AppError;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(&parts.headers)?;
        let claims = state.jwt()?.verify(token)?;
        // Current role and active status always come from PostgreSQL, never client claims.
        let user = sqlx::query_as::<_, User>("SELECT u.id, u.username, u.name, u.email, u.email_verified_at, u.role, u.is_active, u.created_at, u.updated_at FROM users u JOIN access_tokens t ON t.user_id=u.id WHERE u.id=$1 AND t.id=$2 AND t.expires_at>now() AND u.is_active")
            .bind(claims.sub).bind(claims.jti).fetch_optional(state.pool()?).await?.ok_or_else(AppError::unauthorized)?;
        if state.config.require_email_verification && user.email_verified_at.is_none() {
            return Err(AppError::email_unverified());
        }
        // JWTs carry identity only. Resolve current permissions on every
        // request so role changes are immediate and default-deny.
        let permissions = crate::rbac::effective_permissions(state.pool()?, user.id).await?;
        Ok(Self {
            user,
            token_id: claims.jti,
            permissions,
        })
    }
}
