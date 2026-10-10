use crate::{
    api::AppState,
    auth::{self, Principal},
    errors::{AppError, RequestId},
    management::{self, User},
};
use axum::{Extension, Json, extract::State, http::StatusCode};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RegisterRequest {
    pub name: String,
    pub email: String,
    #[schema(write_only)]
    pub password: String,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    pub email: String,
    #[schema(write_only)]
    pub password: String,
}
#[derive(Serialize, ToSchema)]
pub struct TokenResponse {
    pub user: User,
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
}
#[derive(Serialize, ToSchema)]
pub struct MeResponse {
    pub user: User,
}

#[utoipa::path(post, path="/api/v1/auth/register", tag="auth", request_body=RegisterRequest,
    responses((status=201, body=User, description="Account created; verification queued when SMTP is configured"), (status=503, body=crate::errors::ErrorResponse), (status=409, body=crate::errors::ErrorResponse), (status=422, body=crate::errors::ErrorResponse), (status=429, body=crate::errors::ErrorResponse)))]
pub async fn register(
    State(state): State<AppState>,
    Extension(id): Extension<RequestId>,
    Json(input): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<User>), AppError> {
    if state.config.require_email_verification && state.email_verifications.is_none() {
        return Err(AppError::mail_unavailable());
    }
    let runtime = state.auth()?;
    runtime.allow_login().await?;
    let name = management::display_name(&input.name)?;
    let email = management::email(&input.email)?;
    management::password(&input.password)?;
    let hash = runtime.hash(input.password).await?;
    let user_id = Uuid::new_v4();
    let mut tx = state.pool()?.begin().await?;
    // Username is retained solely for compatibility with existing administration.
    // Public clients cannot choose a role, ID or legacy username.
    let user = sqlx::query_as::<_, User>("INSERT INTO users(id,username,name,email,password_hash,role) VALUES ($1,$2,$3,$4,$5,'user') RETURNING id,username,name,email,email_verified_at,role,is_active,created_at,updated_at")
        .bind(user_id).bind(user_id.simple().to_string()).bind(name).bind(email).bind(hash).fetch_one(&mut *tx).await?;
    management::audit(&mut tx, user.id, "auth.register", user.id, id.0).await?;
    tx.commit().await?;
    if let Some(queue) = &state.email_verifications
        && queue
            .enqueue(
                user.email.clone().expect("registration requires email"),
                id.0,
            )
            .is_err()
    {
        // Account is committed; a resend can be requested. Do not return a false registration failure.
        tracing::warn!(request_id=%id.0,"verification email could not be queued");
    }
    Ok((StatusCode::CREATED, Json(user)))
}

#[utoipa::path(post, path="/api/v1/auth/login", tag="auth", request_body=LoginRequest,
    responses((status=200, body=TokenResponse), (status=403, description="email_not_verified when REQUIRE_EMAIL_VERIFICATION=true", body=crate::errors::ErrorResponse), (status=401, body=crate::errors::ErrorResponse), (status=429, body=crate::errors::ErrorResponse), (status=503, body=crate::errors::ErrorResponse)))]
pub async fn login(
    State(state): State<AppState>,
    Extension(id): Extension<RequestId>,
    Json(input): Json<LoginRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let runtime = state.auth()?;
    runtime.allow_login().await?;
    let email = management::email(&input.email).map_err(|_| AppError::unauthorized())?;
    if input.password.is_empty() || input.password.len() > 256 {
        return Err(AppError::unauthorized());
    }
    let pool = state.pool()?;
    let record: Option<(Uuid, String)> =
        sqlx::query_as("SELECT id,password_hash FROM users WHERE email=$1")
            .bind(&email)
            .fetch_optional(pool)
            .await?;
    let hash = record
        .as_ref()
        .map(|(_, h)| h)
        .unwrap_or(&runtime.dummy_hash)
        .clone();
    let valid = runtime.verify(input.password, hash.clone()).await?;
    let Some((user_id, _)) = record.filter(|_| valid) else {
        return Err(AppError::unauthorized());
    };
    let mut tx = pool.begin().await?;
    // Password/email changes and deactivation serialize on this user row.
    let user = sqlx::query_as::<_, User>("SELECT id,username,name,email,email_verified_at,role,is_active,created_at,updated_at FROM users WHERE id=$1 AND password_hash=$2 AND email=$3 AND is_active FOR UPDATE")
        .bind(user_id).bind(hash).bind(email).fetch_optional(&mut *tx).await?.ok_or_else(AppError::unauthorized)?;
    if state.config.require_email_verification && user.email_verified_at.is_none() {
        return Err(AppError::email_unverified());
    }
    sqlx::query("DELETE FROM access_tokens WHERE user_id=$1 AND expires_at<=now()")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM access_tokens WHERE id IN (SELECT id FROM access_tokens WHERE user_id=$1 ORDER BY created_at DESC,id OFFSET 9)").bind(user_id).execute(&mut *tx).await?;
    let token_id = Uuid::new_v4();
    let expires = Utc::now() + Duration::seconds(state.config.jwt_ttl_seconds);
    let access_token = state.jwt()?.issue(user_id, token_id, expires.timestamp())?;
    sqlx::query("INSERT INTO access_tokens(id,user_id,expires_at) VALUES ($1,$2,$3)")
        .bind(token_id)
        .bind(user_id)
        .bind(expires)
        .execute(&mut *tx)
        .await?;
    management::audit(&mut tx, user_id, "auth.login", user_id, id.0).await?;
    tx.commit().await?;
    Ok(Json(TokenResponse {
        user,
        access_token,
        token_type: "Bearer".into(),
        expires_in: state.config.jwt_ttl_seconds,
    }))
}

#[utoipa::path(get,path="/api/v1/auth/me",tag="auth",security(("bearer"=[])),responses((status=200,body=MeResponse),(status=403,body=crate::errors::ErrorResponse),(status=401,body=crate::errors::ErrorResponse)))]
pub async fn me(principal: Principal) -> Json<MeResponse> {
    Json(MeResponse {
        user: principal.user,
    })
}

#[utoipa::path(post,path="/api/v1/auth/logout",tag="auth",security(("bearer"=[])),responses((status=204,description="JWT revoked"),(status=403,body=crate::errors::ErrorResponse),(status=401,body=crate::errors::ErrorResponse)))]
pub async fn logout(
    State(state): State<AppState>,
    principal: Principal,
    Extension(id): Extension<RequestId>,
) -> Result<StatusCode, AppError> {
    let mut tx = state.pool()?.begin().await?;
    sqlx::query("DELETE FROM access_tokens WHERE id=$1")
        .bind(principal.token_id)
        .execute(&mut *tx)
        .await?;
    management::audit(
        &mut tx,
        principal.user.id,
        "auth.logout",
        principal.user.id,
        id.0,
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ForgotPassword {
    pub email: String,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ResetPassword {
    #[schema(write_only)]
    pub token: String,
    #[schema(write_only)]
    pub password: String,
}
#[derive(Serialize, ToSchema)]
pub struct ResetAccepted {
    pub message: String,
}
#[utoipa::path(post,path="/api/v1/auth/forgot-password",tag="auth",request_body=ForgotPassword,responses((status=202,body=ResetAccepted),(status=422,body=crate::errors::ErrorResponse),(status=429,body=crate::errors::ErrorResponse),(status=503,body=crate::errors::ErrorResponse)))]
pub async fn forgot_password(
    State(state): State<AppState>,
    Extension(id): Extension<RequestId>,
    Json(input): Json<ForgotPassword>,
) -> Result<(StatusCode, Json<ResetAccepted>), AppError> {
    state.auth()?.allow_login().await?;
    let email = management::email(&input.email)?;
    // Queue both existing and unknown addresses; response cannot reveal existence.
    state
        .password_resets
        .as_ref()
        .ok_or_else(AppError::mail_unavailable)?
        .enqueue(email, id.0)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(ResetAccepted {
            message: "If this account is eligible, password reset instructions will be sent."
                .into(),
        }),
    ))
}
#[utoipa::path(post,path="/api/v1/auth/reset-password",tag="auth",request_body=ResetPassword,responses((status=204,description="Password changed and all credentials revoked"),(status=422,body=crate::errors::ErrorResponse),(status=429,body=crate::errors::ErrorResponse)))]
pub async fn reset_password(
    State(state): State<AppState>,
    Extension(id): Extension<RequestId>,
    Json(input): Json<ResetPassword>,
) -> Result<StatusCode, AppError> {
    let runtime = state.auth()?;
    runtime.allow_login().await?;
    if input.token.len() != 64 || !input.token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AppError::invalid("Invalid or expired reset token"));
    }
    management::password(&input.password)?;
    let token_hash = auth::digest(&input.token);
    let pool = state.pool()?;
    let user_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM password_resets WHERE token_hash=$1 AND expires_at>now()",
    )
    .bind(&token_hash)
    .fetch_optional(pool)
    .await?;
    let user_id = user_id.ok_or_else(|| AppError::invalid("Invalid or expired reset token"))?;
    let hash = runtime.hash(input.password).await?;
    let mut tx = pool.begin().await?;
    let active: Option<bool> =
        sqlx::query_scalar("SELECT is_active FROM users WHERE id=$1 FOR UPDATE")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
    if active != Some(true) {
        return Err(AppError::invalid("Invalid or expired reset token"));
    }
    let consumed = sqlx::query(
        "DELETE FROM password_resets WHERE user_id=$1 AND token_hash=$2 AND expires_at>now()",
    )
    .bind(user_id)
    .bind(&token_hash)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if consumed != 1 {
        return Err(AppError::invalid("Invalid or expired reset token"));
    }
    sqlx::query("UPDATE users SET password_hash=$2,updated_at=now() WHERE id=$1")
        .bind(user_id)
        .bind(hash)
        .execute(&mut *tx)
        .await?;
    management::revoke_credentials(&mut tx, user_id).await?;
    management::audit(&mut tx, user_id, "auth.password_reset", user_id, id.0).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifyEmail {
    #[schema(write_only)]
    pub token: String,
}
#[utoipa::path(post,path="/api/v1/auth/verify-email",tag="auth",request_body=VerifyEmail,responses((status=204,description="Email verified; sign in again"),(status=422,body=crate::errors::ErrorResponse),(status=429,body=crate::errors::ErrorResponse)))]
pub async fn verify_email(
    State(state): State<AppState>,
    Extension(id): Extension<RequestId>,
    Json(input): Json<VerifyEmail>,
) -> Result<StatusCode, AppError> {
    state.auth()?.allow_login().await?;
    crate::email_verification::consume(state.pool()?, &input.token, id.0).await?;
    Ok(StatusCode::NO_CONTENT)
}
#[utoipa::path(post,path="/api/v1/auth/resend-verification",tag="auth",request_body=ForgotPassword,responses((status=202,body=ResetAccepted),(status=422,body=crate::errors::ErrorResponse),(status=429,body=crate::errors::ErrorResponse),(status=503,body=crate::errors::ErrorResponse)))]
pub async fn resend_verification(
    State(state): State<AppState>,
    Extension(id): Extension<RequestId>,
    Json(input): Json<ForgotPassword>,
) -> Result<(StatusCode, Json<ResetAccepted>), AppError> {
    state.auth()?.allow_login().await?;
    let email = management::email(&input.email)?;
    state
        .email_verifications
        .as_ref()
        .ok_or_else(AppError::mail_unavailable)?
        .enqueue(email, id.0)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(ResetAccepted {
            message: "If this account is eligible, verification instructions will be sent.".into(),
        }),
    ))
}
