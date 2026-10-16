use crate::{
    api::AppState,
    auth::{self, Principal},
    errors::{AppError, RequestId},
    management::{self, User},
};
use axum::{
    Extension, Json,
    extract::State,
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{COOKIE, ORIGIN, SET_COOKIE},
    },
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

const REFRESH_COOKIE: &str = "__Host-mellcore-refresh";
const REFRESH_LIFETIME_SECONDS: i64 = 30 * 24 * 60 * 60;

fn refresh_cookie(token: &str) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{REFRESH_COOKIE}={token}; Path=/; Max-Age={REFRESH_LIFETIME_SECONDS}; HttpOnly; Secure; SameSite=Strict"
    ))
    .expect("hex token is a valid cookie value")
}

fn clear_refresh_cookie() -> HeaderValue {
    HeaderValue::from_static(
        "__Host-mellcore-refresh=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict",
    )
}

fn cookie_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(name, value)| {
            (name == REFRESH_COOKIE
                && value.len() == 64
                && value.bytes().all(|b| b.is_ascii_hexdigit()))
            .then_some(value)
        })
}

fn require_same_origin(headers: &HeaderMap, origin: &str) -> Result<(), AppError> {
    if headers.get(ORIGIN).and_then(|value| value.to_str().ok()) == Some(origin) {
        Ok(())
    } else {
        Err(AppError::forbidden())
    }
}

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
    pub roles: Vec<crate::rbac::RbacRole>,
    pub permissions: Vec<String>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangePassword {
    #[schema(write_only)]
    pub current_password: String,
    #[schema(write_only)]
    pub new_password: String,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangeEmail {
    #[schema(write_only)]
    pub current_password: String,
    pub new_email: String,
}

#[derive(Serialize, ToSchema)]
pub struct EmailChangeAccepted {
    pub message: String,
}

#[utoipa::path(post, path="/api/v1/auth/change-password", tag="auth", security(("bearer"=[])), request_body=ChangePassword,
    responses((status=204, description="Password changed; all sessions are revoked"), (status=401, body=crate::errors::ErrorResponse), (status=422, body=crate::errors::ErrorResponse), (status=429, body=crate::errors::ErrorResponse)))]
pub async fn change_password(
    State(state): State<AppState>,
    principal: Principal,
    Extension(id): Extension<RequestId>,
    Json(input): Json<ChangePassword>,
) -> Result<StatusCode, AppError> {
    let runtime = state.auth()?;
    runtime.allow_login().await?;
    if input.current_password.is_empty() || input.current_password.len() > 256 {
        return Err(AppError::unauthorized());
    }
    management::password(&input.new_password)?;
    let old_hash: String =
        sqlx::query_scalar("SELECT password_hash FROM users WHERE id=$1 AND is_active")
            .bind(principal.user.id)
            .fetch_optional(state.pool()?)
            .await?
            .ok_or_else(AppError::unauthorized)?;
    if !runtime
        .verify(input.current_password, old_hash.clone())
        .await?
    {
        return Err(AppError::unauthorized());
    }
    let new_hash = runtime.hash(input.new_password).await?;
    let mut tx = state.pool()?.begin().await?;
    let current_hash: Option<String> =
        sqlx::query_scalar("SELECT password_hash FROM users WHERE id=$1 AND is_active FOR UPDATE")
            .bind(principal.user.id)
            .fetch_optional(&mut *tx)
            .await?;
    if current_hash.as_deref() != Some(old_hash.as_str()) {
        return Err(AppError::unauthorized());
    }
    sqlx::query("UPDATE users SET password_hash=$2,updated_at=now() WHERE id=$1")
        .bind(principal.user.id)
        .bind(new_hash)
        .execute(&mut *tx)
        .await?;
    management::revoke_credentials(&mut tx, principal.user.id).await?;
    management::audit(
        &mut tx,
        principal.user.id,
        "auth.password_changed",
        principal.user.id,
        id.0,
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(post, path="/api/v1/auth/change-email", tag="auth", security(("bearer"=[])), request_body=ChangeEmail,
    responses((status=202, body=EmailChangeAccepted), (status=401, body=crate::errors::ErrorResponse), (status=409, body=crate::errors::ErrorResponse), (status=422, body=crate::errors::ErrorResponse), (status=429, body=crate::errors::ErrorResponse), (status=503, body=crate::errors::ErrorResponse)))]
pub async fn change_email(
    State(state): State<AppState>,
    principal: Principal,
    Extension(id): Extension<RequestId>,
    Json(input): Json<ChangeEmail>,
) -> Result<(StatusCode, Json<EmailChangeAccepted>), AppError> {
    let runtime = state.auth()?;
    runtime.allow_login().await?;
    if input.current_password.is_empty() || input.current_password.len() > 256 {
        return Err(AppError::unauthorized());
    }
    let new_email = management::email(&input.new_email)?;
    if principal.user.email.as_deref() == Some(new_email.as_str()) {
        return Err(AppError::invalid(
            "New email must differ from the current email",
        ));
    }
    let old_hash: String =
        sqlx::query_scalar("SELECT password_hash FROM users WHERE id=$1 AND is_active")
            .bind(principal.user.id)
            .fetch_optional(state.pool()?)
            .await?
            .ok_or_else(AppError::unauthorized)?;
    if !runtime.verify(input.current_password, old_hash).await? {
        return Err(AppError::unauthorized());
    }
    let used: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email=$1) OR EXISTS(SELECT 1 FROM email_verifications WHERE email=$1 AND user_id<>$2 AND expires_at>now())")
        .bind(&new_email).bind(principal.user.id).fetch_one(state.pool()?).await?;
    if used {
        return Err(AppError::conflict("Email address is already in use"));
    }
    let recent: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM email_verifications WHERE user_id=$1 AND created_at>now()-interval '1 minute')")
        .bind(principal.user.id).fetch_one(state.pool()?).await?;
    if recent {
        return Err(AppError::busy());
    }
    state
        .email_verifications
        .as_ref()
        .ok_or_else(AppError::mail_unavailable)?
        .enqueue_change(principal.user.id, new_email, id.0)?;
    let mut tx = state.pool()?.begin().await?;
    management::audit(
        &mut tx,
        principal.user.id,
        "auth.email_change_requested",
        principal.user.id,
        id.0,
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(EmailChangeAccepted {
            message:
                "Подтвердите новый адрес по ссылке из письма. После подтверждения войдите снова."
                    .into(),
        }),
    ))
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
    sqlx::query("INSERT INTO user_role_assignments(user_id,role_id,assigned_by) VALUES($1,'00000000-0000-4000-8000-000000000004',$1)")
        .bind(user.id).execute(&mut *tx).await?;
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
) -> Result<(HeaderMap, Json<TokenResponse>), AppError> {
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
    let refresh_token = auth::new_token();
    let refresh_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO refresh_sessions(id,user_id,token_hash,expires_at) VALUES ($1,$2,$3,$4)",
    )
    .bind(refresh_id)
    .bind(user_id)
    .bind(auth::digest(&refresh_token))
    .bind(Utc::now() + Duration::seconds(REFRESH_LIFETIME_SECONDS))
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM refresh_sessions WHERE id IN (SELECT id FROM refresh_sessions WHERE user_id=$1 ORDER BY created_at DESC,id DESC OFFSET 9)")
        .bind(user_id).execute(&mut *tx).await?;
    let token_id = Uuid::new_v4();
    let expires = Utc::now() + Duration::seconds(state.config.jwt_ttl_seconds);
    let access_token = state.jwt()?.issue(user_id, token_id, expires.timestamp())?;
    sqlx::query(
        "INSERT INTO access_tokens(id,user_id,expires_at,refresh_session_id) VALUES ($1,$2,$3,$4)",
    )
    .bind(token_id)
    .bind(user_id)
    .bind(expires)
    .bind(refresh_id)
    .execute(&mut *tx)
    .await?;
    management::audit(&mut tx, user_id, "auth.login", user_id, id.0).await?;
    tx.commit().await?;
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, refresh_cookie(&refresh_token));
    Ok((
        headers,
        Json(TokenResponse {
            user,
            access_token,
            token_type: "Bearer".into(),
            expires_in: state.config.jwt_ttl_seconds,
        }),
    ))
}

#[utoipa::path(post, path="/api/v1/auth/refresh", tag="auth",
    responses((status=200, body=TokenResponse), (status=401, body=crate::errors::ErrorResponse)))]
pub async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<TokenResponse>), AppError> {
    require_same_origin(&headers, &state.config.app_origin)?;
    let token = cookie_token(&headers).ok_or_else(AppError::unauthorized)?;
    let mut tx = state.pool()?.begin().await?;
    let row: Option<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT r.id,r.user_id FROM refresh_sessions r JOIN users u ON u.id=r.user_id WHERE r.token_hash=$1 AND r.expires_at>now() AND u.is_active FOR UPDATE OF r,u"
    ).bind(auth::digest(token)).fetch_optional(&mut *tx).await?;
    let (refresh_id, user_id) = row.ok_or_else(AppError::unauthorized)?;
    let user = sqlx::query_as::<_, User>(
        "SELECT id,username,name,email,email_verified_at,role,is_active,created_at,updated_at FROM users WHERE id=$1"
    ).bind(user_id).fetch_one(&mut *tx).await?;
    if state.config.require_email_verification && user.email_verified_at.is_none() {
        return Err(AppError::email_unverified());
    }
    let expires = Utc::now() + Duration::seconds(state.config.jwt_ttl_seconds);
    let token_id = Uuid::new_v4();
    let access_token = state.jwt()?.issue(user_id, token_id, expires.timestamp())?;
    sqlx::query("DELETE FROM access_tokens WHERE user_id=$1 AND expires_at<=now()")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO access_tokens(id,user_id,expires_at,refresh_session_id) VALUES ($1,$2,$3,$4)",
    )
    .bind(token_id)
    .bind(user_id)
    .bind(expires)
    .bind(refresh_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE refresh_sessions SET expires_at=$2 WHERE id=$1")
        .bind(refresh_id)
        .bind(Utc::now() + Duration::seconds(REFRESH_LIFETIME_SECONDS))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(SET_COOKIE, refresh_cookie(token));
    Ok((
        response_headers,
        Json(TokenResponse {
            user,
            access_token,
            token_type: "Bearer".into(),
            expires_in: state.config.jwt_ttl_seconds,
        }),
    ))
}

#[utoipa::path(get,path="/api/v1/auth/me",tag="auth",security(("bearer"=[])),responses((status=200,body=MeResponse),(status=403,body=crate::errors::ErrorResponse),(status=401,body=crate::errors::ErrorResponse)))]
pub async fn me(State(state): State<AppState>, principal: Principal) -> Result<Json<MeResponse>, AppError> {
    let access = crate::rbac::effective_access(state.pool()?, &principal, principal.user.id).await?;
    Ok(Json(MeResponse {
        user: principal.user,
        roles: access.roles,
        permissions: access.permissions,
    }))
}

#[utoipa::path(post,path="/api/v1/auth/logout",tag="auth",responses((status=204,description="Refresh session and its JWTs revoked")))]
pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(id): Extension<RequestId>,
) -> Result<(HeaderMap, StatusCode), AppError> {
    if cookie_token(&headers).is_some() {
        require_same_origin(&headers, &state.config.app_origin)?;
    }
    let mut tx = state.pool()?.begin().await?;
    if let Some(token) = cookie_token(&headers) {
        let user_id: Option<Uuid> = sqlx::query_scalar(
            "DELETE FROM refresh_sessions WHERE token_hash=$1 RETURNING user_id",
        )
        .bind(auth::digest(token))
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(user_id) = user_id {
            management::audit(&mut tx, user_id, "auth.logout", user_id, id.0).await?;
        }
    }
    if let Some(value) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        && let Some(token) = value.strip_prefix("Bearer ")
        && let Ok(claims) = state.jwt()?.verify(token)
    {
        sqlx::query("DELETE FROM access_tokens WHERE id=$1 AND user_id=$2")
            .bind(claims.jti)
            .bind(claims.sub)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(SET_COOKIE, clear_refresh_cookie());
    Ok((response_headers, StatusCode::NO_CONTENT))
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
