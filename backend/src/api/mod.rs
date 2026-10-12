pub mod auth;
pub mod center_registry;
pub mod profiles;
pub mod server_bootstrap;
pub mod servers;
pub mod telemetry;
pub mod trap_actions;
pub mod traps;
pub mod users;

use std::{sync::Arc, time::Instant};

use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, MatchedPath, Request, State},
    http::{HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Serialize;
use tower_http::limit::RequestBodyLimitLayer;
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;
use uuid::Uuid;

use crate::{
    config::Config,
    errors::{self, AppError, ErrorResponse, RequestId},
    models::{ActualState, CommandType, DesiredState, JobPhase, JobStatus, Role, TrapLevel},
    telemetry::{AttackEvent, IncomingEvent, TelemetryBatch, ValidationError},
};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub database: Option<sqlx::PgPool>,
    pub authentication: Option<Arc<crate::auth::AuthRuntime>>,
    pub jwt: Option<Arc<crate::auth::Jwt>>,
    pub password_resets: Option<crate::password_reset::PasswordResets>,
    pub email_verifications: Option<crate::email_verification::EmailVerifications>,
}

impl AppState {
    pub async fn new(config: Config, database: sqlx::PgPool) -> Result<Self, AppError> {
        let jwt = crate::auth::Jwt::new(
            config
                .jwt_secret
                .as_ref()
                .ok_or_else(|| {
                    AppError::invalid("JWT_SECRET is required to serve the management API")
                })?
                .expose(),
        )?;
        let password_resets = config
            .smtp
            .as_ref()
            .map(|smtp| {
                let delivery = crate::mail::SmtpDelivery::new(
                    smtp,
                    &config.frontend_url,
                    &config.frontend_reset_path,
                    crate::mail::MailPurpose::PasswordReset,
                )?;
                Ok::<_, AppError>(crate::password_reset::PasswordResets::start(
                    database.clone(),
                    Arc::new(delivery),
                ))
            })
            .transpose()?;
        let email_verifications = config
            .smtp
            .as_ref()
            .map(|smtp| {
                let delivery = crate::mail::SmtpDelivery::new(
                    smtp,
                    &config.frontend_url,
                    &config.frontend_verify_path,
                    crate::mail::MailPurpose::EmailVerification,
                )?;
                Ok::<_, AppError>(crate::email_verification::EmailVerifications::start(
                    database.clone(),
                    Arc::new(delivery),
                ))
            })
            .transpose()?;
        let authentication =
            crate::auth::AuthRuntime::new(config.auth_max_concurrency, config.login_per_minute)
                .await?;
        Ok(Self {
            config: Arc::new(config),
            database: Some(database),
            authentication: Some(Arc::new(authentication)),
            jwt: Some(Arc::new(jwt)),
            password_resets,
            email_verifications,
        })
    }
    pub fn jwt(&self) -> Result<&crate::auth::Jwt, AppError> {
        self.jwt.as_deref().ok_or_else(AppError::unavailable)
    }
    pub fn pool(&self) -> Result<&sqlx::PgPool, AppError> {
        self.database.as_ref().ok_or_else(AppError::unavailable)
    }
    pub fn auth(&self) -> Result<&crate::auth::AuthRuntime, AppError> {
        self.authentication
            .as_deref()
            .ok_or_else(AppError::unavailable)
    }
}

#[derive(Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "HoneyForge Backend",
        version = "0.1.0",
        description = "Management API and internal telemetry ingestion. Public registration always grants user role. Email login uses Bearer JWT. Profiles are shared templates; only administrators modify them. Servers and traps are owner-scoped. The server bootstrap endpoint installs an agent through Center over SSH; ordinary server registration and desired trap state do not deploy anything. Port reservations are exclusive per registered server/protocol/port; dispatcher backends use distinct TCP ports. Pritvoryashka telemetry uses an independent opaque bearer token, validates trap/server ownership and is stored idempotently in PostgreSQL."
    ),
    paths(live, ready, auth::register, auth::verify_email, auth::resend_verification, auth::forgot_password, auth::reset_password, auth::change_password, auth::change_email, auth::login, auth::refresh, auth::me, auth::logout, users::create, users::list, users::get, users::update, users::delete, profiles::create, profiles::list, profiles::get, profiles::update, profiles::delete, servers::create, servers::list, servers::get, servers::update, servers::delete, servers::ports, server_bootstrap::start, server_bootstrap::status, traps::create, traps::list, traps::get, traps::update, traps::delete, traps::runtime_config, trap_actions::start, trap_actions::status, telemetry::ingest, telemetry::ingest_from_center, telemetry::list, telemetry::list_attack_matches, telemetry::list_graph_proposals, telemetry::review_graph_proposal),
    modifiers(&SecuritySchemes),
    components(schemas(
        trap_actions::TrapActionRequest,
        trap_actions::TrapActionProgress,
        HealthResponse,
        ErrorResponse,
        auth::ChangePassword,
        auth::ChangeEmail,
        auth::EmailChangeAccepted,
        TelemetryBatch,
        telemetry::CenterEventInput,
        telemetry::AttackGraphMatch,
        telemetry::AttackGraphProposal,
        telemetry::ReviewGraphProposal,
        telemetry::ReviewGraphResult,
        IncomingEvent,
        AttackEvent,
        ValidationError,
        Role,
        TrapLevel,
        DesiredState,
        ActualState,
        JobStatus,
        JobPhase,
        CommandType,
        crate::kozyavka::Settings
    ))
)]
pub struct ApiDoc;

struct SecuritySchemes;
impl utoipa::Modify for SecuritySchemes {
    fn modify(&self, doc: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = doc.components.as_mut() {
            components.add_security_scheme(
                "bearer",
                utoipa::openapi::security::SecurityScheme::Http(
                    utoipa::openapi::security::HttpBuilder::new()
                        .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
            components.add_security_scheme(
                "telemetry_bearer",
                utoipa::openapi::security::SecurityScheme::Http(
                    utoipa::openapi::security::HttpBuilder::new()
                        .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                        .bearer_format("opaque agent token")
                        .build(),
                ),
            );
        }
    }
}

pub fn router(config: &Config) -> Router {
    router_with_state(AppState {
        config: Arc::new(config.clone()),
        database: None,
        authentication: None,
        jwt: None,
        password_resets: None,
        email_verifications: None,
    })
}

pub fn router_with_state(state: AppState) -> Router {
    let config = state.config.clone();
    let mut app = Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/internal/v1/telemetry/batches", post(telemetry::ingest))
        .route(
            "/internal/v1/center/events",
            post(telemetry::ingest_from_center),
        )
        .route(
            "/internal/v1/center/traps",
            post(center_registry::register_trap),
        )
        .route(
            "/internal/v1/center/traps/removed",
            post(center_registry::mark_removed),
        )
        .route("/api/v1/auth/register", post(auth::register))
        .route("/api/v1/auth/verify-email", post(auth::verify_email))
        .route(
            "/api/v1/auth/resend-verification",
            post(auth::resend_verification),
        )
        .route("/api/v1/auth/forgot-password", post(auth::forgot_password))
        .route("/api/v1/auth/reset-password", post(auth::reset_password))
        .route("/api/v1/auth/login", post(auth::login))
        .route("/api/v1/auth/change-password", post(auth::change_password))
        .route("/api/v1/auth/change-email", post(auth::change_email))
        .route("/api/v1/auth/refresh", post(auth::refresh))
        .route("/api/v1/auth/me", get(auth::me))
        .route("/api/v1/auth/logout", post(auth::logout))
        .route("/api/v1/servers", get(servers::list).post(servers::create))
        .route("/api/v1/servers/bootstrap", post(server_bootstrap::start))
        .route(
            "/api/v1/servers/{server_id}/bootstrap",
            get(server_bootstrap::status),
        )
        .route(
            "/api/v1/servers/{server_id}",
            get(servers::get)
                .put(servers::update)
                .delete(servers::delete),
        )
        .route("/api/v1/servers/{server_id}/ports", get(servers::ports))
        .route("/api/v1/traps", get(traps::list).post(traps::create))
        .route(
            "/api/v1/traps/{trap_id}/runtime-config",
            get(traps::runtime_config),
        )
        .route("/api/v1/traps/{trap_id}/events", get(telemetry::list))
        .route("/api/v1/traps/{trap_id}/actions", post(trap_actions::start))
        .route(
            "/api/v1/traps/{trap_id}/actions/{action_id}",
            get(trap_actions::status),
        )
        .route(
            "/api/v1/traps/{trap_id}/attack-matches",
            get(telemetry::list_attack_matches),
        )
        .route(
            "/api/v1/knowledge/proposals",
            get(telemetry::list_graph_proposals),
        )
        .route(
            "/api/v1/knowledge/proposals/{proposal_id}/review",
            post(telemetry::review_graph_proposal),
        )
        .route(
            "/api/v1/traps/{trap_id}",
            get(traps::get).put(traps::update).delete(traps::delete),
        )
        .route("/api/v1/users", get(users::list).post(users::create))
        .route(
            "/api/v1/users/{id}",
            get(users::get).put(users::update).delete(users::delete),
        )
        .route(
            "/api/v1/profiles",
            get(profiles::list).post(profiles::create),
        )
        .route(
            "/api/v1/profiles/{id}",
            get(profiles::get)
                .put(profiles::update)
                .delete(profiles::delete),
        );
    if config.docs_enabled {
        app = app.merge(SwaggerUi::new("/docs").url("/openapi.json", ApiDoc::openapi()));
    }
    let cors = tower_http::cors::CorsLayer::new()
        .allow_origin([
            HeaderValue::from_str(&config.app_origin).expect("validated frontend origin")
        ])
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
        ])
        .expose_headers([
            axum::http::header::HeaderName::from_static("x-request-id"),
            axum::http::header::RETRY_AFTER,
        ])
        .max_age(std::time::Duration::from_secs(600));
    app.fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(DefaultBodyLimit::max(config.http_max_body_bytes))
        .layer(RequestBodyLimitLayer::new(config.http_max_body_bytes))
        .layer(middleware::from_fn(request_context))
        .layer(cors)
        .with_state(state)
}

#[utoipa::path(get, path = "/health/live", tag = "health", responses((status = 200, description = "HTTP process is alive; no dependency readiness implied", body = HealthResponse)))]
async fn live() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "alive".into(),
    })
}

#[utoipa::path(get, path = "/health/ready", tag = "health", responses((status=200, description="Management database and telemetry storage schema are ready", body=HealthResponse), (status = 503, description = "Management database unavailable", body = ErrorResponse)))]
async fn ready(State(state): State<AppState>, Extension(id): Extension<RequestId>) -> Response {
    if let Some(pool) = state.database {
        return match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            sqlx::query("SELECT 1 FROM trap_profiles LIMIT 0").execute(&pool),
        )
        .await
        {
            Ok(Ok(_)) => Json(HealthResponse {
                status: "management_ready".into(),
            })
            .into_response(),
            _ => errors::response(
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                "Management database is unavailable",
                id,
            ),
        };
    }
    errors::response(
        StatusCode::SERVICE_UNAVAILABLE,
        "storage_not_initialized",
        "Durable storage is not initialized",
        id,
    )
}

async fn not_found(Extension(id): Extension<RequestId>) -> Response {
    errors::response(StatusCode::NOT_FOUND, "not_found", "Route not found", id)
}

async fn method_not_allowed(Extension(id): Extension<RequestId>) -> Response {
    errors::response(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "Method not allowed",
        id,
    )
}

async fn request_context(mut request: Request, next: Next) -> Response {
    // Generate our own correlation ID; do not log untrusted headers, raw paths,
    // query parameters or request bodies, which can contain credentials.
    let id = RequestId(Uuid::new_v4());
    request.extensions_mut().insert(id);
    let method = request.method().clone();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|path| path.as_str().to_owned())
        .unwrap_or_else(|| "<unmatched>".into());
    let started = Instant::now();
    let mut response = next.run(request).await;
    if let Some(error) = response.extensions_mut().remove::<AppError>() {
        response = errors::response(error.status, error.code, error.message, id);
    } else if matches!(
        response.status(),
        StatusCode::BAD_REQUEST
            | StatusCode::UNPROCESSABLE_ENTITY
            | StatusCode::UNSUPPORTED_MEDIA_TYPE
    ) {
        // Framework rejections may echo credentials or invalid input values.
        response = errors::response(
            response.status(),
            "invalid_request",
            "Invalid request body, path, query or content type",
            id,
        );
    }
    if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
        response = errors::response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "Request body exceeds the configured limit",
            id,
        );
    }
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&id.0.to_string()).expect("UUID is a valid header value"),
    );
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    if response.status() == StatusCode::TOO_MANY_REQUESTS {
        response
            .headers_mut()
            .insert("retry-after", HeaderValue::from_static("60"));
    }
    tracing::info!(request_id = %id.0, %method, %route, status = response.status().as_u16(), elapsed_ms = started.elapsed().as_millis(), "request completed");
    response.into_response()
}
