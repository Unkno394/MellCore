use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Clone, Copy)]
pub struct RequestId(pub Uuid);

#[derive(Clone, Debug)]
pub struct AppError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: &'static str,
}

impl AppError {
    pub fn invalid(message: &'static str) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code: "validation_error",
            message,
        }
    }
    pub fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: "Invalid credentials or access token",
        }
    }
    pub fn forbidden() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "forbidden",
            message: "Access denied",
        }
    }
    pub fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: "Resource not found",
        }
    }
    pub fn conflict(message: &'static str) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "conflict",
            message,
        }
    }
    pub fn email_unverified() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "email_not_verified",
            message: "Verify your email address before signing in",
        }
    }
    pub fn mail_unavailable() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "mail_unavailable",
            message: "Email delivery is not configured or unavailable",
        }
    }
    pub fn unavailable() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "database_unavailable",
            message: "Database is unavailable",
        }
    }
    pub fn center_unavailable() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "center_unavailable",
            message: "Center is unavailable or rejected the command",
        }
    }
    pub fn busy() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "rate_limited",
            message: "Too many authentication requests; retry later",
        }
    }
    pub fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: "Internal error",
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let mut response = self.status.into_response();
        response.extensions_mut().insert(self);
        response
    }
}

impl From<sqlx::Error> for AppError {
    fn from(error: sqlx::Error) -> Self {
        match error {
            sqlx::Error::RowNotFound => Self::not_found(),
            sqlx::Error::Database(ref db) if db.is_unique_violation() => match db.constraint() {
                Some("server_ports_external_listener_unique") => {
                    Self::conflict("Public port is already reserved on this server")
                }
                Some("server_ports_dispatcher_target_unique") => {
                    Self::conflict("Dispatcher backend port is already reserved")
                }
                Some("server_ports_dispatcher_member_unique") => {
                    Self::conflict("Trap already belongs to this dispatcher port")
                }
                _ => Self::conflict("Resource already exists"),
            },
            // PostgreSQL reports explicit ON DELETE RESTRICT as 23001;
            // SQLx's helper only recognizes the 23503 foreign-key variant.
            sqlx::Error::Database(ref db)
                if db.is_foreign_key_violation() || db.code().as_deref() == Some("23001") =>
            {
                Self::conflict("Resource is still referenced")
            }
            sqlx::Error::Database(ref db) if db.is_check_violation() => {
                Self::invalid("Data violates a constraint")
            }
            sqlx::Error::PoolTimedOut
            | sqlx::Error::PoolClosed
            | sqlx::Error::Io(_)
            | sqlx::Error::Tls(_) => Self::unavailable(),
            sqlx::Error::Database(ref db) => {
                // PostgreSQL's message and detail can include bound data. Log
                // only structured diagnostics that identify the failing class
                // or constraint without exposing query parameters.
                tracing::error!(
                    sqlstate = db.code().as_deref().unwrap_or("unknown"),
                    constraint = ?db.constraint(),
                    table = ?db.table(),
                    "database operation failed"
                );
                Self::internal()
            }
            _ => {
                // Do not log SQLx error text: it can contain bound values/DSNs.
                tracing::error!("database operation failed");
                Self::internal()
            }
        }
    }
}

#[derive(Serialize, ToSchema)]
pub struct ErrorResponse {
    pub error: ErrorBody,
}

#[derive(Serialize, ToSchema)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
    pub request_id: Uuid,
}

pub fn response(status: StatusCode, code: &str, message: &str, request_id: RequestId) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: ErrorBody {
                code: code.to_owned(),
                message: message.to_owned(),
                request_id: request_id.0,
            },
        }),
    )
        .into_response()
}
