use std::{env, net::SocketAddr, str::FromStr};

use thiserror::Error;

use crate::telemetry::TelemetryLimits;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegrationMode {
    Mock,
    Real,
}

impl FromStr for IntegrationMode {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "mock" => Ok(Self::Mock),
            "real" => Ok(Self::Real),
            _ => Err(()),
        }
    }
}

/// Contains only settings used by this stage. Never add secrets to Debug output.
#[derive(Clone, Debug)]
pub struct Config {
    pub bind: SocketAddr,
    pub docs_enabled: bool,
    pub log_filter: String,
    pub http_max_body_bytes: usize,
    pub telemetry: TelemetryLimits,
    pub integration_mode: IntegrationMode,
    pub database_url: Option<Secret>,
    pub database_allow_insecure_local: bool,
    pub database_max_connections: u32,
    pub app_origin: String,
    pub frontend_url: String,
    pub frontend_reset_path: String,
    pub frontend_verify_path: String,
    pub require_email_verification: bool,
    pub jwt_secret: Option<Secret>,
    pub jwt_ttl_seconds: i64,
    pub smtp: Option<SmtpConfig>,
    pub auth_max_concurrency: usize,
    pub login_per_minute: u32,
}

#[derive(Clone, Debug)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Secret,
    pub from: String,
    pub starttls: bool,
}

#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("invalid configuration: {key}: {reason}")]
pub struct ConfigError {
    pub key: &'static str,
    pub reason: &'static str,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|key| match env::var(key) {
            Ok(value) => Ok(Some(value)),
            Err(env::VarError::NotPresent) => Ok(None),
            Err(env::VarError::NotUnicode(_)) => Err(ConfigError {
                key,
                reason: "must contain valid Unicode",
            }),
        })
    }

    /// Dependency injection avoids mutating process-wide environment in tests.
    pub fn from_lookup(
        lookup: impl Fn(&'static str) -> Result<Option<String>, ConfigError>,
    ) -> Result<Self, ConfigError> {
        let get = |key, default: &str| -> Result<String, ConfigError> {
            Ok(lookup(key)?.unwrap_or_else(|| default.to_owned()))
        };
        let parse_error = |key| ConfigError {
            key,
            reason: "invalid value",
        };
        let bind: SocketAddr = get("API_BIND", "127.0.0.1:8080")?
            .parse()
            .map_err(|_| parse_error("API_BIND"))?;
        let docs_enabled: bool = get("DOCS_ENABLED", "false")?
            .parse()
            .map_err(|_| parse_error("DOCS_ENABLED"))?;
        // Until operator authentication exists, documentation is local-only.
        if docs_enabled && !bind.ip().is_loopback() {
            return Err(ConfigError {
                key: "DOCS_ENABLED",
                reason: "requires a loopback API_BIND until documentation authentication exists",
            });
        }
        let number = |key, default, min, max| -> Result<usize, ConfigError> {
            let value: usize = get(key, default)?.parse().map_err(|_| parse_error(key))?;
            if !(min..=max).contains(&value) {
                return Err(ConfigError {
                    key,
                    reason: "outside supported range",
                });
            }
            Ok(value)
        };
        let http_max_body_bytes = number("HTTP_MAX_BODY_BYTES", "1048576", 1024, 16 * 1024 * 1024)?;
        let telemetry = TelemetryLimits {
            max_batch_events: number("TELEMETRY_MAX_BATCH_EVENTS", "100", 1, 10_000)?,
            max_payload_bytes: number(
                "TELEMETRY_MAX_PAYLOAD_BYTES",
                "65536",
                2,
                http_max_body_bytes,
            )?,
            max_metadata_bytes: number(
                "TELEMETRY_MAX_METADATA_BYTES",
                "8192",
                2,
                http_max_body_bytes,
            )?,
            max_event_age_seconds: number(
                "TELEMETRY_MAX_EVENT_AGE_SECONDS",
                "604800",
                1,
                31_536_000,
            )? as i64,
            max_future_skew_seconds: number("TELEMETRY_MAX_FUTURE_SKEW_SECONDS", "300", 0, 3600)?
                as i64,
            retention_days: number("RETENTION_DAYS", "30", 1, 3650)? as i64,
        };
        let log_filter = get("RUST_LOG", "honeyforge_backend=info")?;
        if tracing_subscriber::EnvFilter::try_new(&log_filter).is_err() {
            return Err(parse_error("RUST_LOG"));
        }
        let frontend_url = lookup("FRONTEND_URL")?
            .or(lookup("APP_ORIGIN")?)
            .unwrap_or_else(|| "https://localhost".into());
        let frontend = url::Url::parse(&frontend_url).map_err(|_| parse_error("FRONTEND_URL"))?;
        if !matches!(frontend.scheme(), "http" | "https")
            || frontend.host_str().is_none()
            || !frontend.username().is_empty()
            || frontend.password().is_some()
            || frontend.query().is_some()
            || frontend.fragment().is_some()
            || frontend.path() != "/"
        {
            return Err(ConfigError {
                key: "FRONTEND_URL",
                reason: "must be a frontend origin without credentials, subpath, query or fragment",
            });
        }
        let app_origin = frontend.origin().ascii_serialization();
        let frontend_url = app_origin.clone();
        let path = |key, default: &str| -> Result<String, ConfigError> {
            let value = get(key, default)?;
            if !value.starts_with('/')
                || value.starts_with("//")
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/_-".contains(&b))
            {
                return Err(ConfigError {
                    key,
                    reason: "must be a local frontend route beginning with /",
                });
            }
            Ok(value)
        };
        let frontend_reset_path = path("FRONTEND_RESET_PATH", "/reset-password")?;
        let frontend_verify_path = path("FRONTEND_VERIFY_PATH", "/verify-email")?;
        let require_email_verification: bool = get("REQUIRE_EMAIL_VERIFICATION", "false")?
            .parse()
            .map_err(|_| parse_error("REQUIRE_EMAIL_VERIFICATION"))?;
        let origin = url::Url::parse(&app_origin).map_err(|_| parse_error("APP_ORIGIN"))?;
        if !matches!(origin.scheme(), "http" | "https")
            || origin.host_str().is_none()
            || origin.username() != ""
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || origin.origin().ascii_serialization() != app_origin
        {
            return Err(parse_error("APP_ORIGIN"));
        }
        let local_origin = origin.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if origin.scheme() != "https" && (!bind.ip().is_loopback() || !local_origin) {
            return Err(ConfigError {
                key: "APP_ORIGIN",
                reason: "HTTP origins are only allowed on loopback",
            });
        }
        let jwt_secret = lookup("JWT_SECRET")?.map(Secret);
        if jwt_secret.as_ref().is_some_and(|s| s.expose().len() < 32) {
            return Err(ConfigError {
                key: "JWT_SECRET",
                reason: "requires at least 32 bytes of random secret material",
            });
        }
        let smtp_host = lookup("SMTP_HOST")?;
        let smtp_user = lookup("SMTP_USERNAME")?;
        let smtp_password = lookup("SMTP_PASSWORD")?;
        let smtp_from = lookup("SMTP_FROM")?;
        let smtp = match (smtp_host, smtp_user, smtp_password, smtp_from) {
            (None, None, None, None) => None,
            (Some(host), Some(username), Some(password), Some(from))
                if !host.is_empty()
                    && !username.is_empty()
                    && !password.is_empty()
                    && from.parse::<lettre::Address>().is_ok() =>
            {
                Some(SmtpConfig {
                    host,
                    username,
                    password: Secret(password),
                    from,
                    port: number("SMTP_PORT", "465", 1, 65535)? as u16,
                    starttls: match get("SMTP_TLS_MODE", "implicit")?.as_str() {
                        "implicit" => false,
                        "starttls" => true,
                        _ => return Err(parse_error("SMTP_TLS_MODE")),
                    },
                })
            }
            _ => {
                return Err(ConfigError {
                    key: "SMTP_HOST",
                    reason: "set SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD and a valid SMTP_FROM together",
                });
            }
        };
        Ok(Self {
            bind,
            docs_enabled,
            log_filter,
            http_max_body_bytes,
            telemetry,
            integration_mode: get("INTEGRATION_MODE", "mock")?
                .parse()
                .map_err(|_| parse_error("INTEGRATION_MODE"))?,
            database_url: lookup("DATABASE_URL")?
                .filter(|v| !v.is_empty())
                .map(Secret),
            database_allow_insecure_local: get("DATABASE_ALLOW_INSECURE_LOCAL", "false")?
                .parse()
                .map_err(|_| {
                parse_error("DATABASE_ALLOW_INSECURE_LOCAL")
            })?,
            database_max_connections: number("DATABASE_MAX_CONNECTIONS", "5", 1, 100)? as u32,
            app_origin,
            frontend_url,
            frontend_reset_path,
            frontend_verify_path,
            require_email_verification,
            jwt_secret,
            jwt_ttl_seconds: number("JWT_TTL_SECONDS", "900", 60, 3600)? as i64,
            smtp,
            auth_max_concurrency: number("AUTH_MAX_CONCURRENCY", "2", 1, 16)?,
            login_per_minute: number("LOGIN_PER_MINUTE", "30", 1, 1000)? as u32,
        })
    }
}
