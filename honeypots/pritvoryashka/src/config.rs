use std::{net::SocketAddr, path::PathBuf, time::Duration};

use serde::Deserialize;
use thiserror::Error;
use uuid::Uuid;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub bind: SocketAddr,
    pub health_bind: SocketAddr,
    pub trap_id: Uuid,
    pub server_id: Uuid,
    pub agent_id: Uuid,
    #[serde(default = "default_hostname")]
    pub hostname: String,
    pub host_key: PathBuf,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_idle_seconds")]
    pub idle_timeout_seconds: u64,
    #[serde(default = "default_input_bytes")]
    pub max_input_bytes: usize,
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    pub policy: AuthPolicy,
    pub username: Option<String>,
    pub password_env: Option<String>,
    pub capture: CredentialCapture,
    pub max_attempts: usize,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthPolicy {
    AcceptAll,
    Configured,
    RejectAll,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialCapture {
    None,
    Username,
    Password,
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    pub endpoint: Option<String>,
    pub token_env: Option<String>,
    pub jsonl_path: Option<PathBuf>,
    pub queue_capacity: usize,
    pub batch_size: usize,
    pub flush_interval_ms: u64,
    pub max_event_bytes: usize,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            policy: AuthPolicy::AcceptAll,
            username: None,
            password_env: None,
            capture: CredentialCapture::Username,
            max_attempts: 6,
        }
    }
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            endpoint: None,
            token_env: None,
            jsonl_path: Some(PathBuf::from("pritvoryashka-events.jsonl")),
            queue_capacity: 1024,
            batch_size: 50,
            flush_interval_ms: 500,
            max_event_bytes: 65_536,
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot read configuration: {0}")]
    Read(#[from] std::io::Error),
    #[error("invalid configuration JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid configuration: {0}")]
    Invalid(&'static str),
}

impl Config {
    pub async fn load(path: impl AsRef<std::path::Path>) -> Result<Self, ConfigError> {
        let bytes = tokio::fs::read(path).await?;
        let config: Self = serde_json::from_slice(&bytes)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.trap_id.is_nil() || self.server_id.is_nil() || self.agent_id.is_nil() {
            return Err(ConfigError::Invalid("identity UUIDs must not be nil"));
        }
        if self.hostname.is_empty()
            || self.hostname.len() > 64
            || !self
                .hostname
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
        {
            return Err(ConfigError::Invalid("hostname is invalid"));
        }
        if !(1..=10_000).contains(&self.max_connections)
            || !(1..=20).contains(&self.auth.max_attempts)
            || !(30..=86_400).contains(&self.idle_timeout_seconds)
            || !(256..=65_536).contains(&self.max_input_bytes)
            || !(1..=100_000).contains(&self.telemetry.queue_capacity)
            || !(1..=1000).contains(&self.telemetry.batch_size)
            || !(100..=60_000).contains(&self.telemetry.flush_interval_ms)
            || !(1024..=1_048_576).contains(&self.telemetry.max_event_bytes)
        {
            return Err(ConfigError::Invalid(
                "one or more limits are outside supported ranges",
            ));
        }
        if self.auth.policy == AuthPolicy::Configured
            && (self.auth.username.as_deref().is_none_or(str::is_empty)
                || self.auth.password_env.as_deref().is_none_or(str::is_empty))
        {
            return Err(ConfigError::Invalid(
                "configured authentication requires username and password_env",
            ));
        }
        if self.telemetry.endpoint.is_some()
            && self
                .telemetry
                .token_env
                .as_deref()
                .is_none_or(str::is_empty)
        {
            return Err(ConfigError::Invalid(
                "telemetry endpoint requires token_env",
            ));
        }
        if self.telemetry.endpoint.is_none() && self.telemetry.jsonl_path.is_none() {
            return Err(ConfigError::Invalid(
                "at least one telemetry sink must be configured",
            ));
        }
        if let Some(endpoint) = &self.telemetry.endpoint {
            let url = reqwest::Url::parse(endpoint)
                .map_err(|_| ConfigError::Invalid("telemetry endpoint is invalid"))?;
            let loopback = url.host_str().is_some_and(|host| {
                host == "localhost"
                    || host
                        .trim_matches(['[', ']'])
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            });
            if url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || url.path() != "/internal/v1/telemetry/batches"
                || (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
            {
                return Err(ConfigError::Invalid("telemetry endpoint is unsafe"));
            }
        }
        Ok(())
    }

    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_seconds)
    }
}

fn default_hostname() -> String {
    "srv-app-01".into()
}
fn default_max_connections() -> usize {
    128
}
fn default_idle_seconds() -> u64 {
    600
}
fn default_input_bytes() -> usize {
    8192
}
