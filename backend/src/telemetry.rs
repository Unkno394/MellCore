use std::{collections::HashMap, net::IpAddr};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use utoipa::ToSchema;
use uuid::Uuid;

pub const SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Debug)]
pub struct TelemetryLimits {
    pub max_batch_events: usize,
    pub max_payload_bytes: usize,
    pub max_metadata_bytes: usize,
    pub max_event_age_seconds: i64,
    pub max_future_skew_seconds: i64,
    pub retention_days: i64,
}

/// Input only. Transport authentication must establish the sender independently.
/// Intentionally no Debug: payloads may contain credentials from honeypot logs.
#[derive(Clone, Deserialize, Serialize, PartialEq, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TelemetryBatch {
    pub schema_version: u16,
    pub batch_id: Uuid,
    pub agent_id: Uuid,
    pub server_id: Uuid,
    pub events: Vec<IncomingEvent>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct IncomingEvent {
    pub event_id: Uuid,
    pub trap_id: Uuid,
    pub session_id: Option<String>,
    pub sequence_no: Option<u64>,
    pub event_type: String,
    pub occurred_at: DateTime<Utc>,
    #[schema(value_type = Option<String>, example = "192.0.2.15")]
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub protocol: String,
    pub service_type: String,
    pub payload: Value,
    pub metadata: Value,
}

/// Internal canonical record, created only after sender/trap authorization.
/// On retries storage MUST reuse the first persisted record and its timestamps.
#[derive(Clone, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct AttackEvent {
    pub schema_version: u16,
    pub agent_id: Uuid,
    pub server_id: Uuid,
    #[serde(flatten)]
    pub event: IncomingEvent,
    pub received_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Error, ToSchema)]
#[error("{code}: {field}")]
pub struct ValidationError {
    pub code: ValidationCode,
    pub event_index: Option<usize>,
    pub field: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ValidationCode {
    UnsupportedSchema,
    InvalidValue,
    LimitExceeded,
    EventTooOld,
    EventInFuture,
    ConflictingEventId,
}

impl std::fmt::Display for ValidationCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl TelemetryBatch {
    /// Pure validation: does not authenticate, persist, or acknowledge anything.
    pub fn validate(
        &self,
        limits: &TelemetryLimits,
        now: DateTime<Utc>,
    ) -> Result<(), ValidationError> {
        let error = |code, field: &str| ValidationError {
            code,
            event_index: None,
            field: field.to_owned(),
        };
        if self.schema_version != SCHEMA_VERSION {
            return Err(error(ValidationCode::UnsupportedSchema, "schema_version"));
        }
        for (name, id) in [
            ("batch_id", self.batch_id),
            ("agent_id", self.agent_id),
            ("server_id", self.server_id),
        ] {
            if id.is_nil() {
                return Err(error(ValidationCode::InvalidValue, name));
            }
        }
        if self.events.is_empty() {
            return Err(error(ValidationCode::InvalidValue, "events"));
        }
        if self.events.len() > limits.max_batch_events {
            return Err(error(ValidationCode::LimitExceeded, "events"));
        }
        let mut seen = HashMap::new();
        for (index, event) in self.events.iter().enumerate() {
            event.validate(limits, now).map_err(|mut error| {
                error.event_index = Some(index);
                error
            })?;
            if let Some(previous) = seen.insert(event.event_id, event)
                && previous != event
            {
                return Err(ValidationError {
                    code: ValidationCode::ConflictingEventId,
                    event_index: Some(index),
                    field: "event_id".into(),
                });
            }
        }
        Ok(())
    }
}

impl IncomingEvent {
    fn validate(
        &self,
        limits: &TelemetryLimits,
        now: DateTime<Utc>,
    ) -> Result<(), ValidationError> {
        let error = |code, field: &str| ValidationError {
            code,
            event_index: None,
            field: field.to_owned(),
        };
        for (name, id) in [("event_id", self.event_id), ("trap_id", self.trap_id)] {
            if id.is_nil() {
                return Err(error(ValidationCode::InvalidValue, name));
            }
        }
        if self.occurred_at < now - Duration::seconds(limits.max_event_age_seconds) {
            return Err(error(ValidationCode::EventTooOld, "occurred_at"));
        }
        if self.occurred_at > now + Duration::seconds(limits.max_future_skew_seconds) {
            return Err(error(ValidationCode::EventInFuture, "occurred_at"));
        }
        for (name, value) in [
            ("event_type", &self.event_type),
            ("protocol", &self.protocol),
            ("service_type", &self.service_type),
        ] {
            if !valid_label(value) {
                return Err(error(ValidationCode::InvalidValue, name));
            }
        }
        if let Some(session) = &self.session_id
            && (session.is_empty() || session.len() > 256 || session.chars().any(char::is_control))
        {
            return Err(error(ValidationCode::InvalidValue, "session_id"));
        }
        for (name, value, max_bytes) in [
            ("payload", &self.payload, limits.max_payload_bytes),
            ("metadata", &self.metadata, limits.max_metadata_bytes),
        ] {
            if !value.is_object() {
                return Err(error(ValidationCode::InvalidValue, name));
            }
            // Value is JSON-only; serialization cannot fail for these values.
            let size = serde_json::to_vec(value)
                .map_err(|_| error(ValidationCode::InvalidValue, name))?
                .len();
            if size > max_bytes {
                return Err(error(ValidationCode::LimitExceeded, name));
            }
        }
        Ok(())
    }
}

fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(&c))
}
