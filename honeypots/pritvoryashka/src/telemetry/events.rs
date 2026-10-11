use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

pub const SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TelemetryBatch {
    pub schema_version: u16,
    pub batch_id: Uuid,
    pub agent_id: Uuid,
    pub server_id: Uuid,
    pub events: Vec<IncomingEvent>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IncomingEvent {
    pub event_id: Uuid,
    pub trap_id: Uuid,
    pub session_id: Option<String>,
    pub sequence_no: Option<u64>,
    pub event_type: String,
    pub occurred_at: DateTime<Utc>,
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub protocol: String,
    pub service_type: String,
    pub payload: Value,
    pub metadata: Value,
}
