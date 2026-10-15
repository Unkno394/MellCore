//! Kazik protocol is the semantic layer above a replaceable packet transport.
//!
//! It defines immutable command, event and ACK envelopes.  It does not encrypt
//! packets and does not know whether HFSP frames travel through Hysteria, TCP,
//! HTTPS or LoRa.  Transport security belongs to the transport implementation.

use std::{net::IpAddr, time::Duration};

use hf_core::{AgentCommand, HfspCodecError, HfspFrame, HfspMessageKind, HostInventory};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

pub const KAZIK_PROTOCOL_VERSION: u16 = 1;
/// Application-level limits keep telemetry within one practical Hysteria UDP datagram while
/// retaining the existing HFSP/Kazik version and envelope shape.
pub const MAX_TELEMETRY_BATCH_EVENTS: usize = 20;
pub const MAX_TELEMETRY_PACKET_BYTES: usize = 16 * 1024;
pub const MAX_TELEMETRY_BATCH_WAIT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KazikEnvelope {
    pub protocol_version: u16,
    /// Globally stable id used for deduplication and the durable sender outbox.
    pub message_id: Uuid,
    /// Agent identity is authenticated by the transport credential; it is not trusted by itself.
    pub agent_id: Uuid,
    /// Per-agent credential issued at registration. It is sent only inside the protected
    /// transport and must be checked by Center together with `agent_id`.
    pub transport_credential: String,
    /// Unix milliseconds set by the sender. It is informational, not an ordering authority.
    pub sent_at_unix_ms: i64,
    pub body: KazikBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KazikBody {
    Register(Register),
    Command { command: AgentCommand },
    Telemetry { events: Vec<TrapEvent> },
    Ack(Acknowledgement),
    Heartbeat { status: AgentStatus },
    Error { code: String, message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Register {
    pub enrollment_token: String,
    pub hostname: String,
    pub agent_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AckDisposition {
    Accepted,
    Applied,
    Duplicate,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Acknowledgement {
    /// The immutable `message_id` being acknowledged, never a transport sequence number.
    pub acknowledged_message_id: Uuid,
    pub disposition: AckDisposition,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AgentStatus {
    pub hostname: String,
    pub active_trap_count: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    /// Added to the existing heartbeat so inventory uses the authenticated, durable HFSP path.
    /// Missing values keep heartbeats from older agents valid during rolling upgrades.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_inventory: Option<HostInventory>,
}

/// Normalized event emitted by any trap source. `payload` remains source-specific;
/// Kazik supplies stable routing, dedupe and session fields around it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TrapEvent {
    pub event_id: Uuid,
    pub trap_id: Uuid,
    pub session_id: Option<String>,
    pub source_sequence_no: Option<u64>,
    pub occurred_at_unix_ms: i64,
    pub event_type: String,
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub protocol: String,
    pub service_type: String,
    pub payload: Value,
    pub metadata: Value,
}

#[derive(Debug, Error)]
pub enum KazikCodecError {
    #[error("unsupported Kazik protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("Kazik body does not match HFSP frame kind")]
    KindMismatch,
    #[error(transparent)]
    Hfsp(#[from] HfspCodecError),
}

impl KazikEnvelope {
    pub fn new(
        agent_id: Uuid,
        transport_credential: impl Into<String>,
        sent_at_unix_ms: i64,
        body: KazikBody,
    ) -> Self {
        Self {
            protocol_version: KAZIK_PROTOCOL_VERSION,
            message_id: Uuid::new_v4(),
            agent_id,
            transport_credential: transport_credential.into(),
            sent_at_unix_ms,
            body,
        }
    }

    pub fn hfsp_kind(&self) -> HfspMessageKind {
        match self.body {
            KazikBody::Register(_) => HfspMessageKind::Register,
            KazikBody::Command { .. } => HfspMessageKind::Command,
            KazikBody::Telemetry { .. } => HfspMessageKind::Telemetry,
            KazikBody::Ack(_) => HfspMessageKind::Ack,
            KazikBody::Heartbeat { .. } => HfspMessageKind::Heartbeat,
            KazikBody::Error { .. } => HfspMessageKind::Error,
        }
    }

    pub fn encode_hfsp(
        &self,
        sequence: u64,
        acknowledgement: u64,
    ) -> Result<Vec<u8>, KazikCodecError> {
        if self.protocol_version != KAZIK_PROTOCOL_VERSION {
            return Err(KazikCodecError::UnsupportedVersion(self.protocol_version));
        }
        Ok(HfspFrame::from_json(self.hfsp_kind(), sequence, acknowledgement, self)?.encode()?)
    }

    pub fn decode_hfsp(packet: &[u8]) -> Result<(Self, u64, u64), KazikCodecError> {
        let frame = HfspFrame::decode(packet)?;
        let envelope: Self = frame.payload_json()?;
        if envelope.protocol_version != KAZIK_PROTOCOL_VERSION {
            return Err(KazikCodecError::UnsupportedVersion(
                envelope.protocol_version,
            ));
        }
        if envelope.hfsp_kind() != frame.kind {
            return Err(KazikCodecError::KindMismatch);
        }
        Ok((envelope, frame.sequence, frame.acknowledgement))
    }
}

/// Durable delivery contract. Implement it in `services` with SQLite on the agent;
/// never store inbound commands in this outbox. A sender first persists the complete packet,
/// retransmits the same `message_id` until an ACK arrives, then removes it atomically.
pub trait DurableOutbox {
    type Error;

    fn enqueue(&mut self, envelope: KazikEnvelope) -> Result<(), Self::Error>;
    fn pending(&self, maximum: usize) -> Result<Vec<KazikEnvelope>, Self::Error>;
    fn acknowledge(&mut self, message_id: Uuid) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn telemetry_round_trip_preserves_pritvoryashka_shape() {
        let agent_id = Uuid::new_v4();
        let event_id = Uuid::new_v4();
        let envelope = KazikEnvelope::new(
            agent_id,
            "credential",
            1_760_000_000_000,
            KazikBody::Telemetry {
                events: vec![TrapEvent {
                    event_id,
                    trap_id: Uuid::new_v4(),
                    session_id: Some("ssh-session".into()),
                    source_sequence_no: Some(4),
                    occurred_at_unix_ms: 1_760_000_000_001,
                    event_type: "command.executed".into(),
                    source_ip: Some("203.0.113.9".parse().unwrap()),
                    source_port: Some(51000),
                    destination_port: Some(2222),
                    protocol: "tcp".into(),
                    service_type: "ssh".into(),
                    payload: json!({"command":"cat","input":"cat /var/log/auth.log"}),
                    metadata: json!({"source":"pritvoryashka"}),
                }],
            },
        );
        let bytes = envelope.encode_hfsp(11, 7).unwrap();
        let (decoded, sequence, acknowledgement) = KazikEnvelope::decode_hfsp(&bytes).unwrap();
        assert_eq!(decoded.message_id, envelope.message_id);
        assert_eq!(decoded.agent_id, envelope.agent_id);
        assert_eq!((sequence, acknowledgement), (11, 7));
        let KazikBody::Telemetry { events } = decoded.body else {
            panic!("wrong body")
        };
        assert_eq!(events[0].event_id, event_id);
    }

    #[test]
    fn rejects_hfsp_kind_with_wrong_semantic_body() {
        let envelope = KazikEnvelope::new(
            Uuid::new_v4(),
            "credential",
            1,
            KazikBody::Heartbeat {
                status: AgentStatus {
                    hostname: "vps".into(),
                    active_trap_count: 1,
                    capabilities: vec![],
                    host_inventory: None,
                },
            },
        );
        let bad = HfspFrame::from_json(HfspMessageKind::Telemetry, 1, 0, &envelope)
            .unwrap()
            .encode()
            .unwrap();
        assert!(matches!(
            KazikEnvelope::decode_hfsp(&bad),
            Err(KazikCodecError::KindMismatch)
        ));
    }

    #[test]
    fn heartbeat_without_inventory_remains_compatible() {
        let status: AgentStatus = serde_json::from_value(json!({
            "hostname": "older-agent",
            "active_trap_count": 2
        }))
        .unwrap();
        assert_eq!(status.host_inventory, None);
    }
}
