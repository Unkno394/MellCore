use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use std::{
    io::{self, Write},
    net::{IpAddr, SocketAddr},
};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize)]
/// Trap-originated payload. Server identity must come from the receiving
/// agent/backend's authenticated context, never from this payload.
pub struct ConnectionEvent {
    pub schema_version: u8,
    /// Generated once per event. Preserve this ID when queuing or retrying.
    pub event_id: Uuid,
    pub event_type: &'static str,
    pub timestamp: String,
    pub trap_id: Uuid,
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub trap_port: u16,
}

impl ConnectionEvent {
    pub fn new(trap_id: Uuid, client: SocketAddr, local: SocketAddr) -> Self {
        Self {
            schema_version: 1,
            event_id: Uuid::new_v4(),
            event_type: "connection",
            timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            trap_id,
            client_ip: client.ip(),
            client_port: client.port(),
            trap_port: local.port(),
        }
    }

    pub fn write_json_line(&self, mut writer: impl Write) -> io::Result<()> {
        serde_json::to_writer(&mut writer, self).map_err(io::Error::other)?;
        writer.write_all(b"\n")?;
        writer.flush()
    }
}

/// Synchronous sink: an agent can implement this by enqueueing the event.
/// Implementations must be thread-safe and should return promptly.
/// Persist the original event (including event_id) before transport retries;
/// do not call ConnectionEvent::new to reconstruct a queued event.
pub trait EventSink: Send + Sync + 'static {
    fn emit(&self, event: &ConnectionEvent) -> io::Result<()>;
}

#[derive(Default)]
pub struct StdoutSink;

impl EventSink for StdoutSink {
    fn emit(&self, event: &ConnectionEvent) -> io::Result<()> {
        // Hold the lock for the whole line to prevent interleaved JSON events.
        event.write_json_line(io::stdout().lock())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_one_complete_json_line_with_connection_metadata() {
        let id = Uuid::from_u128(1);
        let event = ConnectionEvent::new(
            id,
            "[::1]:45123".parse().unwrap(),
            "[::1]:2222".parse().unwrap(),
        );
        let mut bytes = Vec::new();
        event.write_json_line(&mut bytes).unwrap();
        assert_eq!(bytes.iter().filter(|&&byte| byte == b'\n').count(), 1);
        assert_eq!(bytes.last(), Some(&b'\n'));
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["schema_version"], 1);
        let event_id = Uuid::parse_str(json["event_id"].as_str().unwrap()).unwrap();
        assert_eq!(event_id, event.event_id);
        assert_eq!(event_id.get_version_num(), 4);
        assert!(!event_id.is_nil());
        assert!(json.get("server_id").is_none());
        assert_eq!(json["event_type"], "connection");
        assert_eq!(json["trap_id"], id.to_string());
        assert_eq!(json["client_ip"], "::1");
        assert_eq!(json["client_port"], 45123);
        assert_eq!(json["trap_port"], 2222);
        let timestamp =
            chrono::DateTime::parse_from_rfc3339(json["timestamp"].as_str().unwrap()).unwrap();
        assert_eq!(timestamp.offset().local_minus_utc(), 0);
        assert!(
            (Utc::now() - timestamp.with_timezone(&Utc))
                .num_seconds()
                .abs()
                < 5
        );
    }

    #[test]
    fn new_connections_get_distinct_ids_even_with_identical_endpoints() {
        let trap_id = Uuid::from_u128(1);
        let client = "127.0.0.1:45123".parse().unwrap();
        let local = "127.0.0.1:2222".parse().unwrap();
        let first = ConnectionEvent::new(trap_id, client, local);
        let second = ConnectionEvent::new(trap_id, client, local);
        assert_ne!(first.event_id, second.event_id);
        assert_eq!(first.trap_id, second.trap_id);
    }

    #[test]
    fn repeated_serialization_and_cloning_preserve_event_identity() {
        let event = ConnectionEvent::new(
            Uuid::from_u128(1),
            "127.0.0.1:45123".parse().unwrap(),
            "127.0.0.1:2222".parse().unwrap(),
        );
        let mut first = Vec::new();
        let mut retry = Vec::new();
        let mut queued_copy = Vec::new();
        event.write_json_line(&mut first).unwrap();
        event.write_json_line(&mut retry).unwrap();
        event.clone().write_json_line(&mut queued_copy).unwrap();
        assert_eq!(first, retry);
        assert_eq!(first, queued_copy);
    }
}
