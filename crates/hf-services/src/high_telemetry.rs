//! Durable ingress for telemetry produced inside a High Interaction VM.
//!
//! The guest is deliberately treated as untrusted. It supplies only source facts and a stable
//! retry id. The host assigns the trap/agent identities, canonical event id and ordering number,
//! persists the normalized event, and only then returns an acknowledgement.

use std::{
    fs,
    net::IpAddr,
    path::Path,
    sync::{Arc, Mutex},
};

use kazik_protocol::{KazikBody, KazikEnvelope, TrapEvent};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use uuid::Uuid;

pub const HIGH_TELEMETRY_VERSION: u8 = 1;
pub const MAX_HIGH_TELEMETRY_FRAME_BYTES: usize = 16 * 1024;
pub const DEFAULT_MAX_PENDING_HIGH_EVENTS: usize = 100_000;
const MAX_SESSION_ID_BYTES: usize = 256;
const MAX_FUTURE_SKEW_MS: i64 = 5 * 60 * 1_000;
const MAX_PAST_AGE_MS: i64 = 30 * 24 * 60 * 60 * 1_000;

const SUPPORTED_EVENT_TYPES: &[&str] = &[
    "guest.boot",
    "guest.shutdown",
    "guest.journal",
    "guest.audit",
    "process.exec",
    "process.exit",
    "file.created",
    "file.modified",
    "file.deleted",
    "file.renamed",
    "file.permissions",
    "network.connect",
    "network.connect.failed",
    "privilege.sudo",
    "privilege.su",
    "sensor.diagnostic",
    "sensor.heartbeat",
    "ssh.auth.succeeded",
    "ssh.auth.failed",
    "ssh.session.opened",
    "ssh.session.closed",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GuestHighEvent {
    pub version: u8,
    pub guest_event_id: Uuid,
    pub guest_sequence: u64,
    pub occurred_at_unix_ms: i64,
    pub event_type: String,
    pub session_id: Option<String>,
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    #[serde(default)]
    pub destination_ip: Option<IpAddr>,
    #[serde(default)]
    pub destination_port: Option<u16>,
    #[serde(default = "default_event_origin")]
    pub event_origin: String,
    #[serde(default = "default_event_confidence")]
    pub event_confidence: String,
    #[serde(default)]
    pub transport: Option<String>,
    pub payload: Value,
}

fn default_event_origin() -> String {
    "unknown".into()
}

fn default_event_confidence() -> String {
    "unknown".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuestHighAcknowledgement {
    pub version: u8,
    pub acknowledged_guest_event_id: Uuid,
    pub event_id: Uuid,
    pub host_sequence: u64,
    pub duplicate: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PersistedHighEvent {
    pub event: TrapEvent,
    pub host_sequence: u64,
    pub duplicate: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HighTelemetryBatch {
    pub message_id: Uuid,
    pub created_at_unix_ms: i64,
    pub events: Vec<TrapEvent>,
}

impl HighTelemetryBatch {
    pub fn kazik_envelope(
        &self,
        agent_id: Uuid,
        transport_credential: impl Into<String>,
    ) -> KazikEnvelope {
        KazikEnvelope {
            protocol_version: kazik_protocol::KAZIK_PROTOCOL_VERSION,
            message_id: self.message_id,
            agent_id,
            transport_credential: transport_credential.into(),
            sent_at_unix_ms: self.created_at_unix_ms,
            body: KazikBody::Telemetry {
                events: self.events.clone(),
            },
        }
    }
}

#[derive(Debug, Error)]
pub enum HighTelemetryError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("invalid High telemetry event: {0}")]
    InvalidEvent(String),
    #[error("High telemetry frame exceeds {MAX_HIGH_TELEMETRY_FRAME_BYTES} bytes")]
    FrameTooLarge,
    #[error("High telemetry JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("guest event {0} was retried with different immutable contents")]
    ConflictingDuplicate(Uuid),
    #[error("High telemetry durable queue reached its configured limit of {0} events")]
    QueueFull(usize),
    #[error("persisted High telemetry is invalid: {0}")]
    CorruptStore(String),
}

impl GuestHighEvent {
    pub fn validate(&self) -> Result<(), HighTelemetryError> {
        if self.version != HIGH_TELEMETRY_VERSION {
            return Err(HighTelemetryError::InvalidEvent(format!(
                "unsupported version {}",
                self.version
            )));
        }
        if self.guest_event_id.is_nil() {
            return Err(HighTelemetryError::InvalidEvent(
                "guest_event_id must not be nil".into(),
            ));
        }
        if self.guest_sequence == 0 {
            return Err(HighTelemetryError::InvalidEvent(
                "guest_sequence must start at one".into(),
            ));
        }
        if !SUPPORTED_EVENT_TYPES.contains(&self.event_type.as_str()) {
            return Err(HighTelemetryError::InvalidEvent(format!(
                "unsupported event_type {}",
                self.event_type
            )));
        }
        if self
            .session_id
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_SESSION_ID_BYTES)
        {
            return Err(HighTelemetryError::InvalidEvent(
                "session_id must contain 1..=256 bytes".into(),
            ));
        }
        if matches!(
            self.event_type.as_str(),
            "ssh.session.opened" | "ssh.session.closed"
        ) && self.session_id.is_none()
        {
            return Err(HighTelemetryError::InvalidEvent(
                "session events require session_id".into(),
            ));
        }
        if self.source_port == Some(0) {
            return Err(HighTelemetryError::InvalidEvent(
                "source_port must be nonzero".into(),
            ));
        }
        if self.destination_port == Some(0) {
            return Err(HighTelemetryError::InvalidEvent(
                "destination_port must be nonzero".into(),
            ));
        }
        if !matches!(
            self.event_origin.as_str(),
            "kernel_audit" | "systemd_journal" | "sensor" | "unknown"
        ) {
            return Err(HighTelemetryError::InvalidEvent(
                "unsupported event_origin".into(),
            ));
        }
        if !matches!(
            self.event_confidence.as_str(),
            "observed" | "inferred" | "unknown"
        ) {
            return Err(HighTelemetryError::InvalidEvent(
                "unsupported event_confidence".into(),
            ));
        }
        if self.transport.as_ref().is_some_and(|transport| {
            !matches!(transport.as_str(), "tcp" | "udp" | "local" | "unknown")
        }) {
            return Err(HighTelemetryError::InvalidEvent(
                "unsupported transport".into(),
            ));
        }
        if !self.payload.is_object() {
            return Err(HighTelemetryError::InvalidEvent(
                "payload must be a JSON object".into(),
            ));
        }
        Ok(())
    }
}

pub fn parse_guest_high_event(frame: &[u8]) -> Result<GuestHighEvent, HighTelemetryError> {
    if frame.len() > MAX_HIGH_TELEMETRY_FRAME_BYTES {
        return Err(HighTelemetryError::FrameTooLarge);
    }
    let event: GuestHighEvent = serde_json::from_slice(frame)
        .map_err(|error| HighTelemetryError::InvalidJson(error.to_string()))?;
    event.validate()?;
    let canonical = serde_json::to_vec(&event)
        .map_err(|error| HighTelemetryError::InvalidJson(error.to_string()))?;
    if canonical.len() > MAX_HIGH_TELEMETRY_FRAME_BYTES {
        return Err(HighTelemetryError::FrameTooLarge);
    }
    Ok(event)
}

pub struct HighTelemetryStore {
    connection: Connection,
    max_pending_events: usize,
}

pub type SharedHighTelemetryStore = Arc<Mutex<HighTelemetryStore>>;

impl HighTelemetryStore {
    pub fn open(
        path: impl AsRef<Path>,
        max_pending_events: usize,
    ) -> Result<Self, HighTelemetryError> {
        if max_pending_events == 0 {
            return Err(HighTelemetryError::InvalidEvent(
                "queue limit must be greater than zero".into(),
            ));
        }
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(path)?;
        #[cfg(unix)]
        if path != Path::new(":memory:") {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        connection.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS high_telemetry_events (
                trap_id TEXT NOT NULL,
                guest_event_id TEXT NOT NULL,
                guest_event_json BLOB NOT NULL,
                agent_id TEXT NOT NULL,
                event_id TEXT NOT NULL UNIQUE,
                host_sequence INTEGER NOT NULL,
                received_at_unix_ms INTEGER NOT NULL,
                event_json BLOB NOT NULL,
                PRIMARY KEY (trap_id, guest_event_id),
                UNIQUE (trap_id, host_sequence)
            );
            CREATE TABLE IF NOT EXISTS high_telemetry_state (
                trap_id TEXT PRIMARY KEY NOT NULL,
                next_sequence INTEGER NOT NULL,
                last_received_at_unix_ms INTEGER
            );
            CREATE INDEX IF NOT EXISTS high_telemetry_received_idx
              ON high_telemetry_events(received_at_unix_ms, event_id);
            CREATE TABLE IF NOT EXISTS high_telemetry_batches (
                message_id TEXT PRIMARY KEY NOT NULL,
                created_at_unix_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS high_telemetry_batch_events (
                message_id TEXT NOT NULL,
                event_id TEXT NOT NULL UNIQUE,
                position INTEGER NOT NULL,
                PRIMARY KEY (message_id, position),
                FOREIGN KEY (message_id) REFERENCES high_telemetry_batches(message_id)
            );
            CREATE TABLE IF NOT EXISTS high_telemetry_delivery_errors (
                event_id TEXT PRIMARY KEY NOT NULL,
                reason TEXT NOT NULL,
                created_at_unix_ms INTEGER NOT NULL
            );
            ",
        )?;
        ensure_last_received_column(&connection)?;
        Ok(Self {
            connection,
            max_pending_events,
        })
    }

    pub fn ingest(
        &mut self,
        agent_id: Uuid,
        trap_id: Uuid,
        guest: GuestHighEvent,
        received_at_unix_ms: i64,
    ) -> Result<PersistedHighEvent, HighTelemetryError> {
        if agent_id.is_nil() || trap_id.is_nil() {
            return Err(HighTelemetryError::InvalidEvent(
                "host agent_id and trap_id must not be nil".into(),
            ));
        }
        guest.validate()?;
        let guest_json = serde_json::to_vec(&guest)
            .map_err(|error| HighTelemetryError::InvalidJson(error.to_string()))?;
        if guest_json.len() > MAX_HIGH_TELEMETRY_FRAME_BYTES {
            return Err(HighTelemetryError::FrameTooLarge);
        }

        let transaction = self.connection.transaction()?;
        let existing = transaction
            .query_row(
                "SELECT guest_event_json, event_json, host_sequence
                 FROM high_telemetry_events WHERE trap_id = ?1 AND guest_event_id = ?2",
                params![trap_id.to_string(), guest.guest_event_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?;
        if let Some((existing_guest, event_json, host_sequence)) = existing {
            if existing_guest != guest_json {
                return Err(HighTelemetryError::ConflictingDuplicate(
                    guest.guest_event_id,
                ));
            }
            let event: TrapEvent = serde_json::from_slice(&event_json)
                .map_err(|error| HighTelemetryError::CorruptStore(error.to_string()))?;
            let host_sequence = u64::try_from(host_sequence)
                .map_err(|_| HighTelemetryError::CorruptStore("negative host sequence".into()))?;
            transaction.commit()?;
            return Ok(PersistedHighEvent {
                event,
                host_sequence,
                duplicate: true,
            });
        }

        let queued: i64 =
            transaction.query_row("SELECT COUNT(*) FROM high_telemetry_events", [], |row| {
                row.get(0)
            })?;
        if queued >= i64::try_from(self.max_pending_events).unwrap_or(i64::MAX) {
            return Err(HighTelemetryError::QueueFull(self.max_pending_events));
        }

        transaction.execute(
            "INSERT OR IGNORE INTO high_telemetry_state
             (trap_id, next_sequence, last_received_at_unix_ms) VALUES (?1, 1, NULL)",
            [trap_id.to_string()],
        )?;
        let host_sequence_i64: i64 = transaction.query_row(
            "SELECT next_sequence FROM high_telemetry_state WHERE trap_id = ?1",
            [trap_id.to_string()],
            |row| row.get(0),
        )?;
        let next_sequence = host_sequence_i64
            .checked_add(1)
            .ok_or_else(|| HighTelemetryError::CorruptStore("host sequence exhausted".into()))?;
        transaction.execute(
            "UPDATE high_telemetry_state
             SET next_sequence = ?1, last_received_at_unix_ms = ?2 WHERE trap_id = ?3",
            params![next_sequence, received_at_unix_ms, trap_id.to_string()],
        )?;
        let host_sequence = u64::try_from(host_sequence_i64)
            .map_err(|_| HighTelemetryError::CorruptStore("negative host sequence".into()))?;
        let (occurred_at_unix_ms, timestamp_normalized) =
            normalize_timestamp(guest.occurred_at_unix_ms, received_at_unix_ms);
        let service_type = if guest.event_type.starts_with("ssh.") {
            "ssh"
        } else {
            "guest-os"
        };
        let protocol = guest.transport.as_deref().unwrap_or_else(|| {
            if guest.event_type.starts_with("ssh.") {
                "tcp"
            } else {
                "local"
            }
        });
        let event = TrapEvent {
            event_id: Uuid::new_v4(),
            trap_id,
            session_id: guest.session_id.clone(),
            source_sequence_no: Some(host_sequence),
            occurred_at_unix_ms,
            event_type: guest.event_type.clone(),
            source_ip: guest.source_ip,
            source_port: guest.source_port,
            destination_port: guest
                .destination_port
                .or_else(|| guest.event_type.starts_with("ssh.").then_some(22)),
            protocol: protocol.into(),
            service_type: service_type.into(),
            payload: guest.payload.clone(),
            metadata: json!({
                "source": "high-ubuntu-ssh",
                "agent_id": agent_id,
                "guest_event_id": guest.guest_event_id,
                "guest_sequence": guest.guest_sequence,
                "guest_occurred_at_unix_ms": guest.occurred_at_unix_ms,
                "received_at_unix_ms": received_at_unix_ms,
                "timestamp_normalized": timestamp_normalized,
                "event_origin": guest.event_origin,
                "event_confidence": guest.event_confidence,
                "destination_ip": guest.destination_ip,
                "provenance": "untrusted_guest_report",
                "guest_fields_authenticated": false,
                "source_ordering": "guest_sequence_only",
                "cross_source_ordering": "not_guaranteed",
            }),
        };
        let event_json = serde_json::to_vec(&event)
            .map_err(|error| HighTelemetryError::InvalidJson(error.to_string()))?;
        transaction.execute(
            "INSERT INTO high_telemetry_events
             (trap_id, guest_event_id, guest_event_json, agent_id, event_id, host_sequence,
              received_at_unix_ms, event_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                trap_id.to_string(),
                guest.guest_event_id.to_string(),
                guest_json,
                agent_id.to_string(),
                event.event_id.to_string(),
                host_sequence_i64,
                received_at_unix_ms,
                event_json,
            ],
        )?;
        transaction.commit()?;
        Ok(PersistedHighEvent {
            event,
            host_sequence,
            duplicate: false,
        })
    }

    /// Events remain here until a future Kazik integration has received a center ACK.
    pub fn pending(&self, maximum: usize) -> Result<Vec<TrapEvent>, HighTelemetryError> {
        let mut statement = self.connection.prepare(
            "SELECT event_json FROM high_telemetry_events
             ORDER BY received_at_unix_ms, event_id LIMIT ?1",
        )?;
        let rows = statement.query_map([i64::try_from(maximum).unwrap_or(i64::MAX)], |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        rows.map(|row| {
            serde_json::from_slice(&row?)
                .map_err(|error| HighTelemetryError::CorruptStore(error.to_string()))
        })
        .collect()
    }

    pub fn pending_count(&self) -> Result<usize, HighTelemetryError> {
        let count: i64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM high_telemetry_events", [], |row| {
                    row.get(0)
                })?;
        usize::try_from(count)
            .map_err(|_| HighTelemetryError::CorruptStore("negative event count".into()))
    }

    pub fn last_received_at(&self, trap_id: Uuid) -> Result<Option<i64>, HighTelemetryError> {
        self.connection
            .query_row(
                "SELECT last_received_at_unix_ms FROM high_telemetry_state WHERE trap_id = ?1",
                [trap_id.to_string()],
                |row| row.get(0),
            )
            .optional()
            .map(Option::flatten)
            .map_err(HighTelemetryError::from)
    }

    /// Creates a durable, stable batch mapping in the same database transaction as selection.
    /// An existing unacknowledged batch is returned unchanged after restart or retry.
    pub fn prepare_kazik_batch(
        &mut self,
        maximum_events: usize,
        maximum_json_bytes: usize,
        created_at_unix_ms: i64,
    ) -> Result<Option<HighTelemetryBatch>, HighTelemetryError> {
        if maximum_events == 0 || maximum_json_bytes == 0 {
            return Err(HighTelemetryError::InvalidEvent(
                "Kazik batch limits must be nonzero".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        let existing = transaction
            .query_row(
                "SELECT message_id, created_at_unix_ms FROM high_telemetry_batches
                 ORDER BY created_at_unix_ms, message_id LIMIT 1",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        if let Some((message_id, created_at)) = existing {
            let batch = load_batch(&transaction, &message_id, created_at)?;
            transaction.commit()?;
            return Ok(Some(batch));
        }

        let candidates = {
            let mut statement = transaction.prepare(
                "SELECT event_id, event_json FROM high_telemetry_events
                 WHERE trap_id = (
                   SELECT trap_id FROM high_telemetry_events
                   WHERE event_id NOT IN (SELECT event_id FROM high_telemetry_batch_events)
                     AND event_id NOT IN (SELECT event_id FROM high_telemetry_delivery_errors)
                   ORDER BY received_at_unix_ms, rowid LIMIT 1
                 )
                   AND event_id NOT IN (SELECT event_id FROM high_telemetry_batch_events)
                   AND event_id NOT IN (SELECT event_id FROM high_telemetry_delivery_errors)
                 ORDER BY received_at_unix_ms, rowid LIMIT ?1",
            )?;
            statement
                .query_map([i64::try_from(maximum_events).unwrap_or(i64::MAX)], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut selected = Vec::new();
        let mut used_bytes = 2_usize;
        for (event_id, bytes) in candidates {
            let additional = bytes.len().saturating_add(1);
            if !selected.is_empty() && used_bytes.saturating_add(additional) > maximum_json_bytes {
                break;
            }
            if selected.is_empty() && used_bytes.saturating_add(additional) > maximum_json_bytes {
                let reason = format!(
                    "normalized event exceeds the {maximum_json_bytes}-byte Center batch budget"
                );
                transaction.execute(
                    "INSERT OR IGNORE INTO high_telemetry_delivery_errors
                     (event_id, reason, created_at_unix_ms) VALUES (?1, ?2, ?3)",
                    params![event_id, reason, created_at_unix_ms],
                )?;
                tracing::warn!(%event_id, maximum_json_bytes,
                    "High event retained locally and excluded from Center batches because it cannot fit in Kazik");
                continue;
            }
            let event = serde_json::from_slice::<TrapEvent>(&bytes)
                .map_err(|error| HighTelemetryError::CorruptStore(error.to_string()))?;
            selected.push((event_id, event));
            used_bytes = used_bytes.saturating_add(additional);
        }
        if selected.is_empty() {
            transaction.commit()?;
            return Ok(None);
        }
        let message_id = Uuid::new_v4();
        transaction.execute(
            "INSERT INTO high_telemetry_batches (message_id, created_at_unix_ms) VALUES (?1, ?2)",
            params![message_id.to_string(), created_at_unix_ms],
        )?;
        for (position, (event_id, _)) in selected.iter().enumerate() {
            transaction.execute(
                "INSERT INTO high_telemetry_batch_events (message_id, event_id, position)
                 VALUES (?1, ?2, ?3)",
                params![
                    message_id.to_string(),
                    event_id,
                    i64::try_from(position).unwrap_or(i64::MAX)
                ],
            )?;
        }
        transaction.commit()?;
        Ok(Some(HighTelemetryBatch {
            message_id,
            created_at_unix_ms,
            events: selected.into_iter().map(|(_, event)| event).collect(),
        }))
    }

    /// Deletes mapped events only after Center's semantic ACK confirms durable persistence.
    /// Transport delivery alone is never sufficient for this call.
    pub fn acknowledge_durable_kazik_batch(
        &mut self,
        message_id: Uuid,
    ) -> Result<(), HighTelemetryError> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "DELETE FROM high_telemetry_events WHERE event_id IN
             (SELECT event_id FROM high_telemetry_batch_events WHERE message_id = ?1)",
            [message_id.to_string()],
        )?;
        transaction.execute(
            "DELETE FROM high_telemetry_batch_events WHERE message_id = ?1",
            [message_id.to_string()],
        )?;
        transaction.execute(
            "DELETE FROM high_telemetry_batches WHERE message_id = ?1",
            [message_id.to_string()],
        )?;
        transaction.commit()?;
        Ok(())
    }
}

fn ensure_last_received_column(connection: &Connection) -> Result<(), HighTelemetryError> {
    let mut statement = connection.prepare("PRAGMA table_info(high_telemetry_state)")?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?;
    if !columns
        .iter()
        .any(|column| column == "last_received_at_unix_ms")
    {
        connection.execute(
            "ALTER TABLE high_telemetry_state ADD COLUMN last_received_at_unix_ms INTEGER",
            [],
        )?;
    }
    connection.execute(
        "UPDATE high_telemetry_state
         SET last_received_at_unix_ms = (
             SELECT MAX(received_at_unix_ms) FROM high_telemetry_events events
             WHERE events.trap_id = high_telemetry_state.trap_id
         )
         WHERE last_received_at_unix_ms IS NULL",
        [],
    )?;
    Ok(())
}

fn load_batch(
    connection: &Connection,
    message_id: &str,
    created_at_unix_ms: i64,
) -> Result<HighTelemetryBatch, HighTelemetryError> {
    let parsed_message_id = Uuid::parse_str(message_id)
        .map_err(|error| HighTelemetryError::CorruptStore(error.to_string()))?;
    let mut statement = connection.prepare(
        "SELECT events.event_json FROM high_telemetry_batch_events mapping
         JOIN high_telemetry_events events ON events.event_id = mapping.event_id
         WHERE mapping.message_id = ?1 ORDER BY mapping.position",
    )?;
    let events = statement
        .query_map([message_id], |row| row.get::<_, Vec<u8>>(0))?
        .map(|row| {
            serde_json::from_slice(&row?)
                .map_err(|error| HighTelemetryError::CorruptStore(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if events.is_empty() {
        return Err(HighTelemetryError::CorruptStore(format!(
            "Kazik batch {message_id} has no mapped events"
        )));
    }
    Ok(HighTelemetryBatch {
        message_id: parsed_message_id,
        created_at_unix_ms,
        events,
    })
}

fn normalize_timestamp(guest: i64, received: i64) -> (i64, bool) {
    let earliest = received.saturating_sub(MAX_PAST_AGE_MS);
    let latest = received.saturating_add(MAX_FUTURE_SKEW_MS);
    if (earliest..=latest).contains(&guest) {
        (guest, false)
    } else {
        (received, true)
    }
}

fn unix_time_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}

#[cfg(unix)]
pub async fn receive_high_telemetry_connection(
    stream: tokio::net::UnixStream,
    trap_id: Uuid,
    agent_id: Uuid,
    store: SharedHighTelemetryStore,
) -> Result<(), HighTelemetryError> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    loop {
        let mut line = Vec::new();
        let read = {
            let mut bounded = (&mut reader).take((MAX_HIGH_TELEMETRY_FRAME_BYTES + 2) as u64);
            bounded.read_until(b'\n', &mut line).await?
        };
        if read == 0 {
            return Ok(());
        }
        if line.last() != Some(&b'\n') || line.len() > MAX_HIGH_TELEMETRY_FRAME_BYTES + 1 {
            return Err(HighTelemetryError::FrameTooLarge);
        }
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        let guest = parse_guest_high_event(&line)?;
        let acknowledged_guest_event_id = guest.guest_event_id;
        let store_for_write = store.clone();
        let persisted = tokio::task::spawn_blocking(move || {
            let mut store = store_for_write.lock().map_err(|_| {
                HighTelemetryError::CorruptStore("telemetry store mutex poisoned".into())
            })?;
            store.ingest(agent_id, trap_id, guest, unix_time_ms())
        })
        .await
        .map_err(|error| HighTelemetryError::CorruptStore(error.to_string()))??;
        let acknowledgement = GuestHighAcknowledgement {
            version: HIGH_TELEMETRY_VERSION,
            acknowledged_guest_event_id,
            event_id: persisted.event.event_id,
            host_sequence: persisted.host_sequence,
            duplicate: persisted.duplicate,
        };
        let mut acknowledgement = serde_json::to_vec(&acknowledgement)
            .map_err(|error| HighTelemetryError::InvalidJson(error.to_string()))?;
        acknowledgement.push(b'\n');
        writer.write_all(&acknowledgement).await?;
        writer.flush().await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(event_id: Uuid) -> GuestHighEvent {
        GuestHighEvent {
            version: HIGH_TELEMETRY_VERSION,
            guest_event_id: event_id,
            guest_sequence: 7,
            occurred_at_unix_ms: 1_760_000_000_000,
            event_type: "ssh.auth.failed".into(),
            session_id: Some("sshd:42".into()),
            source_ip: Some("203.0.113.9".parse().unwrap()),
            source_port: Some(51000),
            destination_ip: None,
            destination_port: Some(22),
            event_origin: "systemd_journal".into(),
            event_confidence: "observed".into(),
            transport: Some("tcp".into()),
            payload: json!({"username":"root","method":"password"}),
        }
    }

    fn temporary_database() -> (std::path::PathBuf, std::path::PathBuf) {
        let directory = std::env::temp_dir().join(format!("hf-high-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).unwrap();
        (directory.join("events.sqlite"), directory)
    }

    #[test]
    fn validates_format_and_rejects_unknown_or_oversized_input() {
        let encoded = serde_json::to_vec(&event(Uuid::new_v4())).unwrap();
        assert_eq!(parse_guest_high_event(&encoded).unwrap().guest_sequence, 7);
        let unknown = br#"{"version":1,"unexpected":true}"#;
        assert!(matches!(
            parse_guest_high_event(unknown),
            Err(HighTelemetryError::InvalidJson(_))
        ));
        assert!(matches!(
            parse_guest_high_event(&vec![b'x'; MAX_HIGH_TELEMETRY_FRAME_BYTES + 1]),
            Err(HighTelemetryError::FrameTooLarge)
        ));
        let mut forged_host_origin = event(Uuid::new_v4());
        forged_host_origin.event_origin = "host".into();
        assert!(matches!(
            forged_host_origin.validate(),
            Err(HighTelemetryError::InvalidEvent(_))
        ));
    }

    #[test]
    fn commits_before_ack_data_and_deduplicates_retry() {
        let (path, directory) = temporary_database();
        let mut store = HighTelemetryStore::open(&path, 10).unwrap();
        let agent_id = Uuid::new_v4();
        let trap_id = Uuid::new_v4();
        let guest = event(Uuid::new_v4());
        let first = store
            .ingest(agent_id, trap_id, guest.clone(), 1_760_000_000_100)
            .unwrap();
        let retry = store
            .ingest(agent_id, trap_id, guest, 1_760_000_000_200)
            .unwrap();
        assert!(!first.duplicate);
        assert!(retry.duplicate);
        assert_eq!(first.event.event_id, retry.event.event_id);
        assert_eq!(first.host_sequence, retry.host_sequence);
        assert_eq!(store.pending_count().unwrap(), 1);
        assert_eq!(first.event.metadata["provenance"], "untrusted_guest_report");
        assert_eq!(first.event.metadata["guest_fields_authenticated"], false);
        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_conflicting_retry_and_stops_at_capacity() {
        let (path, directory) = temporary_database();
        let mut store = HighTelemetryStore::open(&path, 1).unwrap();
        let agent_id = Uuid::new_v4();
        let trap_id = Uuid::new_v4();
        let id = Uuid::new_v4();
        store
            .ingest(agent_id, trap_id, event(id), 1_760_000_000_100)
            .unwrap();
        let mut conflict = event(id);
        conflict.payload = json!({"username":"different"});
        assert!(matches!(
            store.ingest(agent_id, trap_id, conflict, 1_760_000_000_100),
            Err(HighTelemetryError::ConflictingDuplicate(_))
        ));
        assert!(matches!(
            store.ingest(agent_id, trap_id, event(Uuid::new_v4()), 1_760_000_000_100),
            Err(HighTelemetryError::QueueFull(1))
        ));
        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn recovers_events_and_sequence_after_reopen() {
        let (path, directory) = temporary_database();
        let agent_id = Uuid::new_v4();
        let trap_id = Uuid::new_v4();
        let first_id = Uuid::new_v4();
        {
            let mut store = HighTelemetryStore::open(&path, 10).unwrap();
            let first = store
                .ingest(agent_id, trap_id, event(first_id), 1_760_000_000_100)
                .unwrap();
            assert_eq!(first.host_sequence, 1);
        }
        {
            let mut recovered = HighTelemetryStore::open(&path, 10).unwrap();
            assert_eq!(recovered.pending(10).unwrap().len(), 1);
            let retry = recovered
                .ingest(agent_id, trap_id, event(first_id), 1_760_000_000_200)
                .unwrap();
            assert!(retry.duplicate);
            let next = recovered
                .ingest(agent_id, trap_id, event(Uuid::new_v4()), 1_760_000_000_300)
                .unwrap();
            assert_eq!(next.host_sequence, 2);
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn normalizes_unreasonable_guest_clock() {
        let received = 1_760_000_000_000;
        assert_eq!(
            normalize_timestamp(received - 1, received),
            (received - 1, false)
        );
        assert_eq!(normalize_timestamp(0, received), (received, true));
        assert_eq!(
            normalize_timestamp(received + MAX_FUTURE_SKEW_MS + 1, received),
            (received, true)
        );
    }

    #[test]
    fn kazik_batch_mapping_is_bounded_stable_and_requires_durable_ack() {
        let (path, directory) = temporary_database();
        let agent_id = Uuid::new_v4();
        let trap_id = Uuid::new_v4();
        {
            let mut store = HighTelemetryStore::open(&path, 10).unwrap();
            for sequence in 1..=3 {
                let mut guest = event(Uuid::new_v4());
                guest.guest_sequence = sequence;
                store
                    .ingest(
                        agent_id,
                        trap_id,
                        guest,
                        1_760_000_000_000 + sequence as i64,
                    )
                    .unwrap();
            }
            let batch = store
                .prepare_kazik_batch(2, 128 * 1024, 1_760_000_001_000)
                .unwrap()
                .unwrap();
            assert_eq!(batch.events.len(), 2);
            let envelope = batch.kazik_envelope(agent_id, "host-only-credential");
            assert_eq!(envelope.message_id, batch.message_id);
            assert!(matches!(
                envelope.body,
                KazikBody::Telemetry { ref events } if events.len() == 2
            ));
        }
        {
            let mut recovered = HighTelemetryStore::open(&path, 10).unwrap();
            let retry = recovered
                .prepare_kazik_batch(50, 512 * 1024, 1_760_000_009_000)
                .unwrap()
                .unwrap();
            assert_eq!(retry.events.len(), 2);
            assert_eq!(retry.created_at_unix_ms, 1_760_000_001_000);
            recovered
                .acknowledge_durable_kazik_batch(retry.message_id)
                .unwrap();
            assert_eq!(recovered.pending_count().unwrap(), 1);
            assert_eq!(
                recovered.last_received_at(trap_id).unwrap(),
                Some(1_760_000_000_003)
            );
            let next = recovered
                .prepare_kazik_batch(2, 128 * 1024, 1_760_000_010_000)
                .unwrap()
                .unwrap();
            assert_ne!(next.message_id, retry.message_id);
            assert_eq!(next.events.len(), 1);
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_connection_acks_only_a_persisted_event() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let (path, directory) = temporary_database();
        let store = Arc::new(Mutex::new(HighTelemetryStore::open(&path, 10).unwrap()));
        let trap_id = Uuid::new_v4();
        let agent_id = Uuid::new_v4();
        let guest = event(Uuid::new_v4());
        let (host, mut guest_side) = tokio::net::UnixStream::pair().unwrap();
        let receiver = tokio::spawn(receive_high_telemetry_connection(
            host,
            trap_id,
            agent_id,
            store.clone(),
        ));
        let mut frame = serde_json::to_vec(&guest).unwrap();
        frame.push(b'\n');
        guest_side.write_all(&frame).await.unwrap();
        let mut guest_side = BufReader::new(guest_side);
        let mut acknowledgement = String::new();
        guest_side.read_line(&mut acknowledgement).await.unwrap();
        let acknowledgement: GuestHighAcknowledgement =
            serde_json::from_str(&acknowledgement).unwrap();
        assert_eq!(
            acknowledgement.acknowledged_guest_event_id,
            guest.guest_event_id
        );
        assert_eq!(store.lock().unwrap().pending_count().unwrap(), 1);
        guest_side.get_mut().shutdown().await.unwrap();
        receiver.await.unwrap().unwrap();
        drop(guest_side);
        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }
}
