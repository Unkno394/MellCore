//! Agent-side durable queue for outbound Kazik envelopes.
//!
//! The owner persists an envelope before the first send. An ACK deletes only its
//! matching `message_id`; a failed transport leaves the original bytes available
//! for retry. Inbound commands deliberately do not use this database.

use std::{fs, path::Path};

use kazik_protocol::{DurableOutbox, KazikEnvelope};
use rusqlite::{Connection, params};
use thiserror::Error;
use uuid::Uuid;

use crate::FailoverSender;

#[derive(Debug, Error)]
pub enum SqliteOutboxError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("Kazik envelope serialization failed: {0}")]
    Serialization(String),
    #[error("message {0} already exists with different immutable contents")]
    ConflictingMessage(Uuid),
}

#[derive(Debug, Error)]
pub enum DeliveryPumpError {
    #[error(transparent)]
    Outbox(#[from] SqliteOutboxError),
    #[error("Kazik frame encoding failed: {0}")]
    Codec(String),
    #[error("all packet transports failed: {0}")]
    Transport(String),
}

pub struct SqliteKazikOutbox {
    connection: Connection,
}

#[derive(Debug, Clone)]
pub struct QueuedEnvelope {
    pub envelope: KazikEnvelope,
    /// Stable HFSP sequence. Retries of one message reuse this exact number.
    pub sequence: u64,
}

impl SqliteKazikOutbox {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SqliteOutboxError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(path)?;
        connection.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            CREATE TABLE IF NOT EXISTS kazik_outbox (
                message_id TEXT PRIMARY KEY NOT NULL,
                envelope_json BLOB NOT NULL,
                created_at_unix_ms INTEGER NOT NULL,
                sequence_no INTEGER
            );
            CREATE TABLE IF NOT EXISTS kazik_outbox_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                next_sequence INTEGER NOT NULL
            );
            INSERT OR IGNORE INTO kazik_outbox_state (singleton, next_sequence) VALUES (1, 1);
            CREATE INDEX IF NOT EXISTS kazik_outbox_created_idx
              ON kazik_outbox(created_at_unix_ms, message_id);
            ",
        )?;
        let has_priority = {
            let mut statement = connection.prepare("PRAGMA table_info(kazik_outbox)")?;
            let columns = statement.query_map([], |row| row.get::<_, String>(1))?
                .collect::<Result<Vec<_>, _>>()?;
            columns.iter().any(|name| name == "priority")
        };
        if !has_priority {
            connection.execute("ALTER TABLE kazik_outbox ADD COLUMN priority INTEGER NOT NULL DEFAULT 0", [])?;
        }
        Ok(Self { connection })
    }

    /// Scheduling priority never changes immutable bytes or an assigned sequence.
    pub fn prioritize(&mut self, message_id: Uuid) -> Result<(), SqliteOutboxError> {
        self.connection.execute("UPDATE kazik_outbox SET priority=1 WHERE message_id=?1", [message_id.to_string()])?;
        Ok(())
    }

    pub fn contains(&self, message_id: Uuid) -> Result<bool, SqliteOutboxError> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM kazik_outbox WHERE message_id=?1)",
            [message_id.to_string()],
            |row| row.get::<_, bool>(0),
        )?)
    }

    fn encode(envelope: &KazikEnvelope) -> Result<Vec<u8>, SqliteOutboxError> {
        serde_json::to_vec(envelope)
            .map_err(|error| SqliteOutboxError::Serialization(error.to_string()))
    }

    fn decode(bytes: &[u8]) -> Result<KazikEnvelope, SqliteOutboxError> {
        serde_json::from_slice(bytes)
            .map_err(|error| SqliteOutboxError::Serialization(error.to_string()))
    }

    /// Returns persisted messages with a stable HFSP sequence assigned before any network I/O.
    pub fn ready_to_send(
        &mut self,
        maximum: usize,
    ) -> Result<Vec<QueuedEnvelope>, SqliteOutboxError> {
        let transaction = self.connection.transaction()?;
        let rows = {
            let mut statement = transaction.prepare(
                "SELECT message_id, envelope_json, sequence_no FROM kazik_outbox
                 ORDER BY priority DESC, created_at_unix_ms, rowid LIMIT ?1",
            )?;
            statement
                .query_map([i64::try_from(maximum).unwrap_or(i64::MAX)], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut next_sequence: i64 = transaction.query_row(
            "SELECT next_sequence FROM kazik_outbox_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let mut ready = Vec::with_capacity(rows.len());
        for (message_id, bytes, existing_sequence) in rows {
            let sequence = match existing_sequence {
                Some(sequence) => sequence,
                None => {
                    let allocated = next_sequence;
                    next_sequence = next_sequence.checked_add(1).ok_or_else(|| {
                        SqliteOutboxError::Serialization("HFSP sequence exhausted".into())
                    })?;
                    transaction.execute(
                        "UPDATE kazik_outbox SET sequence_no = ?1 WHERE message_id = ?2",
                        params![allocated, message_id],
                    )?;
                    allocated
                }
            };
            ready.push(QueuedEnvelope {
                envelope: Self::decode(&bytes)?,
                sequence: u64::try_from(sequence).map_err(|_| {
                    SqliteOutboxError::Serialization("invalid persisted HFSP sequence".into())
                })?,
            });
        }
        transaction.execute(
            "UPDATE kazik_outbox_state SET next_sequence = ?1 WHERE singleton = 1",
            [next_sequence],
        )?;
        transaction.commit()?;
        Ok(ready)
    }
}

impl DurableOutbox for SqliteKazikOutbox {
    type Error = SqliteOutboxError;

    fn enqueue(&mut self, envelope: KazikEnvelope) -> Result<(), Self::Error> {
        let bytes = Self::encode(&envelope)?;
        let inserted = self.connection.execute(
            "INSERT OR IGNORE INTO kazik_outbox (message_id, envelope_json, created_at_unix_ms)
             VALUES (?1, ?2, ?3)",
            params![
                envelope.message_id.to_string(),
                &bytes,
                envelope.sent_at_unix_ms
            ],
        )?;
        if inserted == 1 {
            return Ok(());
        }
        let existing: Vec<u8> = self.connection.query_row(
            "SELECT envelope_json FROM kazik_outbox WHERE message_id = ?1",
            [envelope.message_id.to_string()],
            |row| row.get(0),
        )?;
        if existing == bytes {
            Ok(())
        } else {
            Err(SqliteOutboxError::ConflictingMessage(envelope.message_id))
        }
    }

    fn pending(&self, maximum: usize) -> Result<Vec<KazikEnvelope>, Self::Error> {
        let mut statement = self.connection.prepare(
            "SELECT envelope_json FROM kazik_outbox
             ORDER BY priority DESC, created_at_unix_ms, rowid LIMIT ?1",
        )?;
        let rows = statement.query_map([i64::try_from(maximum).unwrap_or(i64::MAX)], |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        rows.map(|row| Self::decode(&row?)).collect()
    }

    fn acknowledge(&mut self, message_id: Uuid) -> Result<(), Self::Error> {
        self.connection.execute(
            "DELETE FROM kazik_outbox WHERE message_id = ?1",
            [message_id.to_string()],
        )?;
        Ok(())
    }
}

/// Attempts to send persisted envelopes once. It deliberately does *not* delete them:
/// only an incoming semantic Kazik ACK may call `acknowledge`.
pub async fn send_pending_once(
    outbox: &mut SqliteKazikOutbox,
    sender: &FailoverSender,
    maximum: usize,
) -> Result<usize, DeliveryPumpError> {
    let queued = outbox.ready_to_send(maximum)?;
    for item in &queued {
        let packet = item
            .envelope
            .encode_hfsp(item.sequence, 0)
            .map_err(|error| DeliveryPumpError::Codec(error.to_string()))?;
        sender
            .send(&packet)
            .await
            .map_err(|error| DeliveryPumpError::Transport(error.message))?;
    }
    Ok(queued.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kazik_protocol::{AgentStatus, KazikBody, TrapEvent};

    fn heartbeat() -> KazikEnvelope {
        KazikEnvelope::new(
            Uuid::new_v4(),
            "test-credential",
            100,
            KazikBody::Heartbeat {
                status: AgentStatus {
                    hostname: "test-vps".into(),
                    active_trap_count: 2,
                },
            },
        )
    }

    #[test]
    fn priority_survives_restart_without_changing_sequence() {
        let path = std::env::temp_dir().join(format!("hf-priority-{}.sqlite", Uuid::new_v4()));
        let mut outbox = SqliteKazikOutbox::open(&path).unwrap();
        let old = heartbeat(); let mut alert = heartbeat(); alert.sent_at_unix_ms = 200;
        outbox.enqueue(old.clone()).unwrap(); outbox.enqueue(alert.clone()).unwrap();
        let sequence = outbox.ready_to_send(10).unwrap()[1].sequence;
        outbox.prioritize(alert.message_id).unwrap(); drop(outbox);
        let mut restored = SqliteKazikOutbox::open(&path).unwrap();
        assert_eq!(restored.pending(1).unwrap()[0].message_id, alert.message_id);
        let ready = restored.ready_to_send(1).unwrap();
        assert_eq!(ready[0].envelope.message_id, alert.message_id);
        assert_eq!(ready[0].sequence, sequence);
        restored.acknowledge(alert.message_id).unwrap();
        assert_eq!(restored.pending(1).unwrap()[0].message_id, old.message_id);
        drop(restored); fs::remove_file(path).unwrap();
    }

    #[test]
    fn persists_until_matching_ack_and_deduplicates_same_message() {
        let path = std::env::temp_dir().join(format!("hf-kazik-{}.sqlite", Uuid::new_v4()));
        let mut outbox = SqliteKazikOutbox::open(&path).unwrap();
        let envelope = heartbeat();
        outbox.enqueue(envelope.clone()).unwrap();
        outbox.enqueue(envelope.clone()).unwrap();
        let first = outbox.ready_to_send(10).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].sequence, 1);
        assert_eq!(outbox.ready_to_send(10).unwrap()[0].sequence, 1);
        outbox.acknowledge(Uuid::new_v4()).unwrap();
        assert_eq!(outbox.pending(10).unwrap().len(), 1);
        outbox.acknowledge(envelope.message_id).unwrap();
        assert!(outbox.pending(10).unwrap().is_empty());
        drop(outbox);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn telemetry_batch_survives_restart_and_only_matching_ack_deletes_it() {
        let path = std::env::temp_dir().join(format!("hf-kazik-batch-{}.sqlite", Uuid::new_v4()));
        let events: Vec<_> = (0..3).map(|sequence| TrapEvent {
            event_id: Uuid::new_v4(),
            trap_id: Uuid::new_v4(),
            session_id: Some(format!("session-{sequence}")),
            source_sequence_no: Some(sequence),
            occurred_at_unix_ms: 100 + sequence as i64,
            event_type: "command.executed".into(),
            source_ip: None,
            source_port: None,
            destination_port: Some(2224),
            protocol: "tcp".into(),
            service_type: "ssh".into(),
            payload: serde_json::json!({"sequence":sequence}),
            metadata: serde_json::json!({}),
        }).collect();
        let envelope = KazikEnvelope::new(
            Uuid::new_v4(),
            "test-credential",
            100,
            KazikBody::Telemetry { events: events.clone() },
        );
        let mut outbox = SqliteKazikOutbox::open(&path).unwrap();
        outbox.enqueue(envelope.clone()).unwrap();
        let first = outbox.ready_to_send(1).unwrap();
        let first_packet = first[0].envelope.encode_hfsp(first[0].sequence, 0).unwrap();
        drop(outbox);

        let mut restarted = SqliteKazikOutbox::open(&path).unwrap();
        let retried = restarted.ready_to_send(1).unwrap();
        assert_eq!(retried[0].envelope.message_id, envelope.message_id);
        assert_eq!(retried[0].envelope.encode_hfsp(retried[0].sequence, 0).unwrap(), first_packet);
        restarted.acknowledge(Uuid::new_v4()).unwrap();
        assert_eq!(restarted.pending(1).unwrap().len(), 1);
        let KazikBody::Telemetry { events: restored } = &restarted.pending(1).unwrap()[0].body else {
            panic!("expected telemetry")
        };
        assert_eq!(restored, &events);
        restarted.acknowledge(envelope.message_id).unwrap();
        assert!(restarted.pending(1).unwrap().is_empty());
        drop(restarted);
        fs::remove_file(path).unwrap();
    }
}
