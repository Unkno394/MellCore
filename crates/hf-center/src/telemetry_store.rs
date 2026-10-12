use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use anyhow::Context;
use kazik_protocol::TrapEvent;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct StoredTelemetryEvent {
    pub agent_id: Uuid,
    pub received_at_unix_ms: i64,
    pub event: TrapEvent,
}

/// Append-only durable sink. Event IDs are deduplicated across retries and Center restarts.
pub struct TelemetryStore {
    path: PathBuf,
    file: File,
    seen: HashSet<(Uuid, Uuid)>,
    rejected_seen: HashSet<(Uuid, Uuid)>,
}

impl TelemetryStore {
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            let create_parent = !parent.exists();
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
            #[cfg(unix)]
            if create_parent {
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }
        }
        let mut seen = HashSet::new();
        if let Ok(file) = File::open(&path) {
            for line in BufReader::new(file).lines() {
                let Ok(line) = line else { continue };
                if let Ok(record) = serde_json::from_str::<StoredTelemetryEvent>(&line) {
                    seen.insert((record.agent_id, record.event.event_id));
                }
            }
        }
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options
            .open(&path)
            .with_context(|| format!("open telemetry file {}", path.display()))?;
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let mut rejected_seen = HashSet::new();
        if let Ok(file) = File::open(path.with_extension("rejected.jsonl")) {
            for line in BufReader::new(file).lines().flatten() {
                if let Ok(record) = serde_json::from_str::<StoredTelemetryEvent>(&line) {
                    rejected_seen.insert((record.agent_id, record.event.event_id));
                }
            }
        }
        Ok(Self { path, file, seen, rejected_seen })
    }

    /// Durable quarantine for events whose trap is absent from Center's registry.
    /// The exact event is kept for operator reconciliation and manual replay.
    pub fn reject(&mut self, agent_id: Uuid, events: &[TrapEvent]) -> anyhow::Result<usize> {
        let path = self.path.with_extension("rejected.jsonl");
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&path)?;
        let received_at_unix_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;
        let mut count = 0;
        let mut pending = HashSet::new();
        for event in events {
            if self.rejected_seen.contains(&(agent_id, event.event_id))
                || !pending.insert((agent_id, event.event_id)) { continue; }
            serde_json::to_writer(&mut file, &StoredTelemetryEvent {
                agent_id, received_at_unix_ms, event: event.clone(),
            })?;
            file.write_all(b"\n")?;
            count += 1;
        }
        file.flush()?;
        file.sync_data()?;
        self.rejected_seen.extend(pending);
        Ok(count)
    }

    /// Returns the number of newly stored events. The caller must ACK only after this succeeds.
    pub fn persist(&mut self, agent_id: Uuid, events: &[TrapEvent]) -> anyhow::Result<usize> {
        let received_at_unix_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;
        let mut pending = Vec::new();
        for event in events {
            if self.seen.contains(&(agent_id, event.event_id))
                || pending.iter().any(|record: &StoredTelemetryEvent| {
                    record.agent_id == agent_id && record.event.event_id == event.event_id
                })
            {
                continue;
            }
            pending.push(StoredTelemetryEvent {
                agent_id,
                received_at_unix_ms,
                event: event.clone(),
            });
        }
        for record in &pending {
            serde_json::to_writer(&mut self.file, record)?;
            self.file.write_all(b"\n")?;
        }
        self.file.flush()?;
        if !pending.is_empty() {
            self.file.sync_data()?;
        }
        for record in &pending {
            self.seen.insert((record.agent_id, record.event.event_id));
        }
        if !pending.is_empty() {
            tracing::debug!(path = %self.path.display(), count = pending.len(), "telemetry batch appended");
        }
        Ok(pending.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn event(id: Uuid) -> TrapEvent {
        TrapEvent {
            event_id: id,
            trap_id: Uuid::new_v4(),
            session_id: None,
            source_sequence_no: None,
            occurred_at_unix_ms: 1_800_000_000_000,
            event_type: "connection".into(),
            source_ip: Some("192.0.2.1".parse::<IpAddr>().unwrap()),
            source_port: Some(12345),
            destination_port: Some(2223),
            protocol: "tcp".into(),
            service_type: "ssh".into(),
            payload: serde_json::json!({"source":"test"}),
            metadata: serde_json::json!({}),
        }
    }

    #[test]
    fn persists_and_deduplicates_events_across_reopen() {
        let path = std::env::temp_dir().join(format!("hf-telemetry-{}.jsonl", Uuid::new_v4()));
        let agent_id = Uuid::new_v4();
        let event = event(Uuid::new_v4());
        {
            let mut store = TelemetryStore::open(&path).unwrap();
            assert_eq!(store.persist(agent_id, &[event.clone()]).unwrap(), 1);
            assert_eq!(store.persist(agent_id, &[event.clone()]).unwrap(), 0);
        }
        let mut reopened = TelemetryStore::open(&path).unwrap();
        assert_eq!(reopened.persist(agent_id, &[event]).unwrap(), 0);
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 1);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn lost_batch_ack_replay_is_deduplicated_after_restart() {
        let path = std::env::temp_dir().join(format!("hf-telemetry-batch-{}.jsonl", Uuid::new_v4()));
        let agent_id = Uuid::new_v4();
        let batch = vec![event(Uuid::new_v4()), event(Uuid::new_v4()), event(Uuid::new_v4())];
        {
            let mut store = TelemetryStore::open(&path).unwrap();
            assert_eq!(store.persist(agent_id, &batch).unwrap(), batch.len());
            // A lost ACK causes the complete immutable envelope to be sent again.
            assert_eq!(store.persist(agent_id, &batch).unwrap(), 0);
        }
        let mut restarted = TelemetryStore::open(&path).unwrap();
        assert_eq!(restarted.persist(agent_id, &batch).unwrap(), 0);
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), batch.len());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn quarantined_unknown_trap_is_durable_and_not_in_main_spool() {
        let path = std::env::temp_dir().join(format!("hf-rejected-{}.jsonl", Uuid::new_v4()));
        let agent = Uuid::new_v4();
        let event = event(Uuid::new_v4());
        {
            let mut store = TelemetryStore::open(&path).unwrap();
            assert_eq!(store.reject(agent, &[event.clone()]).unwrap(), 1);
        }
        let mut restored = TelemetryStore::open(&path).unwrap();
        assert_eq!(restored.reject(agent, &[event]).unwrap(), 0);
        assert_eq!(fs::read_to_string(&path).unwrap(), "");
        assert_eq!(fs::read_to_string(path.with_extension("rejected.jsonl")).unwrap().lines().count(), 1);
        fs::remove_file(&path).unwrap();
        fs::remove_file(path.with_extension("rejected.jsonl")).unwrap();
    }
}
