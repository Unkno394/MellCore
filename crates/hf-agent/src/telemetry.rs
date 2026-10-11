use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Seek, SeekFrom, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, bail};
use chrono::{DateTime, SecondsFormat, Utc};
use hf_services::kazik_outbox::SqliteKazikOutbox;
use kazik_protocol::{DurableOutbox, KazikBody, KazikEnvelope, TrapEvent};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::AgentIdentity;

// Keep each HFSP datagram comfortably below its 1 MiB maximum even when Middle events
// approach their configured 64 KiB limit.
// Hysteria carries Kazik in UDP datagrams, so keep a message below the practical UDP ceiling.
const TELEMETRY_CHUNK_SIZE: usize = 1;

#[derive(Deserialize)]
struct MiddleBatch {
    events: Vec<MiddleEvent>,
}

#[derive(Deserialize)]
struct MiddleEvent {
    event_id: Uuid,
    trap_id: Uuid,
    session_id: Option<String>,
    sequence_no: Option<u64>,
    event_type: String,
    occurred_at: DateTime<Utc>,
    source_ip: Option<IpAddr>,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    protocol: String,
    service_type: String,
    payload: Value,
    metadata: Value,
}

#[derive(Deserialize)]
struct LowEvent {
    event_id: Uuid,
    event_type: String,
    timestamp: DateTime<Utc>,
    trap_id: Uuid,
    client_ip: IpAddr,
    client_port: u16,
    trap_port: u16,
}

/// Collects new trap output, durably queues it before advancing source cursors, and returns the
/// number of events placed in the Kazik outbox. Center ACKs remain responsible for deletion.
pub fn collect_new_events(
    project_root: &Path,
    state_dir: &Path,
    identity: &AgentIdentity,
    outbox: &mut SqliteKazikOutbox,
) -> anyhow::Result<usize> {
    let mut collected = 0;
    let cursor_dir = state_dir.join("telemetry-cursors");
    fs::create_dir_all(&cursor_dir)?;
    let projects = match fs::read_dir(project_root) {
        Ok(projects) => projects,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };

    for entry in projects {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Ok(trap_id) = Uuid::parse_str(&entry.file_name().to_string_lossy()) else {
            continue;
        };
        let project = entry.path();
        let middle_log = project.join("runtime/events.jsonl");
        if middle_log.is_file() {
            collected += collect_middle(&middle_log, &cursor_dir, trap_id, identity, outbox)?;
            continue;
        }
        if project.join("config.json").is_file() {
            collected += collect_low(&project, &cursor_dir, trap_id, identity, outbox)?;
        }
    }
    Ok(collected)
}

fn collect_middle(
    log_path: &Path,
    cursor_dir: &Path,
    trap_id: Uuid,
    identity: &AgentIdentity,
    outbox: &mut SqliteKazikOutbox,
) -> anyhow::Result<usize> {
    let cursor_path = cursor_dir.join(format!("{trap_id}-middle.offset"));
    let offset = read_offset(&cursor_path)?;
    let mut file = File::open(log_path).with_context(|| format!("open {}", log_path.display()))?;
    let length = file.metadata()?.len();
    if offset > length {
        // The source file was rotated or replaced; start at its beginning.
        write_cursor(&cursor_path, b"0\n")?;
        file.seek(SeekFrom::Start(0))?;
    } else {
        file.seek(SeekFrom::Start(offset))?;
    }

    let mut reader = BufReader::new(file);
    let mut next_offset = if offset > length { 0 } else { offset };
    let mut events = Vec::new();
    loop {
        let mut line = Vec::new();
        let read = reader.read_until(b'\n', &mut line)?;
        if read == 0 || line.last() != Some(&b'\n') {
            break; // keep a partial trailing JSON line for the next poll
        }
        next_offset += read as u64;
        match serde_json::from_slice::<MiddleBatch>(&line) {
            Ok(batch) => events.extend(batch.events.into_iter().map(Into::into)),
            Err(error) => tracing::warn!(%error, trap_id = %trap_id, "skipping malformed Middle telemetry line"),
        }
    }
    let count = queue_events(events, identity, outbox)?;
    write_cursor(&cursor_path, format!("{next_offset}\n").as_bytes())?;
    Ok(count)
}

fn collect_low(
    project: &Path,
    cursor_dir: &Path,
    trap_id: Uuid,
    identity: &AgentIdentity,
    outbox: &mut SqliteKazikOutbox,
) -> anyhow::Result<usize> {
    let cursor_path = cursor_dir.join(format!("{trap_id}-low.timestamp"));
    let cursor = match fs::read_to_string(&cursor_path) {
        Ok(value) => value.trim().to_owned(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error.into()),
    };
    let since = if cursor.is_empty() {
        "1970-01-01T00:00:00Z"
    } else {
        cursor.as_str()
    };
    let container = format!("hf-{}-honeypot-1", trap_id.simple());
    let output = Command::new("docker")
        .args(["logs", "--timestamps", "--since", &since, &container])
        .output()
        .with_context(|| format!("read Docker logs for trap {trap_id}"))?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr);
        if message.contains("No such container") || message.contains("not found") {
            return Ok(0);
        }
        bail!("docker logs for {container} failed: {}", message.trim());
    }

    let mut events = Vec::new();
    let mut newest: Option<DateTime<chrono::FixedOffset>> = None;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        // Docker's --timestamps prepends an RFC3339 timestamp before the application JSON.
        let Some(json_start) = line.find('{') else { continue };
        let docker_timestamp = match DateTime::parse_from_rfc3339(line[..json_start].trim()) {
            Ok(timestamp) => timestamp,
            Err(_) => continue,
        };
        if newest
            .as_ref()
            .is_none_or(|current| docker_timestamp > *current)
        {
            newest = Some(docker_timestamp);
        }
        let Ok(event) = serde_json::from_str::<LowEvent>(&line[json_start..]) else {
            continue;
        };
        if event.trap_id != trap_id {
            continue;
        }
        events.push(TrapEvent {
            event_id: event.event_id,
            trap_id: event.trap_id,
            session_id: None,
            source_sequence_no: None,
            occurred_at_unix_ms: event.timestamp.timestamp_millis(),
            event_type: event.event_type,
            source_ip: Some(event.client_ip),
            source_port: Some(event.client_port),
            destination_port: Some(event.trap_port),
            protocol: "tcp".into(),
            service_type: "ssh".into(),
            payload: serde_json::json!({"source":"honeyforge-low"}),
            metadata: serde_json::json!({"source":"docker-stdout","schema_version":1}),
        });
    }
    let count = queue_events(events, identity, outbox)?;
    if let Some(newest) = newest {
        // --since is inclusive. Move one nanosecond past the last Docker timestamp to avoid
        // repeatedly harvesting the same boundary record on every poll.
        let next = newest + chrono::Duration::nanoseconds(1);
        write_cursor(
            &cursor_path,
            format!("{}\n", next.to_rfc3339_opts(SecondsFormat::Nanos, true)).as_bytes(),
        )?;
    }
    Ok(count)
}

fn queue_events(
    events: Vec<TrapEvent>,
    identity: &AgentIdentity,
    outbox: &mut SqliteKazikOutbox,
) -> anyhow::Result<usize> {
    let count = events.len();
    for chunk in events.chunks(TELEMETRY_CHUNK_SIZE) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;
        outbox.enqueue(KazikEnvelope::new(
            identity.agent_id,
            identity.transport_credential.clone(),
            now,
            KazikBody::Telemetry {
                events: chunk.to_vec(),
            },
        ))?;
    }
    Ok(count)
}

fn read_offset(path: &Path) -> anyhow::Result<u64> {
    match fs::read_to_string(path) {
        Ok(value) => Ok(value.trim().parse().unwrap_or_default()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error.into()),
    }
}

fn write_cursor(path: &Path, value: &[u8]) -> anyhow::Result<()> {
    let temporary = path.with_extension("cursor.tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(value)?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    Ok(())
}

impl From<MiddleEvent> for TrapEvent {
    fn from(event: MiddleEvent) -> Self {
        Self {
            event_id: event.event_id,
            trap_id: event.trap_id,
            session_id: event.session_id,
            source_sequence_no: event.sequence_no,
            occurred_at_unix_ms: event.occurred_at.timestamp_millis(),
            event_type: event.event_type,
            source_ip: event.source_ip,
            source_port: event.source_port,
            destination_port: event.destination_port,
            protocol: event.protocol,
            service_type: event.service_type,
            payload: event.payload,
            metadata: event.metadata,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kazik_protocol::KazikBody;

    #[test]
    fn maps_middle_event_without_losing_identity_or_payload() {
        let event: MiddleEvent = serde_json::from_value(serde_json::json!({
            "event_id":"9a8a8262-556b-43c4-a73f-736c32556721",
            "trap_id":"6b6f7a79-6176-4b61-8000-000000000001",
            "session_id":"session-1",
            "sequence_no":3,
            "event_type":"auth.attempted",
            "occurred_at":"2026-10-11T20:00:00Z",
            "source_ip":"192.0.2.1",
            "source_port":54321,
            "destination_port":2224,
            "protocol":"tcp",
            "service_type":"ssh",
            "payload":{"username":"probe"},
            "metadata":{"source":"test"}
        }))
        .unwrap();
        let normalized = TrapEvent::from(event);
        assert_eq!(normalized.event_type, "auth.attempted");
        assert_eq!(normalized.source_sequence_no, Some(3));
        assert_eq!(normalized.destination_port, Some(2224));
        assert_eq!(normalized.payload["username"], "probe");
    }

    #[test]
    fn middle_jsonl_is_queued_once_before_cursor_advances() {
        let state_dir = std::env::temp_dir().join(format!("hf-agent-telemetry-{}", Uuid::new_v4()));
        let traps = state_dir.join("traps");
        let trap_id = Uuid::new_v4();
        let runtime = traps.join(trap_id.to_string()).join("runtime");
        fs::create_dir_all(&runtime).unwrap();
        let event_id = Uuid::new_v4();
        let line = serde_json::json!({
            "schema_version":1,
            "batch_id":Uuid::new_v4(),
            "agent_id":Uuid::new_v4(),
            "server_id":Uuid::new_v4(),
            "events":[{
                "event_id":event_id,
                "trap_id":trap_id,
                "session_id":"test-session",
                "sequence_no":1,
                "event_type":"connection.opened",
                "occurred_at":"2026-10-11T20:00:00Z",
                "source_ip":"192.0.2.1",
                "source_port":42000,
                "destination_port":2224,
                "protocol":"tcp",
                "service_type":"ssh",
                "payload":{},
                "metadata":{}
            }]
        });
        fs::write(runtime.join("events.jsonl"), format!("{line}\n")).unwrap();
        let identity = AgentIdentity {
            agent_id: Uuid::new_v4(),
            transport_credential: "agent-secret".into(),
            hysteria: None,
        };
        let mut outbox = SqliteKazikOutbox::open(state_dir.join("outbox.sqlite")).unwrap();

        assert_eq!(collect_new_events(&traps, &state_dir, &identity, &mut outbox).unwrap(), 1);
        assert_eq!(collect_new_events(&traps, &state_dir, &identity, &mut outbox).unwrap(), 0);
        let pending = outbox.pending(10).unwrap();
        assert_eq!(pending.len(), 1);
        let KazikBody::Telemetry { events } = &pending[0].body else {
            panic!("expected telemetry envelope");
        };
        assert_eq!(events[0].event_id, event_id);

        drop(outbox);
        fs::remove_dir_all(state_dir).unwrap();
    }
}
