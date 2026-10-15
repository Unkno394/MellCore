use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Seek, SeekFrom, Write},
    net::IpAddr,
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, bail};
use chrono::{DateTime, SecondsFormat, Utc};
use hf_services::kazik_outbox::SqliteKazikOutbox;
use kazik_protocol::{
    DurableOutbox, KazikBody, KazikEnvelope, MAX_TELEMETRY_BATCH_EVENTS, MAX_TELEMETRY_BATCH_WAIT,
    MAX_TELEMETRY_PACKET_BYTES, TrapEvent,
};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::AgentIdentity;

#[derive(Debug)]
struct PlannedBatch {
    envelope: KazikEnvelope,
    critical: bool,
}

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
            Ok(batch) => events.extend(batch.events.into_iter().map(|event| {
                let mut event = TrapEvent::from(event);
                // The file belongs to this project; its content cannot select another trap.
                event.trap_id = trap_id;
                event
            })),
            Err(error) => {
                tracing::warn!(%error, trap_id = %trap_id, "skipping malformed Middle telemetry line")
            }
        }
    }
    let count = queue_events(events, identity, outbox)?;
    write_cursor(&cursor_path, format!("{next_offset}\n").as_bytes())?;
    Ok(count)
}

fn collect_low(
    _project: &Path,
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
        let Some(json_start) = line.find('{') else {
            continue;
        };
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
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;
    for batch in plan_batches(events, identity, now)? {
        let message_id = batch.envelope.message_id;
        if batch.critical {
            outbox.enqueue(batch.envelope)?;
            outbox.prioritize(message_id)?;
        } else {
            outbox.enqueue_batchable_telemetry(batch.envelope)?;
        }
    }
    Ok(count)
}

pub(crate) fn batch_wait() -> std::time::Duration {
    MAX_TELEMETRY_BATCH_WAIT
}

pub(crate) fn is_critical_event(event: &TrapEvent) -> bool {
    let host_observer =
        event.metadata.get("source").and_then(Value::as_str) == Some("hf-agent-ebpf");
    (host_observer
        && matches!(
            event.event_type.as_str(),
            "security.escape_confirmed"
                | "security.namespace_mismatch"
                | "security.host_exec_from_trap"
        ))
        || matches!(
            event.event_type.as_str(),
            "security.trap_quarantined" | "security.trap_quarantine_failed"
        )
        || (host_observer
            && (event.payload.get("policy_decision").and_then(Value::as_str)
                == Some("isolate_trap")
                || matches!(
                    event.metadata.get("assessment").and_then(Value::as_str),
                    Some("confirmed" | "isolated")
                )))
}

pub(crate) fn enqueue_immediate_event(
    identity: &AgentIdentity,
    outbox: &mut SqliteKazikOutbox,
    event: TrapEvent,
) -> anyhow::Result<Uuid> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;
    let critical = is_critical_event(&event);
    let envelope = telemetry_envelope(identity, now, vec![event]);
    ensure_packet_size(&envelope)?;
    let message_id = envelope.message_id;
    if critical {
        outbox.enqueue(envelope)?;
        outbox.prioritize(message_id)?;
    } else {
        outbox.enqueue_batchable_telemetry(envelope)?;
    }
    Ok(message_id)
}

pub(crate) fn ensure_packet_size(envelope: &KazikEnvelope) -> anyhow::Result<()> {
    let encoded_len = envelope.encode_hfsp(0, 0)?.len();
    anyhow::ensure!(
        encoded_len <= MAX_TELEMETRY_PACKET_BYTES,
        "Kazik telemetry message {} is {encoded_len} bytes; maximum is {MAX_TELEMETRY_PACKET_BYTES}",
        envelope.message_id
    );
    Ok(())
}

fn plan_batches(
    events: Vec<TrapEvent>,
    identity: &AgentIdentity,
    sent_at_unix_ms: i64,
) -> anyhow::Result<Vec<PlannedBatch>> {
    let mut chunks: Vec<(Vec<TrapEvent>, bool)> = Vec::new();
    let mut normal = Vec::new();

    for event in events {
        if is_critical_event(&event) {
            if !normal.is_empty() {
                chunks.push((std::mem::take(&mut normal), false));
            }
            let envelope = telemetry_envelope(identity, sent_at_unix_ms, vec![event.clone()]);
            ensure_packet_size(&envelope).with_context(|| {
                format!(
                    "critical event {} cannot fit in one HFSP packet",
                    event.event_id
                )
            })?;
            chunks.push((vec![event], true));
            continue;
        }

        if normal.len() == MAX_TELEMETRY_BATCH_EVENTS {
            chunks.push((std::mem::take(&mut normal), false));
        }
        let mut candidate = normal.clone();
        candidate.push(event.clone());
        let candidate_envelope = telemetry_envelope(identity, sent_at_unix_ms, candidate);
        if candidate_envelope.encode_hfsp(0, 0)?.len() > MAX_TELEMETRY_PACKET_BYTES {
            if normal.is_empty() {
                bail!(
                    "telemetry event {} cannot fit in the {MAX_TELEMETRY_PACKET_BYTES}-byte HFSP limit",
                    event.event_id
                );
            }
            chunks.push((std::mem::take(&mut normal), false));
            let single = telemetry_envelope(identity, sent_at_unix_ms, vec![event.clone()]);
            ensure_packet_size(&single).with_context(|| {
                format!(
                    "telemetry event {} cannot fit in one HFSP packet",
                    event.event_id
                )
            })?;
        }
        normal.push(event);
    }
    if !normal.is_empty() {
        chunks.push((normal, false));
    }

    chunks
        .into_iter()
        .enumerate()
        .map(|(index, (events, critical))| {
            let envelope = telemetry_envelope(
                identity,
                sent_at_unix_ms.saturating_add(index as i64),
                events,
            );
            ensure_packet_size(&envelope)?;
            Ok(PlannedBatch { envelope, critical })
        })
        .collect()
}

fn telemetry_envelope(
    identity: &AgentIdentity,
    sent_at_unix_ms: i64,
    events: Vec<TrapEvent>,
) -> KazikEnvelope {
    KazikEnvelope::new(
        identity.agent_id,
        identity.transport_credential.clone(),
        sent_at_unix_ms,
        KazikBody::Telemetry { events },
    )
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
    fn from(mut event: MiddleEvent) -> Self {
        // Container-controlled JSON cannot impersonate the host observer.
        if !event.metadata.is_object() {
            event.metadata = serde_json::json!({});
        }
        event.metadata["source"] = serde_json::json!("pritvoryashka");
        event.metadata["evidence_domain"] = serde_json::json!("simulated");
        if let Some(metadata) = event.metadata.as_object_mut() {
            metadata.remove("assessment");
            metadata.remove("validation");
        }
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
            protocol: "tcp".into(),
            service_type: "ssh".into(),
            payload: event.payload,
            metadata: event.metadata,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kazik_protocol::{KazikBody, MAX_TELEMETRY_BATCH_EVENTS, MAX_TELEMETRY_PACKET_BYTES};

    fn identity() -> AgentIdentity {
        AgentIdentity {
            agent_id: Uuid::new_v4(),
            transport_credential: "agent-secret".into(),
            hysteria: None,
        }
    }

    fn event(sequence: u64, event_type: &str, blob_bytes: usize) -> TrapEvent {
        TrapEvent {
            event_id: Uuid::new_v4(),
            trap_id: Uuid::new_v4(),
            session_id: Some(format!("session-{sequence}")),
            source_sequence_no: Some(sequence),
            occurred_at_unix_ms: 1_760_000_000_000 + sequence as i64,
            event_type: event_type.into(),
            source_ip: Some("2001:db8::1".parse().unwrap()),
            source_port: Some(40_000 + sequence as u16),
            destination_port: Some(2224),
            protocol: "tcp".into(),
            service_type: "ssh".into(),
            payload: serde_json::json!({"blob":"x".repeat(blob_bytes)}),
            metadata: serde_json::json!({"source":"test"}),
        }
    }

    fn events_in(batch: &PlannedBatch) -> &[TrapEvent] {
        let KazikBody::Telemetry { events } = &batch.envelope.body else {
            panic!("expected telemetry envelope")
        };
        events
    }

    #[test]
    fn batches_preserve_order_fields_and_twenty_event_limit() {
        let identity = identity();
        let input: Vec<_> = (0..45)
            .map(|index| event(index, "command.executed", 4))
            .collect();
        let expected = input.clone();
        let batches = plan_batches(input, &identity, 100).unwrap();
        assert_eq!(
            batches
                .iter()
                .map(|batch| events_in(batch).len())
                .collect::<Vec<_>>(),
            vec![20, 20, 5]
        );
        assert!(
            batches
                .iter()
                .all(|batch| events_in(batch).len() <= MAX_TELEMETRY_BATCH_EVENTS)
        );
        assert!(
            batches
                .iter()
                .all(|batch| batch.envelope.encode_hfsp(0, 0).unwrap().len()
                    <= MAX_TELEMETRY_PACKET_BYTES)
        );
        let actual: Vec<_> = batches.iter().flat_map(events_in).cloned().collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn splits_on_encoded_packet_size_and_rejects_one_oversized_event() {
        let identity = identity();
        let batches = plan_batches(
            vec![
                event(1, "command.executed", 6_000),
                event(2, "command.executed", 6_000),
                event(3, "command.executed", 6_000),
            ],
            &identity,
            100,
        )
        .unwrap();
        assert_eq!(
            batches
                .iter()
                .map(|batch| events_in(batch).len())
                .sum::<usize>(),
            3
        );
        assert!(batches.len() >= 2);
        assert!(
            batches
                .iter()
                .all(|batch| batch.envelope.encode_hfsp(0, 0).unwrap().len()
                    <= MAX_TELEMETRY_PACKET_BYTES)
        );
        assert!(plan_batches(vec![event(4, "command.executed", 20_000)], &identity, 100).is_err());
    }

    #[test]
    fn critical_events_are_separate_and_prioritized_in_the_outbox() {
        let state_dir = std::env::temp_dir().join(format!("hf-critical-batch-{}", Uuid::new_v4()));
        let identity = identity();
        let normal_before = event(1, "command.executed", 0);
        let mut critical = event(2, "security.escape_confirmed", 0);
        critical.metadata = serde_json::json!({"source":"hf-agent-ebpf","assessment":"confirmed"});
        let normal_after = event(3, "command.executed", 0);
        let mut outbox = SqliteKazikOutbox::open(state_dir.join("outbox.sqlite")).unwrap();
        queue_events(
            vec![normal_before, critical.clone(), normal_after],
            &identity,
            &mut outbox,
        )
        .unwrap();
        let pending = outbox.pending(10).unwrap();
        assert_eq!(pending.len(), 3);
        let KazikBody::Telemetry { events } = &pending[0].body else {
            panic!("expected telemetry")
        };
        assert_eq!(events.as_slice(), &[critical]);
        drop(outbox);
        fs::remove_dir_all(state_dir).unwrap();
    }

    #[test]
    fn partial_batches_flush_within_two_seconds() {
        assert_eq!(batch_wait(), std::time::Duration::from_secs(2));
    }

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
        assert_eq!(normalized.metadata["source"], "pritvoryashka");
    }

    #[test]
    fn container_cannot_impersonate_host_monitor() {
        let input = serde_json::json!({
            "event_id":Uuid::new_v4(),"trap_id":Uuid::new_v4(),"event_type":"security.escape_confirmed",
            "occurred_at":"2026-10-11T20:00:00Z","protocol":"local","service_type":"host_monitor",
            "payload":{},"metadata":{"source":"hf-agent-ebpf","assessment":"confirmed","validation":"two_samples_proc_docker_v2"}
        });
        let event = TrapEvent::from(serde_json::from_value::<MiddleEvent>(input).unwrap());
        assert_eq!(event.service_type, "ssh");
        assert_eq!(event.metadata["source"], "pritvoryashka");
        assert!(event.metadata.get("validation").is_none());
        assert!(!is_critical_event(&event));
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
        let identity = identity();
        let mut outbox = SqliteKazikOutbox::open(state_dir.join("outbox.sqlite")).unwrap();

        assert_eq!(
            collect_new_events(&traps, &state_dir, &identity, &mut outbox).unwrap(),
            1
        );
        assert_eq!(
            collect_new_events(&traps, &state_dir, &identity, &mut outbox).unwrap(),
            0
        );
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
