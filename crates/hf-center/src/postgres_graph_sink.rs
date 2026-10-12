//! Mirrors the durable Center spool into PostgreSQL's normalized-action and
//! knowledge-graph pipeline. The cursor advances after a validated commit ACK
//! or a durable rejection record; rejection never implies ClickHouse delivery.
use std::{fs::{self, File, OpenOptions}, io::{BufRead, BufReader, Seek, SeekFrom, Write}, os::unix::fs::{OpenOptionsExt, PermissionsExt}, path::{Path, PathBuf}, time::Duration};

use anyhow::{Context, bail};
use reqwest::Client;
use serde_json::json;

use crate::telemetry_store::StoredTelemetryEvent;

pub struct PostgresGraphSink { client: Client, endpoint: String, token: String }

impl PostgresGraphSink {
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let Ok(endpoint) = std::env::var("HF_CENTER_POSTGRES_TELEMETRY_URL") else { return Ok(None) };
        let token = std::env::var("HF_CENTER_POSTGRES_TELEMETRY_TOKEN")
            .context("HF_CENTER_POSTGRES_TELEMETRY_TOKEN is required with PostgreSQL graph URL")?;
        let url = url::Url::parse(&endpoint)?;
        anyhow::ensure!(url.scheme() == "http" && url.host_str() == Some("127.0.0.1"), "PostgreSQL graph sink must use the local backend over loopback HTTP");
        Ok(Some(Self { client: Client::builder().timeout(Duration::from_secs(10)).build()?, endpoint, token }))
    }

    pub async fn flush_spool(&self, spool_path: &Path) -> anyhow::Result<usize> {
        let cursor_path = spool_path.with_extension("postgres-graph.offset");
        let offset = read_offset(&cursor_path)?;
        let mut file = File::open(spool_path).with_context(|| format!("open telemetry spool {}", spool_path.display()))?;
        let length = file.metadata()?.len();
        if offset > length { bail!("PostgreSQL graph cursor is beyond telemetry spool length") }
        file.seek(SeekFrom::Start(offset))?;
        let mut reader = BufReader::new(file);
        let mut next_offset = offset;
        let mut count = 0;
        loop {
            let mut line = Vec::new();
            let bytes = reader.read_until(b'\n', &mut line)?;
            if bytes == 0 || line.last() != Some(&b'\n') { break; }
            let record: StoredTelemetryEvent = serde_json::from_slice(&line).context("parse Center spool event")?;
            let event = &record.event;
            let occurred_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(event.occurred_at_unix_ms)
                .context("event timestamp is outside chrono range")?;
            let payload = json!({
                "event": {
                    "event_id": event.event_id,
                    "trap_id": event.trap_id,
                    "session_id": event.session_id,
                    "sequence_no": event.source_sequence_no,
                    "event_type": event.event_type,
                    "occurred_at": occurred_at.to_rfc3339(),
                    "source_ip": event.source_ip.map(|ip| ip.to_string()),
                    "source_port": event.source_port,
                    "destination_port": event.destination_port,
                    "protocol": event.protocol,
                    "service_type": event.service_type,
                    "payload": event.payload,
                    "metadata": event.metadata,
                },
                "agent_id": record.agent_id,
            });
            let response = self.client.post(&self.endpoint).bearer_auth(&self.token).json(&payload).send().await?;
            let status = response.status().as_u16();
            if status == 202 {
                let ack: serde_json::Value = response.json().await.context("parse graph commit ACK")?;
                anyhow::ensure!(valid_ack(&ack, event.event_id), "invalid PostgreSQL graph commit ACK");
            } else if matches!(status, 404 | 409 | 422) {
                // A missing backend route also returns 404. It is a deployment
                // failure, not a rejected event, so keep the cursor retryable.
                let error: serde_json::Value = response.json().await.context("parse backend rejection")?;
                let expected = match status {
                    404 => "not_found", 409 => "conflict", _ => "validation_error",
                };
                anyhow::ensure!(error["error"]["code"].as_str() == Some(expected),
                    "unexpected backend rejection shape; cursor remains retryable");
                // Unknown traps/conflicting/invalid events must be reviewable and replayable.
                // The original spool and this rejection record retain the complete event.
                retain_rejection(spool_path, next_offset, status, &record)?;
                tracing::warn!(event_id = %event.event_id, status, offset = next_offset,
                    "graph event rejected; saved to postgres-graph-rejected.jsonl for reconciliation");
            } else {
                bail!("PostgreSQL graph pipeline returned HTTP {status}; cursor remains retryable");
            }
            next_offset += bytes as u64;
            write_offset(&cursor_path, next_offset)?;
            count += 1;
            if count >= 100 { break; }
        }
        Ok(count)
    }
}

fn read_offset(path: &Path) -> anyhow::Result<u64> {
    match fs::read_to_string(path) {
        Ok(value) => Ok(value.trim().parse()?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error.into()),
    }
}
fn write_offset(path: &Path, offset: u64) -> anyhow::Result<()> {
    let temporary = PathBuf::from(format!("{}.tmp", path.display()));
    let mut options = OpenOptions::new(); options.create(true).truncate(true).write(true).mode(0o600);
    let mut file = options.open(&temporary)?; writeln!(file, "{offset}")?; file.sync_all()?;
    fs::rename(temporary, path)?; fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    if let Some(parent) = path.parent() { File::open(parent)?.sync_all()?; }
    Ok(())
}


fn valid_ack(ack: &serde_json::Value, event_id: uuid::Uuid) -> bool {
    ack["batch_id"].as_str().and_then(|s| s.parse::<uuid::Uuid>().ok()) == Some(event_id)
        && matches!((ack["accepted_events"].as_u64(), ack["duplicate_events"].as_u64()),
            (Some(1), Some(0)) | (Some(0), Some(1)))
}

fn retain_rejection(spool: &Path, offset: u64, status: u16, record: &StoredTelemetryEvent) -> anyhow::Result<()> {
    let path = spool.with_extension("postgres-graph-rejected.jsonl");
    let mut file = OpenOptions::new().create(true).append(true).mode(0o600).open(&path)?;
    serde_json::to_writer(&mut file, &json!({"spool_offset":offset,"http_status":status,"record":record}))?;
    file.write_all(b"\n")?; file.sync_all()?;
    if let Some(parent) = path.parent() { File::open(parent)?.sync_all()?; }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_matching_single_event_commit_is_an_ack() {
        let id = uuid::Uuid::new_v4();
        assert!(valid_ack(&json!({"batch_id":id,"accepted_events":1,"duplicate_events":0}),id));
        assert!(valid_ack(&json!({"batch_id":id,"accepted_events":0,"duplicate_events":1}),id));
        assert!(!valid_ack(&json!({"batch_id":id,"accepted_events":0,"duplicate_events":0}),id));
        assert!(!valid_ack(&json!({"batch_id":uuid::Uuid::new_v4(),"accepted_events":1,"duplicate_events":0}),id));
    }
}
