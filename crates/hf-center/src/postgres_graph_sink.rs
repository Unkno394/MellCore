//! Mirrors the durable Center spool into PostgreSQL's normalized-action and
//! knowledge-graph pipeline. The local cursor advances only after HTTP ACK.
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Seek, SeekFrom, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, bail};
use reqwest::Client;
use serde_json::json;

use crate::telemetry_store::StoredTelemetryEvent;

pub struct PostgresGraphSink {
    client: Client,
    endpoint: String,
    token: String,
}

impl PostgresGraphSink {
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let Ok(endpoint) = std::env::var("HF_CENTER_POSTGRES_TELEMETRY_URL") else {
            return Ok(None);
        };
        let token = std::env::var("HF_CENTER_POSTGRES_TELEMETRY_TOKEN")
            .context("HF_CENTER_POSTGRES_TELEMETRY_TOKEN is required with PostgreSQL graph URL")?;
        let url = url::Url::parse(&endpoint)?;
        anyhow::ensure!(
            url.scheme() == "http" && url.host_str() == Some("127.0.0.1"),
            "PostgreSQL graph sink must use the local backend over loopback HTTP"
        );
        Ok(Some(Self {
            client: Client::builder().timeout(Duration::from_secs(10)).build()?,
            endpoint,
            token,
        }))
    }

    pub async fn flush_spool(&self, spool_path: &Path) -> anyhow::Result<usize> {
        let cursor_path = spool_path.with_extension("postgres-graph.offset");
        let offset = read_offset(&cursor_path)?;
        let mut file = File::open(spool_path)
            .with_context(|| format!("open telemetry spool {}", spool_path.display()))?;
        let length = file.metadata()?.len();
        if offset > length {
            bail!("PostgreSQL graph cursor is beyond telemetry spool length")
        }
        file.seek(SeekFrom::Start(offset))?;
        let mut reader = BufReader::new(file);
        let mut next_offset = offset;
        let mut count = 0;
        loop {
            let mut line = Vec::new();
            let bytes = reader.read_until(b'\n', &mut line)?;
            if bytes == 0 || line.last() != Some(&b'\n') {
                break;
            }
            let record: StoredTelemetryEvent =
                serde_json::from_slice(&line).context("parse Center spool event")?;
            let event = record.event;
            let occurred_at =
                chrono::DateTime::<chrono::Utc>::from_timestamp_millis(event.occurred_at_unix_ms)
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
            let response = self
                .client
                .post(&self.endpoint)
                .bearer_auth(&self.token)
                .json(&payload)
                .send()
                .await?;
            if response.status().is_success() {
                // An accepted response means the event and its graph observation committed.
            } else if response.status().as_u16() == 404 || response.status().as_u16() == 422 {
                tracing::warn!(event_id = %event.event_id, status = %response.status(), "event kept in ClickHouse but not indexed by PostgreSQL graph");
            } else {
                response
                    .error_for_status()
                    .context("PostgreSQL graph pipeline rejected Center event")?;
            }
            next_offset += bytes as u64;
            count += 1;
            if count >= 100 {
                break;
            }
        }
        if count > 0 {
            write_offset(&cursor_path, next_offset)?;
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
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true).mode(0o600);
    let mut file = options.open(&temporary)?;
    writeln!(file, "{offset}")?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}
