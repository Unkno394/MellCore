use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Seek, SeekFrom, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use reqwest::Client;
use serde_json::json;

use crate::telemetry_store::StoredTelemetryEvent;

const INSERT_QUERY: &str = "INSERT INTO honeyforge.telemetry_events FORMAT JSONEachRow";
const MAX_INSERT_ROWS: usize = 1_000;

pub struct ClickHouseTelemetry {
    client: Client,
    endpoint: String,
    username: String,
    password: String,
}

impl ClickHouseTelemetry {
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let Ok(endpoint) = std::env::var("HF_CENTER_CLICKHOUSE_URL") else {
            return Ok(None);
        };
        let username = std::env::var("HF_CENTER_CLICKHOUSE_USER")
            .context("HF_CENTER_CLICKHOUSE_USER is required with ClickHouse URL")?;
        let password = std::env::var("HF_CENTER_CLICKHOUSE_PASSWORD")
            .context("HF_CENTER_CLICKHOUSE_PASSWORD is required with ClickHouse URL")?;
        let endpoint = format!("{}/", endpoint.trim_end_matches('/'));
        Ok(Some(Self {
            client: Client::builder().build()?,
            endpoint,
            username,
            password,
        }))
    }

    /// Streams the durable JSONL spool into ClickHouse. Cursor advances only after an
    /// acknowledged insert; a crash between insert and cursor update may replay a block,
    /// which ReplacingMergeTree deduplicates by (agent_id, event_id).
    pub async fn flush_spool(&self, spool_path: &Path) -> anyhow::Result<usize> {
        let cursor_path = spool_path.with_extension("clickhouse.offset");
        let offset = read_offset(&cursor_path)?;
        let mut file = File::open(spool_path)
            .with_context(|| format!("open telemetry spool {}", spool_path.display()))?;
        let length = file.metadata()?.len();
        if offset > length {
            bail!("ClickHouse telemetry cursor is beyond the spool length");
        }
        file.seek(SeekFrom::Start(offset))?;
        let mut reader = BufReader::new(file);
        let mut next_offset = offset;
        let mut body = String::new();
        let mut count = 0usize;
        loop {
            let mut line = Vec::new();
            let read = reader.read_until(b'\n', &mut line)?;
            if read == 0 || line.last() != Some(&b'\n') {
                break;
            }
            next_offset += read as u64;
            let record: StoredTelemetryEvent = serde_json::from_slice(&line)
                .context("parse event from durable telemetry spool")?;
            let event = record.event;
            let row = json!({
                "agent_id": record.agent_id,
                "event_id": event.event_id,
                "trap_id": event.trap_id,
                "received_at_unix_ms": record.received_at_unix_ms,
                "occurred_at_unix_ms": event.occurred_at_unix_ms,
                "event_type": event.event_type,
                "session_id": event.session_id,
                "source_sequence_no": event.source_sequence_no,
                "source_ip": event.source_ip.map(|ip| ip.to_string()),
                "source_port": event.source_port,
                "destination_port": event.destination_port,
                "protocol": event.protocol,
                "service_type": event.service_type,
                "event_payload": event.payload.to_string(),
                "event_metadata": event.metadata.to_string(),
            });
            body.push_str(&serde_json::to_string(&row)?);
            body.push('\n');
            count += 1;
            if count >= MAX_INSERT_ROWS {
                break;
            }
        }
        if count == 0 {
            return Ok(0);
        }

        self.client
            .post(&self.endpoint)
            .basic_auth(&self.username, Some(&self.password))
            .query(&[("query", INSERT_QUERY)])
            .body(body)
            .send()
            .await?
            .error_for_status()
            .context("ClickHouse rejected telemetry insert")?;
        write_offset(&cursor_path, next_offset)?;
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
    options.create(true).truncate(true).write(true);
    options.mode(0o600);
    let mut file = options.open(&temporary)?;
    writeln!(file, "{offset}")?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}
