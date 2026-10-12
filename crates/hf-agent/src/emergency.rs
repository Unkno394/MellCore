//! Root-owned, normally dormant response path. Only a separately confirmed
//! escape may create its marker; the service itself checks marker ownership.

use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    process::Command,
};

use anyhow::{Context, Result};
use kazik_protocol::TrapEvent;
use uuid::Uuid;

const DEFAULT_STATE: &str = "/var/lib/honeyforge";
const SCRIPT: &str = "/usr/local/libexec/honeyforge-emergency";
const UNIT: &str = "/etc/systemd/system/honeyforge-emergency.service";
const UNIT_CONTENT: &str = "# Managed by HoneyForge\n[Unit]\nDescription=HoneyForge confirmed-escape emergency response\nConditionPathExists=/var/lib/honeyforge/security/confirmed-escape\n[Service]\nType=oneshot\nExecStart=/usr/local/libexec/honeyforge-emergency /var/lib/honeyforge/security/confirmed-escape\nTimeoutStartSec=60\n";

pub(crate) struct PendingIncident {
    pub message_id: Uuid,
    pub response_armed: bool,
}

fn marker(state_dir: &Path) -> std::path::PathBuf {
    state_dir.join("security/confirmed-escape")
}

pub(crate) fn armed() -> bool {
    std::env::var("HF_EMERGENCY_ARMED").as_deref() == Ok("1")
}

pub(crate) fn install(state_dir: &Path) -> Result<()> {
    if !Path::new("/run/systemd/system").is_dir() {
        anyhow::ensure!(!armed(), "armed emergency response requires systemd");
        tracing::warn!("systemd is unavailable; emergency service cannot be installed");
        return Ok(());
    }
    if state_dir != Path::new(DEFAULT_STATE) || fs::metadata("/proc/self")?.uid() != 0 {
        anyhow::ensure!(
            !armed(),
            "armed emergency response requires root and the default state directory"
        );
        tracing::warn!(
            "emergency service requires root and the default state directory; response remains disabled"
        );
        return Ok(());
    }
    if armed() {
        for program in ["nft", "bpftrace"] {
            let status = Command::new(program)
                .arg("--version")
                .status()
                .with_context(|| format!("armed emergency response requires {program}"))?;
            anyhow::ensure!(
                status.success(),
                "armed emergency response requires working {program}"
            );
        }
    }
    fs::create_dir_all("/usr/local/libexec")?;
    let script = Path::new(SCRIPT);
    if let Ok(existing) = fs::read_to_string(script) {
        anyhow::ensure!(
            existing.starts_with("#!/bin/sh\n# Managed by HoneyForge\n"),
            "refusing to replace an unmanaged emergency script"
        );
    }
    if fs::read(script).ok().as_deref() != Some(include_str!("emergency.sh").as_bytes()) {
        crate::atomic_write(script, include_bytes!("emergency.sh"))?;
        fs::set_permissions(script, fs::Permissions::from_mode(0o700))?;
    }
    let unit = Path::new(UNIT);
    if let Ok(existing) = fs::read_to_string(unit) {
        anyhow::ensure!(
            existing.starts_with("# Managed by HoneyForge\n"),
            "refusing to replace an unmanaged emergency service"
        );
    }
    if fs::read(unit).ok().as_deref() != Some(UNIT_CONTENT.as_bytes()) {
        crate::atomic_write(unit, UNIT_CONTENT.as_bytes())?;
        crate::run_program("systemctl", &["daemon-reload"])?;
    }
    let directory = state_dir.join("security");
    fs::create_dir_all(&directory)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Durable local evidence, written before asking systemd to isolate the host.
pub(crate) fn record(state_dir: &Path, event: &TrapEvent, message_id: Uuid) -> Result<()> {
    anyhow::ensure!(
        event.event_type == "security.escape_confirmed" && !event.trap_id.is_nil(),
        "only a confirmed escape may create an emergency incident"
    );
    let path = marker(state_dir);
    if path.exists() {
        anyhow::bail!("a confirmed escape incident already exists");
    }
    let parent = path.parent().context("incident marker has no parent")?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(&path)?;
    file.write_all(
        format!(
            "{}\n{}\narmed={}\n",
            event.trap_id,
            message_id,
            u8::from(armed())
        )
        .as_bytes(),
    )?;
    file.sync_all()?;
    let details = parent.join("confirmed-escape.json");
    crate::atomic_write(&details, &serde_json::to_vec_pretty(event)?)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

pub(crate) fn pending(state_dir: &Path) -> Result<Option<PendingIncident>> {
    let path = marker(state_dir);
    let content = match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        fs::metadata(&path)?.uid() == 0,
        "incident marker is not root-owned"
    );
    Ok(Some(parse_marker(&content)?))
}

fn parse_marker(content: &str) -> Result<PendingIncident> {
    let mut lines = content.lines();
    let _: Uuid = lines.next().context("missing trap ID")?.parse()?;
    let message_id = lines.next().context("missing alert message ID")?.parse()?;
    let response_armed = match lines.next() {
        Some("armed=1") => true,
        Some("armed=0") => false,
        _ => anyhow::bail!("invalid incident response state"),
    };
    anyhow::ensure!(lines.next().is_none(), "unexpected incident marker content");
    Ok(PendingIncident {
        message_id,
        response_armed,
    })
}

pub(crate) fn start(state_dir: &Path) -> Result<()> {
    anyhow::ensure!(
        armed(),
        "emergency response is not armed (HF_EMERGENCY_ARMED=1)"
    );
    anyhow::ensure!(
        state_dir == Path::new(DEFAULT_STATE),
        "emergency response requires default state directory"
    );
    anyhow::ensure!(
        pending(state_dir)?.is_some_and(|pending| pending.response_armed),
        "incident was not armed when recorded"
    );
    let status = Command::new("systemctl")
        .args(["start", "--no-block", "honeyforge-emergency.service"])
        .status()?;
    anyhow::ensure!(
        status.success(),
        "systemctl could not start emergency service"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn incident_marker_is_durable_and_cannot_be_replaced() {
        let dir = std::env::temp_dir().join(format!("hf-emergency-{}", Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let event = TrapEvent {
            event_id: Uuid::new_v4(),
            trap_id: Uuid::new_v4(),
            session_id: None,
            source_sequence_no: None,
            occurred_at_unix_ms: 1,
            event_type: "security.escape_confirmed".into(),
            source_ip: None,
            source_port: None,
            destination_port: None,
            protocol: "local".into(),
            service_type: "host_monitor".into(),
            payload: json!({"pid":123}),
            metadata: json!({"assessment":"confirmed"}),
        };
        let message_id = Uuid::new_v4();
        let mut ordinary = event.clone();
        ordinary.event_type = "security.process_exec".into();
        assert!(record(&dir, &ordinary, Uuid::new_v4()).is_err());
        record(&dir, &event, message_id).unwrap();
        let parsed = parse_marker(&fs::read_to_string(marker(&dir)).unwrap()).unwrap();
        assert_eq!(parsed.message_id, message_id);
        assert_eq!(parsed.response_armed, armed());
        assert_eq!(
            fs::metadata(marker(&dir)).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(record(&dir, &event, Uuid::new_v4()).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
