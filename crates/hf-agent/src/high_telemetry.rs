use std::{
    collections::HashMap,
    fs,
    os::unix::fs::FileTypeExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::sandbox::{
    HighDomainState, LibvirtSandboxManager, default_recipe_dir, is_supported_profile,
};
use hf_core::{HighGuestConnection, HighOsProfile};
use hf_services::high_telemetry::{
    HighTelemetryStore, SharedHighTelemetryStore, receive_high_telemetry_connection,
};
use serde::{Deserialize, Serialize};
use tokio::{net::UnixStream, task::JoinHandle};
use uuid::Uuid;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct DomainCounters {
    vcpu_count: Option<u64>,
    cpu_time_ns: Option<u64>,
    memory_current_kib: Option<u64>,
    memory_usable_kib: Option<u64>,
    disk_read_bytes: u64,
    disk_write_bytes: u64,
    network_rx_bytes: u64,
    network_tx_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HighOperationalSnapshot {
    version: u8,
    trap_id: Uuid,
    observed_at_unix_ms: i64,
    domain_state: String,
    running_since_unix_ms: Option<i64>,
    uptime_seconds: Option<u64>,
    /// Aggregate busy percentage across all guest vCPUs (for example, 150% means 1.5 cores).
    #[serde(default)]
    vcpu_utilization_percent_total: Option<f64>,
    counters: DomainCounters,
    /// Kept for compatibility with existing Ubuntu dashboards.  This is false for RDP guests.
    #[serde(default)]
    ssh_ready: bool,
    /// Profile-aware readiness for either SSH or RDP.
    #[serde(default)]
    guest_service_ready: bool,
    #[serde(default)]
    guest_connection: String,
    dnat_ready: bool,
    guest_agent_ready: bool,
    telemetry_channel_present: bool,
    last_guest_event_unix_ms: Option<i64>,
    telemetry_fresh: bool,
    last_error: Option<String>,
}

trait OperationalProbe {
    fn domain_state(&self, trap_id: Uuid) -> anyhow::Result<HighDomainState>;
    fn domstats(&self, trap_id: Uuid) -> anyhow::Result<String>;
    fn guest_service_ready(&self, trap_id: Uuid, profile: HighOsProfile) -> bool;
    fn publication_ready(&self, trap_id: Uuid, profile: HighOsProfile) -> bool;
    fn guest_agent_ready(&self, trap_id: Uuid) -> bool;
}

impl OperationalProbe for LibvirtSandboxManager {
    fn domain_state(&self, trap_id: Uuid) -> anyhow::Result<HighDomainState> {
        LibvirtSandboxManager::domain_state(self, trap_id)
    }

    fn domstats(&self, trap_id: Uuid) -> anyhow::Result<String> {
        LibvirtSandboxManager::domstats(self, trap_id)
    }

    fn guest_service_ready(&self, trap_id: Uuid, profile: HighOsProfile) -> bool {
        LibvirtSandboxManager::guest_service_is_ready(self, trap_id, profile)
    }

    fn publication_ready(&self, trap_id: Uuid, profile: HighOsProfile) -> bool {
        self.service_is_published(&crate::sandbox::HighVm::with_profile(
            trap_id,
            PathBuf::new(),
            0,
            profile,
        ))
    }

    fn guest_agent_ready(&self, trap_id: Uuid) -> bool {
        LibvirtSandboxManager::guest_agent_ready(self, trap_id)
    }
}

pub fn start(
    state_dir: &Path,
    agent_id: Uuid,
    max_pending_events: usize,
    operational_interval: Duration,
) -> anyhow::Result<JoinHandle<()>> {
    if operational_interval < Duration::from_secs(5) {
        anyhow::bail!("High operational polling interval must be at least five seconds");
    }
    let high_root = state_dir.join("high");
    let operational_state_dir = state_dir.to_path_buf();
    fs::create_dir_all(&high_root)?;
    let store = Arc::new(Mutex::new(HighTelemetryStore::open(
        state_dir.join("high-telemetry.sqlite"),
        max_pending_events,
    )?));
    Ok(tokio::spawn(async move {
        let operational_store = store.clone();
        tokio::join!(
            discover_channels(high_root, agent_id, store),
            run_operational_monitor(
                operational_state_dir,
                operational_store,
                operational_interval
            )
        );
    }))
}

async fn run_operational_monitor(
    state_dir: PathBuf,
    store: SharedHighTelemetryStore,
    interval: Duration,
) {
    loop {
        let state_dir_for_poll = state_dir.clone();
        let store_for_poll = store.clone();
        if let Err(error) = tokio::task::spawn_blocking(move || {
            collect_operational_snapshots(&state_dir_for_poll, &store_for_poll)
        })
        .await
        .map_err(|error| anyhow::anyhow!("High operational worker panicked: {error}"))
        .and_then(|result| result)
        {
            tracing::warn!(%error, "High operational poll failed");
        }
        tokio::time::sleep(interval).await;
    }
}

fn collect_operational_snapshots(
    state_dir: &Path,
    store: &SharedHighTelemetryStore,
) -> anyhow::Result<()> {
    let manager =
        LibvirtSandboxManager::with_high_root(default_recipe_dir(), state_dir.join("high"));
    collect_operational_snapshots_with_probe(state_dir, store, &manager, now_ms())
}

fn collect_operational_snapshots_with_probe(
    state_dir: &Path,
    store: &SharedHighTelemetryStore,
    probe: &impl OperationalProbe,
    observed: i64,
) -> anyhow::Result<()> {
    let traps = state_dir.join("traps");
    let Ok(entries) = fs::read_dir(&traps) else {
        return Ok(());
    };
    for entry in entries.flatten().filter(|entry| entry.path().is_dir()) {
        let Ok(trap_id) = Uuid::parse_str(&entry.file_name().to_string_lossy()) else {
            continue;
        };
        let manifest_path = entry.path().join("high.json");
        if !manifest_path.is_file() {
            continue;
        }
        let manifest: serde_json::Value = match fs::read(&manifest_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        {
            Some(manifest) => manifest,
            None => continue,
        };
        let Some(profile) = profile_from_manifest(&manifest) else {
            continue;
        };
        let state = probe
            .domain_state(trap_id)
            .unwrap_or(HighDomainState::Unknown);
        let previous_path = state_dir
            .join("high")
            .join(trap_id.to_string())
            .join("operational.json");
        let previous: Option<HighOperationalSnapshot> = fs::read(&previous_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok());
        let running_since = if state == HighDomainState::Running {
            previous
                .as_ref()
                .filter(|snapshot| snapshot.domain_state == "running")
                .and_then(|snapshot| snapshot.running_since_unix_ms)
                .or(Some(observed))
        } else {
            None
        };
        let counters = if state == HighDomainState::Missing {
            DomainCounters::default()
        } else {
            probe
                .domstats(trap_id)
                .map(|output| parse_domstats(&output))
                .unwrap_or_default()
        };
        let last_guest_event = store
            .lock()
            .map_err(|_| anyhow::anyhow!("High telemetry store mutex poisoned"))?
            .last_received_at(trap_id)?;
        let telemetry_channel_present = state_dir
            .join("high")
            .join(trap_id.to_string())
            .join("telemetry.sock")
            .exists();
        let guest_service_ready =
            state == HighDomainState::Running && probe.guest_service_ready(trap_id, profile);
        let snapshot = HighOperationalSnapshot {
            version: 1,
            trap_id,
            observed_at_unix_ms: observed,
            domain_state: domain_state_name(state).into(),
            running_since_unix_ms: running_since,
            uptime_seconds: running_since.map(|started| {
                u64::try_from(observed.saturating_sub(started) / 1_000).unwrap_or_default()
            }),
            vcpu_utilization_percent_total: vcpu_utilization_percent(
                previous.as_ref(),
                observed,
                &counters,
            ),
            counters,
            ssh_ready: matches!(profile.connection, HighGuestConnection::Ssh { .. })
                && guest_service_ready,
            guest_service_ready,
            guest_connection: match profile.connection {
                HighGuestConnection::Ssh { .. } => "ssh",
                HighGuestConnection::Rdp { .. } => "rdp",
            }
            .into(),
            dnat_ready: probe.publication_ready(trap_id, profile),
            guest_agent_ready: state == HighDomainState::Running
                && probe.guest_agent_ready(trap_id),
            telemetry_channel_present,
            last_guest_event_unix_ms: last_guest_event,
            telemetry_fresh: last_guest_event
                .is_some_and(|last| observed.saturating_sub(last) <= 120_000),
            last_error: manifest
                .get("last_error")
                .and_then(|value| value.as_str())
                .map(str::to_owned),
        };
        write_snapshot(&previous_path, &snapshot)?;
    }
    Ok(())
}

fn profile_from_manifest(manifest: &serde_json::Value) -> Option<HighOsProfile> {
    let declared = manifest
        .get("profile")
        .or_else(|| manifest.pointer("/deployment/profile"));
    let profile = match declared {
        Some(value) => serde_json::from_value(value.clone()).ok()?,
        None => HighOsProfile::ubuntu_ssh(),
    };
    is_supported_profile(profile).then_some(profile)
}

fn vcpu_utilization_percent(
    previous: Option<&HighOperationalSnapshot>,
    observed_at_unix_ms: i64,
    counters: &DomainCounters,
) -> Option<f64> {
    let previous = previous.filter(|snapshot| snapshot.domain_state == "running")?;
    let elapsed_ms = observed_at_unix_ms.checked_sub(previous.observed_at_unix_ms)?;
    if elapsed_ms <= 0 {
        return None;
    }
    let used_ns = counters
        .cpu_time_ns?
        .checked_sub(previous.counters.cpu_time_ns?)?;
    let capacity = counters.vcpu_count.or(previous.counters.vcpu_count)? as f64 * 100.0;
    let percent = used_ns as f64 / (elapsed_ms as f64 * 1_000_000.0) * 100.0;
    Some(percent.clamp(0.0, capacity))
}

fn parse_domstats(output: &str) -> DomainCounters {
    let mut counters = DomainCounters::default();
    for line in output.lines() {
        let Some((key, value)) = line.trim().split_once('=') else {
            continue;
        };
        let Ok(value) = value.parse::<u64>() else {
            continue;
        };
        match key {
            "vcpu.current" => counters.vcpu_count = Some(value),
            "cpu.time" => counters.cpu_time_ns = Some(value),
            "balloon.current" => counters.memory_current_kib = Some(value),
            "balloon.usable" => counters.memory_usable_kib = Some(value),
            key if key.starts_with("block.") && key.ends_with(".rd.bytes") => {
                counters.disk_read_bytes = counters.disk_read_bytes.saturating_add(value)
            }
            key if key.starts_with("block.") && key.ends_with(".wr.bytes") => {
                counters.disk_write_bytes = counters.disk_write_bytes.saturating_add(value)
            }
            key if key.starts_with("net.") && key.ends_with(".rx.bytes") => {
                counters.network_rx_bytes = counters.network_rx_bytes.saturating_add(value)
            }
            key if key.starts_with("net.") && key.ends_with(".tx.bytes") => {
                counters.network_tx_bytes = counters.network_tx_bytes.saturating_add(value)
            }
            _ => {}
        }
    }
    counters
}

fn domain_state_name(state: HighDomainState) -> &'static str {
    match state {
        HighDomainState::Missing => "missing",
        HighDomainState::Running => "running",
        HighDomainState::Paused => "paused",
        HighDomainState::Stopped => "stopped",
        HighDomainState::Crashed => "crashed",
        HighDomainState::Unknown => "unknown",
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}

fn write_snapshot(path: &Path, snapshot: &HighOperationalSnapshot) -> anyhow::Result<()> {
    let parent = path.parent().expect("operational snapshot parent");
    fs::create_dir_all(parent)?;
    let temporary = parent.join("operational.json.tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(snapshot)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(temporary, path)?;
    Ok(())
}

async fn discover_channels(high_root: PathBuf, agent_id: Uuid, store: SharedHighTelemetryStore) {
    let mut monitors: HashMap<Uuid, JoinHandle<()>> = HashMap::new();
    loop {
        monitors.retain(|_, monitor| !monitor.is_finished());
        match fs::read_dir(&high_root) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let instance_dir = entry.path();
                    if !instance_dir.is_dir() {
                        continue;
                    }
                    let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                        continue;
                    };
                    let Ok(trap_id) = Uuid::parse_str(&name) else {
                        continue;
                    };
                    monitors.entry(trap_id).or_insert_with(|| {
                        let store = store.clone();
                        tokio::spawn(async move {
                            monitor_channel(instance_dir, trap_id, agent_id, store).await;
                        })
                    });
                }
            }
            Err(error) => {
                tracing::warn!(%error, path = %high_root.display(), "cannot scan High telemetry channels")
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn monitor_channel(
    instance_dir: PathBuf,
    trap_id: Uuid,
    agent_id: Uuid,
    store: SharedHighTelemetryStore,
) {
    let socket = instance_dir.join("telemetry.sock");
    loop {
        if !instance_dir.is_dir() {
            return;
        }
        match fs::symlink_metadata(&socket) {
            Ok(metadata) if !metadata.file_type().is_socket() => {
                tracing::warn!(trap_id = %trap_id, path = %socket.display(), "refusing non-socket High telemetry path");
            }
            Ok(_) => match UnixStream::connect(&socket).await {
                Ok(stream) => {
                    tracing::info!(trap_id = %trap_id, "connected to High VM telemetry channel");
                    if let Err(error) =
                        receive_high_telemetry_connection(stream, trap_id, agent_id, store.clone())
                            .await
                    {
                        tracing::warn!(trap_id = %trap_id, %error, "High telemetry channel closed");
                    }
                }
                Err(error) => {
                    tracing::debug!(trap_id = %trap_id, %error, "High telemetry channel is not ready");
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(trap_id = %trap_id, %error, "cannot inspect High telemetry socket");
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProbe {
        state: HighDomainState,
        stats: String,
        service: bool,
        publication: bool,
        guest_agent: bool,
    }

    impl OperationalProbe for MockProbe {
        fn domain_state(&self, _trap_id: Uuid) -> anyhow::Result<HighDomainState> {
            Ok(self.state)
        }

        fn domstats(&self, _trap_id: Uuid) -> anyhow::Result<String> {
            Ok(self.stats.clone())
        }

        fn guest_service_ready(&self, _trap_id: Uuid, _profile: HighOsProfile) -> bool {
            self.service
        }

        fn publication_ready(&self, _trap_id: Uuid, _profile: HighOsProfile) -> bool {
            self.publication
        }

        fn guest_agent_ready(&self, _trap_id: Uuid) -> bool {
            self.guest_agent
        }
    }

    #[test]
    fn parses_aggregate_libvirt_counters_without_counting_device_count_fields() {
        let metrics = parse_domstats(
            "vcpu.current=2\ncpu.time=120\nballoon.current=2048\nballoon.usable=512\nblock.count=2\nblock.0.rd.bytes=10\nblock.1.rd.bytes=20\nblock.0.wr.bytes=7\nnet.count=1\nnet.0.rx.bytes=100\nnet.0.tx.bytes=200\n",
        );
        assert_eq!(metrics.vcpu_count, Some(2));
        assert_eq!(metrics.cpu_time_ns, Some(120));
        assert_eq!(metrics.memory_current_kib, Some(2048));
        assert_eq!(metrics.disk_read_bytes, 30);
        assert_eq!(metrics.disk_write_bytes, 7);
        assert_eq!(metrics.network_rx_bytes, 100);
        assert_eq!(metrics.network_tx_bytes, 200);
    }

    #[test]
    fn operational_collection_uses_probe_and_derives_vcpu_utilization() {
        let root = std::env::temp_dir().join(format!("hf-high-metrics-{}", Uuid::new_v4()));
        let trap_id = Uuid::new_v4();
        let trap_dir = root.join("traps").join(trap_id.to_string());
        let runtime_dir = root.join("high").join(trap_id.to_string());
        fs::create_dir_all(&trap_dir).unwrap();
        fs::create_dir_all(&runtime_dir).unwrap();
        fs::write(
            trap_dir.join("high.json"),
            r#"{"last_error":"previous failure"}"#,
        )
        .unwrap();
        fs::write(runtime_dir.join("telemetry.sock"), []).unwrap();
        let store = Arc::new(Mutex::new(
            HighTelemetryStore::open(root.join("telemetry.sqlite"), 10).unwrap(),
        ));

        let first = MockProbe {
            state: HighDomainState::Running,
            stats: "vcpu.current=2\ncpu.time=1000000000\nballoon.current=2048\n".into(),
            service: true,
            publication: true,
            guest_agent: true,
        };
        collect_operational_snapshots_with_probe(&root, &store, &first, 10_000).unwrap();
        let second = MockProbe {
            stats: "vcpu.current=2\ncpu.time=1500000000\nballoon.current=2048\n".into(),
            ..first
        };
        collect_operational_snapshots_with_probe(&root, &store, &second, 11_000).unwrap();

        let snapshot: HighOperationalSnapshot =
            serde_json::from_slice(&fs::read(runtime_dir.join("operational.json")).unwrap())
                .unwrap();
        assert_eq!(snapshot.domain_state, "running");
        assert_eq!(snapshot.vcpu_utilization_percent_total, Some(50.0));
        assert!(snapshot.ssh_ready && snapshot.guest_service_ready);
        assert_eq!(snapshot.guest_connection, "ssh");
        assert!(snapshot.dnat_ready && snapshot.guest_agent_ready);
        assert_eq!(snapshot.last_error.as_deref(), Some("previous failure"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn operational_collection_uses_rdp_readiness_for_windows_profiles() {
        let root = std::env::temp_dir().join(format!("hf-high-windows-metrics-{}", Uuid::new_v4()));
        let trap_id = Uuid::new_v4();
        let trap_dir = root.join("traps").join(trap_id.to_string());
        let runtime_dir = root.join("high").join(trap_id.to_string());
        fs::create_dir_all(&trap_dir).unwrap();
        fs::create_dir_all(&runtime_dir).unwrap();
        fs::write(
            trap_dir.join("high.json"),
            serde_json::to_vec(&serde_json::json!({
                "profile": HighOsProfile::windows_rdp()
            }))
            .unwrap(),
        )
        .unwrap();
        let store = Arc::new(Mutex::new(
            HighTelemetryStore::open(root.join("telemetry.sqlite"), 10).unwrap(),
        ));
        let probe = MockProbe {
            state: HighDomainState::Running,
            stats: String::new(),
            service: true,
            publication: true,
            guest_agent: false,
        };

        collect_operational_snapshots_with_probe(&root, &store, &probe, 10_000).unwrap();

        let snapshot: HighOperationalSnapshot =
            serde_json::from_slice(&fs::read(runtime_dir.join("operational.json")).unwrap())
                .unwrap();
        assert!(snapshot.guest_service_ready && snapshot.dnat_ready);
        assert!(!snapshot.ssh_ready);
        assert_eq!(snapshot.guest_connection, "rdp");
        fs::remove_dir_all(root).unwrap();
    }
}
