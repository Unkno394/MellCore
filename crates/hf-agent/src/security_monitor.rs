//! Passive host process observation. The eBPF tracepoint tells us an exec happened;
//! procfs and Docker labels provide context, never an automatic poweroff decision.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use kazik_protocol::TrapEvent;
use serde_json::json;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
    sync::mpsc,
};
use uuid::Uuid;

use crate::security_policy::{self, TrapTier};

const EXEC_TRACE: &str = r#"tracepoint:sched:sched_process_exec { printf("HF_EXEC %d\n", pid); }"#;
const MAX_NORMAL_EVENTS_PER_MINUTE: usize = 100;
const MAX_SUSPICIOUS_EVENTS_PER_MINUTE: usize = 20;

#[derive(Clone, Debug)]
struct Container {
    trap_id: Uuid,
    container_id: String,
    kind: TrapTier,
    policy_violations: Vec<&'static str>,
}

#[derive(Clone, Debug)]
pub(crate) struct EscapeCandidate {
    pid: u32,
    start_ticks: u64,
    trap_id: Uuid,
    container_id: String,
}

pub(crate) struct SecurityObservation {
    pub event: TrapEvent,
    pub candidate: Option<EscapeCandidate>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Location {
    Trap(Uuid, TrapTier),
    Host,
    Unknown,
}

fn classify(cgroup: &str, containers: &[Container]) -> Location {
    for container in containers {
        if cgroup.contains(&container.container_id) {
            return Location::Trap(container.trap_id, container.kind);
        }
    }
    if cgroup.lines().any(|line| line.starts_with("0::/")) {
        Location::Host
    } else {
        Location::Unknown
    }
}

fn parse_exec_pid(line: &str) -> Option<u32> {
    line.strip_prefix("HF_EXEC ")?.trim().parse().ok()
}

fn parent_pid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:")?.trim().parse().ok())
}

fn start_ticks(stat: &str) -> Option<u64> {
    // comm is inside parentheses and may contain spaces or closing parentheses.
    stat.rsplit_once(") ")?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

fn needs_escape_confirmation(location: &Location, host_pid_ns: bool, host_mnt_ns: bool) -> bool {
    matches!(location, Location::Trap(..)) && host_pid_ns && host_mnt_ns
}

async fn docker_containers(trap_root: &Path) -> Result<Vec<Container>> {
    let output = Command::new("docker")
        .args([
            "ps",
            "--no-trunc",
            "--format",
            "{{.ID}} {{.Label \"com.docker.compose.project\"}}",
        ])
        .output()
        .await
        .context("list running Docker containers")?;
    anyhow::ensure!(
        output.status.success(),
        "docker ps failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut containers = Vec::new();
    for line in String::from_utf8(output.stdout)?.lines() {
        let Some((container_id, project)) = line.split_once(' ') else {
            continue;
        };
        let Some(id) = project.strip_prefix("hf-") else {
            continue;
        };
        let Ok(trap_id) = Uuid::parse_str(id) else {
            continue;
        };
        if container_id.len() != 64 || !container_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        let project_dir = trap_root.join(trap_id.to_string());
        if project_dir.join("compose.yaml").is_file() {
            let kind = if project_dir.join("config.json").is_file() {
                Some(TrapTier::Low)
            } else if project_dir.join("pritvoryashka.json").is_file() {
                Some(TrapTier::Middle)
            } else {
                None
            };
            if let Some(kind) = kind {
                let inspect = Command::new("docker")
                    .args(["inspect", container_id])
                    .output()
                    .await;
                let policy_violations = match inspect {
                    Ok(output) if output.status.success() => serde_json::from_slice::<
                        serde_json::Value,
                    >(&output.stdout)
                    .ok()
                    .and_then(|value| value.as_array().and_then(|items| items.first()).cloned())
                    .map(|value| security_policy::violations(kind, &value, &project_dir))
                    .unwrap_or_else(|| vec!["Docker inspect response is invalid"]),
                    Ok(_) => vec!["Docker inspect failed"],
                    Err(_) => vec!["Docker inspect could not run"],
                };
                if !policy_violations.is_empty() {
                    tracing::warn!(%trap_id, ?policy_violations, "trap container violates its resource policy");
                }
                containers.push(Container {
                    trap_id,
                    container_id: container_id.to_owned(),
                    kind,
                    policy_violations,
                });
            }
        }
    }
    Ok(containers)
}

fn process_event(pid: u32, containers: &[Container]) -> Result<Option<SecurityObservation>> {
    let proc = format!("/proc/{pid}");
    let start = match fs::read_to_string(format!("{proc}/stat")) {
        Ok(stat) => start_ticks(&stat),
        Err(_) => return Ok(None),
    };
    // A short-lived process may already be gone. Losing this event is why this
    // monitor cannot be used as the sole escape detector or shutdown authority.
    let cgroup = match fs::read_to_string(format!("{proc}/cgroup")) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let location = classify(&cgroup, containers);
    let parent = if location == Location::Host {
        let status = fs::read_to_string(format!("{proc}/status"))?;
        parent_pid(&status)
    } else {
        None
    };
    let (trap_id, kind, host_exec_from_trap) = match &location {
        Location::Trap(trap_id, kind) => (*trap_id, *kind, false),
        Location::Host => {
            let Some(parent) = parent else {
                return Ok(None);
            };
            let parent_cgroup = match fs::read_to_string(format!("/proc/{parent}/cgroup")) {
                Ok(value) => value,
                Err(_) => return Ok(None),
            };
            let Location::Trap(trap_id, kind) = classify(&parent_cgroup, containers) else {
                return Ok(None);
            };
            (trap_id, kind, true)
        }
        Location::Unknown => return Ok(None),
    };
    let policy_violations = containers
        .iter()
        .find(|container| container.trap_id == trap_id)
        .map(|container| container.policy_violations.clone())
        .unwrap_or_default();
    let host_pid_ns = fs::read_link("/proc/1/ns/pid")?;
    let host_mnt_ns = fs::read_link("/proc/1/ns/mnt")?;
    let pid_ns = fs::read_link(format!("{proc}/ns/pid"))?;
    let mnt_ns = fs::read_link(format!("{proc}/ns/mnt"))?;
    let shared_host_namespace = pid_ns == host_pid_ns || mnt_ns == host_mnt_ns;
    let exe = fs::read_link(format!("{proc}/exe"))?
        .to_string_lossy()
        .into_owned();
    let end = fs::read_to_string(format!("{proc}/stat"))?;
    if start.is_none() || start != start_ticks(&end) {
        return Ok(None);
    }
    let candidate =
        if needs_escape_confirmation(&location, pid_ns == host_pid_ns, mnt_ns == host_mnt_ns) {
            containers
                .iter()
                .find(|container| {
                    container.trap_id == trap_id && cgroup.contains(&container.container_id)
                })
                .map(|container| EscapeCandidate {
                    pid,
                    start_ticks: start.expect("checked above"),
                    trap_id,
                    container_id: container.container_id.clone(),
                })
        } else {
            None
        };
    let event_type = if host_exec_from_trap {
        "security.host_exec_from_trap"
    } else if !policy_violations.is_empty() {
        "security.policy_violation"
    } else if shared_host_namespace {
        "security.namespace_mismatch"
    } else if !kind.allowed_executable(&exe) {
        "security.unexpected_executable"
    } else {
        "security.process_exec"
    };
    let occurred_at_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as i64;
    let event = TrapEvent {
        event_id: Uuid::new_v4(),
        trap_id,
        session_id: None,
        source_sequence_no: None,
        occurred_at_unix_ms,
        event_type: event_type.into(),
        source_ip: None,
        source_port: None,
        destination_port: None,
        protocol: "local".into(),
        service_type: "host_monitor".into(),
        payload: json!({"pid":pid, "parent_pid":parent, "exe":exe, "cgroup":cgroup.trim(), "pid_namespace":pid_ns.to_string_lossy(), "mount_namespace":mnt_ns.to_string_lossy(), "policy_violations":policy_violations}),
        metadata: json!({"source":"hf-agent-ebpf", "assessment":if event_type == "security.process_exec" { "observed" } else { "suspicious_unconfirmed" }}),
    };
    Ok(Some(SecurityObservation { event, candidate }))
}

/// A second observation plus Docker's runtime configuration is required before an
/// emergency decision. Executing an unexpected binary inside its own namespaces
/// remains suspicious, but is not considered an escape.
pub(crate) async fn confirm_escape(
    candidate: &EscapeCandidate,
    trap_root: &Path,
) -> Result<Option<TrapEvent>> {
    tokio::time::sleep(Duration::from_millis(250)).await;
    let project = trap_root.join(candidate.trap_id.to_string());
    if !project.join("compose.yaml").is_file() {
        return Ok(None);
    }
    let mut inspect = Command::new("docker");
    inspect.args(["inspect", &candidate.container_id]);
    let output = tokio::time::timeout(Duration::from_secs(3), inspect.output())
        .await
        .context("Docker inspect timed out")??;
    anyhow::ensure!(output.status.success(), "Docker inspect failed");
    let details: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let Some(container) = details.as_array().and_then(|items| items.first()) else {
        return Ok(None);
    };
    let expected_project = format!("hf-{}", candidate.trap_id.simple());
    if container["Config"]["Labels"]["com.docker.compose.project"].as_str()
        != Some(expected_project.as_str())
        || container["State"]["Running"].as_bool() != Some(true)
        || !security_policy::violations(container_kind(&project), container, &project).is_empty()
    {
        return Ok(None);
    }
    let Some(container_pid) = container["State"]["Pid"].as_u64() else {
        return Ok(None);
    };
    if container_pid == 0 {
        return Ok(None);
    }
    let host_pid_ns = fs::read_link("/proc/1/ns/pid")?;
    let host_mnt_ns = fs::read_link("/proc/1/ns/mnt")?;
    if fs::read_link(format!("/proc/{container_pid}/ns/pid"))? == host_pid_ns
        || fs::read_link(format!("/proc/{container_pid}/ns/mnt"))? == host_mnt_ns
    {
        // The container itself is not isolated as expected; report it separately
        // rather than treating its normal process as a successful escape.
        return Ok(None);
    }
    let proc = format!("/proc/{}", candidate.pid);
    let stat = match fs::read_to_string(format!("{proc}/stat")) {
        Ok(stat) => stat,
        Err(_) => return Ok(None),
    };
    if start_ticks(&stat) != Some(candidate.start_ticks) {
        return Ok(None);
    }
    let cgroup = fs::read_to_string(format!("{proc}/cgroup"))?;
    if !cgroup.contains(&candidate.container_id)
        || fs::read_link(format!("{proc}/ns/pid"))? != host_pid_ns
        || fs::read_link(format!("{proc}/ns/mnt"))? != host_mnt_ns
    {
        return Ok(None);
    }
    let occurred_at_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as i64;
    Ok(Some(TrapEvent {
        event_id: Uuid::new_v4(),
        trap_id: candidate.trap_id,
        session_id: None,
        source_sequence_no: None,
        occurred_at_unix_ms,
        event_type: "security.escape_confirmed".into(),
        source_ip: None,
        source_port: None,
        destination_port: None,
        protocol: "local".into(),
        service_type: "host_monitor".into(),
        payload: json!({"pid":candidate.pid, "container_id":candidate.container_id.clone(), "cgroup":cgroup.trim(), "start_ticks":candidate.start_ticks}),
        metadata: json!({"source":"hf-agent-ebpf", "assessment":"confirmed", "validation":"second_proc_sample_and_docker_inspect"}),
    }))
}

fn container_kind(project: &Path) -> TrapTier {
    if project.join("pritvoryashka.json").is_file() {
        TrapTier::Middle
    } else {
        TrapTier::Low
    }
}

/// Optional monitor: failure never prevents command or telemetry delivery.
/// A bounded channel limits how much process churn can load the main agent loop.
pub async fn run(trap_root: PathBuf, tx: mpsc::Sender<SecurityObservation>) {
    let mut window_started = Instant::now();
    let mut normal_in_window = 0_usize;
    let mut suspicious_in_window = 0_usize;
    let mut reported_limit = false;
    loop {
        let mut containers = match docker_containers(&trap_root).await {
            Ok(containers) => containers,
            Err(error) => {
                tracing::warn!(%error, "security monitor cannot read Docker labels; retrying");
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
        };
        let mut child = match Command::new("bpftrace")
            .args(["-q", "-B", "none", "-e", EXEC_TRACE])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
        {
            Ok(child) => child,
            Err(error) => {
                tracing::warn!(%error, "security monitor cannot start bpftrace; retrying");
                tokio::time::sleep(Duration::from_secs(30)).await;
                continue;
            }
        };
        let Some(stdout) = child.stdout.take() else {
            continue;
        };
        let mut lines = BufReader::new(stdout).lines();
        let mut refresh = tokio::time::interval(Duration::from_secs(10));
        loop {
            tokio::select! {
                _ = refresh.tick() => {
                    match docker_containers(&trap_root).await {
                        Ok(latest) => containers = latest,
                        Err(error) => tracing::warn!(%error, "security monitor Docker inventory refresh failed"),
                    }
                }
                line = lines.next_line() => match line {
                    Ok(Some(line)) => {
                        let Some(pid) = parse_exec_pid(&line) else { continue };
                        match process_event(pid, &containers) {
                            Ok(Some(observation)) => {
                                if observation.candidate.is_some() {
                                    // A strong escape candidate must not be discarded by the
                                    // ordinary telemetry budget. Backpressure this rare path.
                                    if tx.send(observation).await.is_err() { return; }
                                    continue;
                                }
                                let event = &observation.event;
                                if window_started.elapsed() >= Duration::from_secs(60) {
                                    window_started = Instant::now();
                                    normal_in_window = 0;
                                    suspicious_in_window = 0;
                                    reported_limit = false;
                                }
                                let suspicious = event.event_type != "security.process_exec";
                                let at_limit = if suspicious {
                                    suspicious_in_window >= MAX_SUSPICIOUS_EVENTS_PER_MINUTE
                                } else {
                                    normal_in_window >= MAX_NORMAL_EVENTS_PER_MINUTE
                                };
                                if at_limit {
                                    if !reported_limit {
                                        tracing::warn!("security telemetry rate limit reached; further process events dropped for this minute");
                                        reported_limit = true;
                                    }
                                    continue;
                                }
                                if suspicious {
                                    tracing::warn!(%pid, trap_id = %event.trap_id, event_type = %event.event_type, "suspicious process execution; manual validation required");
                                }
                                if tx.try_send(observation).is_err() {
                                    if !reported_limit {
                                        tracing::warn!("security event channel full; process events dropped");
                                        reported_limit = true;
                                    }
                                } else if suspicious {
                                    suspicious_in_window += 1;
                                } else {
                                    normal_in_window += 1;
                                }
                            }
                            Ok(None) => {}
                            Err(error) => tracing::debug!(%pid, %error, "could not inspect short-lived process"),
                        }
                    }
                    Ok(None) => break,
                    Err(error) => {
                        tracing::warn!(%error, "eBPF process monitor output failed");
                        break;
                    }
                }
            }
        }
        let _ = child.wait().await;
        tracing::warn!("eBPF process monitor stopped; restarting");
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_line_requires_exact_prefix() {
        assert_eq!(parse_exec_pid("HF_EXEC 123"), Some(123));
        assert_eq!(parse_exec_pid("Attaching 1 probe"), None);
        assert_eq!(parse_exec_pid("HF_EXEC no-pid"), None);
        assert_eq!(parent_pid("Name:\ttest\nPPid:\t42\n"), Some(42));
        assert_eq!(
            start_ticks("12 (a b) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 42"),
            Some(42)
        );
    }

    #[test]
    fn only_exact_known_container_is_attributed_to_trap() {
        let trap_id = Uuid::new_v4();
        let id = "a".repeat(64);
        let containers = vec![Container {
            trap_id,
            container_id: id.clone(),
            kind: TrapTier::Low,
            policy_violations: Vec::new(),
        }];
        assert_eq!(
            classify(&format!("0::/system.slice/docker-{id}.scope"), &containers),
            Location::Trap(trap_id, TrapTier::Low)
        );
        assert_eq!(
            classify("0::/system.slice/ssh.service", &containers),
            Location::Host
        );
        assert_eq!(classify("9:memory:/", &containers), Location::Unknown);
        assert!(TrapTier::Low.allowed_executable("/usr/local/bin/honeyforge-low"));
        assert!(!TrapTier::Low.allowed_executable("/bin/bash"));
        assert!(TrapTier::Middle.allowed_executable("/usr/bin/ssh-keygen"));
        let trap = Location::Trap(trap_id, TrapTier::Middle);
        assert!(!needs_escape_confirmation(&trap, true, false));
        assert!(!needs_escape_confirmation(&trap, false, true));
        assert!(!needs_escape_confirmation(&Location::Host, true, true));
        assert!(needs_escape_confirmation(&trap, true, true));
    }
}
