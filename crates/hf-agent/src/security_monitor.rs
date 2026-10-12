//! Passive host process observation. The eBPF tracepoint tells us an exec happened;
//! procfs and Docker labels provide context, never an automatic poweroff decision.

use std::{collections::HashSet, fs, path::{Path, PathBuf}, process::Stdio, time::{Duration, Instant}};

use anyhow::{Context, Result};
use kazik_protocol::TrapEvent;
use serde_json::json;
use tokio::{io::{AsyncBufReadExt, BufReader}, process::Command, sync::mpsc};
use uuid::Uuid;

use crate::security_policy::{self, ActionDecision, ObservedAction, Operation, TrapTier};

// Record the return value as well as the request. A denied open is evidence of
// an attempt, whereas a successful open of the runtime socket is a local risk.
// Paths here are exact; broader filesystem auditing needs a dedicated sensor.
const EXEC_TRACE: &str = r#"
tracepoint:sched:sched_process_exec { printf("HF_EXEC %d\n", pid); }
tracepoint:syscalls:sys_enter_openat
/str(args->filename) == "/run/docker.sock" || str(args->filename) == "/var/run/docker.sock" || str(args->filename) == "/run/containerd/containerd.sock" || str(args->filename) == "/var/run/containerd/containerd.sock" || str(args->filename) == "/run/podman/podman.sock" || str(args->filename) == "/var/run/podman/podman.sock" || str(args->filename) == "/run/crio/crio.sock" || str(args->filename) == "/var/run/crio/crio.sock" || str(args->filename) == "/etc/shadow" || str(args->filename) == "/etc/passwd" || str(args->filename) == "/proc/1/root" || str(args->filename) == "/proc/1/ns/pid" || str(args->filename) == "/proc/1/ns/mnt" || str(args->filename) == "/var/lib/docker"/
{ @hf_open[tid] = str(args->filename); }
tracepoint:syscalls:sys_exit_openat /@hf_open[tid] != ""/ {
  printf("HF_OPEN %d %d %s\n", pid, args->ret, @hf_open[tid]);
  delete(@hf_open[tid]);
}
tracepoint:syscalls:sys_enter_openat2
/str(args->filename) == "/run/docker.sock" || str(args->filename) == "/var/run/docker.sock" || str(args->filename) == "/run/containerd/containerd.sock" || str(args->filename) == "/var/run/containerd/containerd.sock" || str(args->filename) == "/run/podman/podman.sock" || str(args->filename) == "/var/run/podman/podman.sock" || str(args->filename) == "/run/crio/crio.sock" || str(args->filename) == "/var/run/crio/crio.sock" || str(args->filename) == "/etc/shadow" || str(args->filename) == "/etc/passwd" || str(args->filename) == "/proc/1/root" || str(args->filename) == "/proc/1/ns/pid" || str(args->filename) == "/proc/1/ns/mnt" || str(args->filename) == "/var/lib/docker"/
{ @hf_openat2[tid] = str(args->filename); }
tracepoint:syscalls:sys_exit_openat2 /@hf_openat2[tid] != ""/ {
  printf("HF_OPEN %d %d %s\n", pid, args->ret, @hf_openat2[tid]);
  delete(@hf_openat2[tid]);
}
tracepoint:syscalls:sys_enter_connect {
  if (args->addrlen >= 8) {
    @hf_conn_fd[tid] = args->fd;
    @hf_conn_family[tid] = *(uint16 *)uptr((uint8 *)args->uservaddr);
    @hf_conn_port[tid] = *(uint16 *)uptr((uint8 *)args->uservaddr + 2);
    @hf_conn_a0[tid] = *(uint32 *)uptr((uint8 *)args->uservaddr + 4);
  }
  if (args->addrlen >= 24 && @hf_conn_family[tid] == 10) {
    @hf_conn_a0[tid] = *(uint32 *)uptr((uint8 *)args->uservaddr + 8);
    @hf_conn_a1[tid] = *(uint32 *)uptr((uint8 *)args->uservaddr + 12);
    @hf_conn_a2[tid] = *(uint32 *)uptr((uint8 *)args->uservaddr + 16);
    @hf_conn_a3[tid] = *(uint32 *)uptr((uint8 *)args->uservaddr + 20);
  } else {
    @hf_conn_a1[tid] = 0;
    @hf_conn_a2[tid] = 0;
    @hf_conn_a3[tid] = 0;
  }
}
tracepoint:syscalls:sys_exit_connect /@hf_conn_family[tid] != 0/ {
  printf("HF_CONNECT %d %d %d %u %u %u %u %u %u\n", pid, args->ret,
    @hf_conn_fd[tid], @hf_conn_family[tid], @hf_conn_port[tid], @hf_conn_a0[tid],
    @hf_conn_a1[tid], @hf_conn_a2[tid], @hf_conn_a3[tid]);
  delete(@hf_conn_fd[tid]); delete(@hf_conn_family[tid]); delete(@hf_conn_port[tid]);
  delete(@hf_conn_a0[tid]); delete(@hf_conn_a1[tid]); delete(@hf_conn_a2[tid]); delete(@hf_conn_a3[tid]);
}
tracepoint:sched:sched_process_exit {
  delete(@hf_open[tid]); delete(@hf_openat2[tid]); delete(@hf_conn_fd[tid]); delete(@hf_conn_family[tid]);
  delete(@hf_conn_port[tid]); delete(@hf_conn_a0[tid]); delete(@hf_conn_a1[tid]);
  delete(@hf_conn_a2[tid]); delete(@hf_conn_a3[tid]);
}
"#;
const MAX_NORMAL_EVENTS_PER_MINUTE: usize = 100;
const MAX_SUSPICIOUS_EVENTS_PER_MINUTE: usize = 20;

#[derive(Clone, Debug)]
struct Container {
    trap_id: Uuid,
    container_id: String,
    kind: TrapTier,
    policy_violations: Vec<&'static str>,
    init_pid: Option<u32>,
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
        if hf_core::security::container_in_cgroup(&cgroup, &container.container_id) {
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

#[derive(Clone, Copy)]
enum KernelAction<'a> {
    Execute(u32),
    Open(u32, i64, &'a str),
    Connect(u32, i64, i32, u16, u16, u32, u32, u32, u32),
}

fn parse_kernel_action(line: &str) -> Option<KernelAction<'_>> {
    if let Some(pid) = parse_exec_pid(line) { return Some(KernelAction::Execute(pid)); }
    if let Some(rest) = line.strip_prefix("HF_OPEN ") {
        let (pid, rest) = rest.split_once(' ')?;
        let (result, path) = rest.split_once(' ')?;
        return Some(KernelAction::Open(pid.parse().ok()?, result.parse().ok()?, path));
    }
    if let Some(rest) = line.strip_prefix("HF_CONNECT ") {
        let mut fields = rest.split_whitespace();
        return Some(KernelAction::Connect(
            fields.next()?.parse().ok()?, fields.next()?.parse().ok()?,
            fields.next()?.parse().ok()?, fields.next()?.parse().ok()?, fields.next()?.parse().ok()?,
            fields.next()?.parse().ok()?, fields.next()?.parse().ok()?,
            fields.next()?.parse().ok()?, fields.next()?.parse().ok()?,
        ));
    }
    None
}

#[cfg(test)]
mod action_tests {
    use super::*;
    #[test]
    fn parses_syscall_outcome_without_treating_text_as_a_command() {
        assert!(matches!(parse_kernel_action("HF_OPEN 12 -13 /run/docker.sock"),
            Some(KernelAction::Open(12, -13, "/run/docker.sock"))));
        assert!(matches!(parse_kernel_action("HF_CONNECT 44 -115 3 2 47873 16777343 0 0 0"),
            Some(KernelAction::Connect(44, -115, 3, 2, 47873, 16777343, 0, 0, 0))));
        assert_eq!(format_connect_destination(2, 47873, [16777343, 0, 0, 0]), "network:ipv4:127.0.0.1:443");
        assert_eq!(format_connect_destination(10, 47873, [16777216, 0, 0, 0]), "network:ipv6:[::1]:443");
        assert!(parse_kernel_action("HF_OPEN fake 0 /run/docker.sock").is_none());
    }
}

fn apply_action(observation: &mut SecurityObservation, action: &KernelAction<'_>) {
    let (operation, resource, succeeded, result) = match action {
        KernelAction::Execute(_) => (Operation::Execute, observation.event.payload["exe"].as_str().unwrap_or("").to_owned(), true, 0),
        KernelAction::Open(_, result, path) => (Operation::Open, (*path).to_owned(), *result >= 0, *result),
        KernelAction::Connect(_, result, _fd, family, port, a0, a1, a2, a3) => (
            Operation::Connect,
            format_connect_destination(*family, *port, [*a0, *a1, *a2, *a3]),
            *result == 0 || *result == -115 || *result == -114,
            *result,
        ),
    };
    let tier = if observation.event.payload["trap_tier"] == "middle" { TrapTier::Middle } else { TrapTier::Low };
    let inside_trap = observation.event.payload["subject"] == "trap_process"
        && observation.event.payload["container_id"].as_str().is_some_and(|id|
            observation.event.payload["cgroup"].as_str().is_some_and(|cgroup|
                hf_core::security::container_in_cgroup(cgroup, id)));
    let mut decision = security_policy::evaluate(ObservedAction { tier, operation, resource: &resource, succeeded, inside_trap });
    if observation.event.payload["policy_violations"].as_array().is_some_and(|reasons|
        reasons.iter().any(|reason| reason.as_str().is_some_and(security_policy::dangerous_configuration))) {
        decision = ActionDecision::IsolateTrap;
    }
    let operation_name = match operation { Operation::Execute => "execute", Operation::Open => "open", Operation::Connect => "connect" };
    observation.event.payload["operation"] = json!(operation_name);
    observation.event.payload["resource"] = json!(resource);
    observation.event.payload["result"] = json!(result);
    let outcome = if operation == Operation::Connect && matches!(result, -115 | -114) {
        "in_progress"
    } else if succeeded {
        "succeeded"
    } else {
        "denied_or_failed"
    };
    observation.event.payload["outcome"] = json!(outcome);
    observation.event.payload["policy_decision"] = json!(match decision {
        ActionDecision::Allowed => "allowed", ActionDecision::Alert => "alert", ActionDecision::IsolateTrap => "isolate_trap",
    });
    if !matches!(action, KernelAction::Execute(_)) {
        observation.event.event_type = "security.resource_access".into();
        observation.event.metadata["assessment"] = json!(if decision == ActionDecision::Allowed { "observed" } else { "suspicious_unconfirmed" });
    }
}

fn format_connect_destination(family_raw: u16, port_raw: u16, address_raw: [u32; 4]) -> String {
    // sockaddr family is native-endian; port and address fields are network-endian.
    let family = family_raw;
    let port = u16::from_be(port_raw);
    match family {
        2 => format!("network:ipv4:{}:{port}", std::net::Ipv4Addr::from(u32::from_be(address_raw[0]))),
        10 => {
            let mut octets = [0_u8; 16];
            for (index, word) in address_raw.into_iter().enumerate() {
                octets[index * 4..index * 4 + 4].copy_from_slice(&u32::from_be(word).to_be_bytes());
            }
            format!("network:ipv6:[{}]:{port}", std::net::Ipv6Addr::from(octets))
        }
        _ => format!("network:family-{family}:unknown:{port}"),
    }
}

fn parent_pid(status: &str) -> Option<u32> {
    status.lines().find_map(|line| line.strip_prefix("PPid:")?.trim().parse().ok())
}

fn start_ticks(stat: &str) -> Option<u64> {
    // comm is inside parentheses and may contain spaces or closing parentheses.
    stat.rsplit_once(") ")?.1.split_whitespace().nth(19)?.parse().ok()
}

fn needs_escape_confirmation(location: &Location, host_pid_ns: bool, host_mnt_ns: bool) -> bool {
    matches!(location, Location::Trap(..)) && host_pid_ns && host_mnt_ns
}

async fn docker_output(args: &[&str]) -> Result<std::process::Output> {
    let mut command = Command::new("docker");
    command.args(args).kill_on_drop(true);
    tokio::time::timeout(Duration::from_secs(5), command.output())
        .await.context("Docker inventory timed out")?.context("Docker inventory failed")
}

/// Revisit live processes even if namespace changes happened without another exec.
/// This bounded snapshot supplements the exec trace; it is not full syscall tracing.
async fn scan_candidates(containers: Vec<Container>, tx: &mpsc::Sender<SecurityObservation>) {
    let scan = tokio::task::spawn_blocking(move || -> Result<Vec<SecurityObservation>> {
        let mut found = Vec::new();
        let mut visited = 0;
        for entry in fs::read_dir("/proc")? {
            let Ok(entry) = entry else { continue };
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else { continue };
            visited += 1;
            if visited > 8192 || found.len() >= 128 {
                tracing::warn!("security process snapshot budget exceeded; coverage is degraded");
                break;
            }
            if let Ok(Some(observation)) = process_event(pid, &containers) {
                if observation.candidate.is_some() { found.push(observation); }
            }
        }
        Ok(found)
    }).await;
    match scan {
        Ok(Ok(events)) => for event in events { if tx.send(event).await.is_err() { break; } },
        _ => tracing::warn!("security process snapshot failed; coverage is degraded"),
    }
}

async fn docker_containers(trap_root: &Path) -> Result<Vec<Container>> {
    let output = docker_output(&["ps", "--no-trunc", "--format", "{{.ID}} {{.Label \"com.docker.compose.project\"}}"]).await?;
    anyhow::ensure!(output.status.success(), "docker ps failed: {}", String::from_utf8_lossy(&output.stderr));
    let mut containers = Vec::new();
    for line in String::from_utf8(output.stdout)?.lines() {
        let Some((container_id, project)) = line.split_once(' ') else { continue };
        let Some(id) = project.strip_prefix("hf-") else { continue };
        let Ok(trap_id) = Uuid::parse_str(id) else { continue };
        if container_id.len() != 64 || !container_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        let project_dir = trap_root.join(trap_id.to_string());
        if project_dir.join("compose.yaml").is_file() {
            let kind = if project_dir.join("config.json").is_file() {
                Some(TrapTier::Low)
            } else if project_dir.join("pritvoryashka.json").is_file() {
                Some(TrapTier::Middle)
            } else { None };
            if let Some(kind) = kind {
                let inspect = docker_output(&["inspect", container_id]).await;
                let details = match inspect {
                    Ok(output) if output.status.success() => serde_json::from_slice::<serde_json::Value>(&output.stdout)
                        .ok().and_then(|value| value.as_array().and_then(|items| items.first()).cloned()),
                    _ => None,
                };
                let init_pid = details.as_ref().and_then(|value| value["State"]["Pid"].as_u64())
                    .and_then(|value| u32::try_from(value).ok()).filter(|pid| *pid > 1);
                let policy_violations = details.as_ref()
                    .map(|value| security_policy::violations(kind, value, &project_dir))
                    .unwrap_or_else(|| vec!["Docker inspect response is invalid or unavailable"]);
                if !policy_violations.is_empty() {
                    tracing::warn!(%trap_id, ?policy_violations, "trap container violates its resource policy");
                }
                containers.push(Container { trap_id, container_id: container_id.to_owned(), kind, policy_violations, init_pid });
            }
        }
    }
    Ok(containers)
}

async fn report_config_drift(containers: &[Container], reported: &mut HashSet<Uuid>,
    tx: &mpsc::Sender<SecurityObservation>) {
    reported.retain(|id| containers.iter().any(|container| container.trap_id == *id
        && container.policy_violations.iter().any(|reason| security_policy::dangerous_configuration(reason))));
    let unreported: Vec<_> = containers.iter().filter(|container| !reported.contains(&container.trap_id)
        && container.policy_violations.iter().any(|reason| security_policy::dangerous_configuration(reason))).cloned().collect();
    for container in unreported {
        let Some(pid) = container.init_pid else {
            tracing::warn!(trap_id=%container.trap_id, "dangerous trap configuration has no live init process to attribute");
            continue;
        };
        match process_event(pid, containers) {
            Ok(Some(mut observation)) => {
                observation.event.event_type = "security.policy_violation".into();
                apply_action(&mut observation, &KernelAction::Execute(pid));
                if tx.send(observation).await.is_err() { return; }
                reported.insert(container.trap_id);
            }
            _ => tracing::warn!(trap_id=%container.trap_id, "cannot attribute dangerous trap configuration to its init process"),
        }
    }
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
            let Some(parent) = parent else { return Ok(None) };
            let parent_cgroup = match fs::read_to_string(format!("/proc/{parent}/cgroup")) {
                Ok(value) => value,
                Err(_) => return Ok(None),
            };
            let Location::Trap(trap_id, kind) = classify(&parent_cgroup, containers) else { return Ok(None) };
            (trap_id, kind, true)
        }
        Location::Unknown => return Ok(None),
    };
    let policy_violations = containers.iter()
        .find(|container| container.trap_id == trap_id)
        .map(|container| container.policy_violations.clone())
        .unwrap_or_default();
    let container_id = containers.iter().find(|container| container.trap_id == trap_id)
        .map(|container| container.container_id.as_str()).unwrap_or("");
    let host_pid_ns = fs::read_link("/proc/1/ns/pid")?;
    let host_mnt_ns = fs::read_link("/proc/1/ns/mnt")?;
    let pid_ns = fs::read_link(format!("{proc}/ns/pid"))?;
    let mnt_ns = fs::read_link(format!("{proc}/ns/mnt"))?;
    let shared_host_namespace = pid_ns == host_pid_ns || mnt_ns == host_mnt_ns;
    let exe = fs::read_link(format!("{proc}/exe"))?.to_string_lossy().into_owned();
    let end = fs::read_to_string(format!("{proc}/stat"))?;
    if start.is_none() || start != start_ticks(&end) {
        return Ok(None);
    }
    let candidate = if needs_escape_confirmation(&location, pid_ns == host_pid_ns, mnt_ns == host_mnt_ns) {
        containers.iter().find(|container| container.trap_id == trap_id && hf_core::security::container_in_cgroup(&cgroup, &container.container_id))
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
        .duration_since(std::time::UNIX_EPOCH)?.as_millis() as i64;
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
        payload: json!({"pid":pid, "start_ticks":start, "boot_id":fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(), "trap_tier":match kind { TrapTier::Low => "low", TrapTier::Middle => "middle" }, "subject":if host_exec_from_trap { "host_descendant" } else { "trap_process" }, "container_id":container_id, "parent_pid":parent, "exe":exe, "cgroup":cgroup.trim(), "pid_namespace":pid_ns.to_string_lossy(), "mount_namespace":mnt_ns.to_string_lossy(), "policy_violations":policy_violations}),
        metadata: json!({"source":"hf-agent-ebpf", "assessment":if event_type == "security.process_exec" { "observed" } else { "suspicious_unconfirmed" }}),
    };
    Ok(Some(SecurityObservation { event, candidate }))
}

/// A second observation plus Docker's runtime configuration is required before an
/// emergency decision. Executing an unexpected binary inside its own namespaces
/// remains suspicious, but is not considered an escape.
pub(crate) async fn confirm_escape(candidate: &EscapeCandidate, trap_root: &Path) -> Result<Option<TrapEvent>> {
    tokio::time::sleep(Duration::from_millis(250)).await;
    let project = trap_root.join(candidate.trap_id.to_string());
    if !project.join("compose.yaml").is_file()
        || (!project.join("config.json").is_file() && !project.join("pritvoryashka.json").is_file()) {
        return Ok(None);
    }
    let mut inspect = Command::new("docker");
    inspect.args(["inspect", &candidate.container_id]).kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(3), inspect.output())
        .await.context("Docker inspect timed out")??;
    anyhow::ensure!(output.status.success(), "Docker inspect failed");
    let details: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let Some(container) = details.as_array().and_then(|items| items.first()) else { return Ok(None) };
    let expected_project = format!("hf-{}", candidate.trap_id.simple());
    if container["Config"]["Labels"]["com.docker.compose.project"].as_str() != Some(expected_project.as_str())
        || container["State"]["Running"].as_bool() != Some(true)
        || container["HostConfig"]["Privileged"].as_bool() != Some(false)
        || container["HostConfig"]["PidMode"].as_str() == Some("host")
    {
        return Ok(None);
    }
    let Some(container_pid) = container["State"]["Pid"].as_u64() else { return Ok(None) };
    if container_pid == 0 {
        return Ok(None);
    }
    let host_pid_ns = fs::read_link("/proc/1/ns/pid")?;
    let host_mnt_ns = fs::read_link("/proc/1/ns/mnt")?;
    let container_pid_ns = fs::read_link(format!("/proc/{container_pid}/ns/pid"))?;
    let container_mnt_ns = fs::read_link(format!("/proc/{container_pid}/ns/mnt"))?;
    if container_pid_ns == host_pid_ns || container_mnt_ns == host_mnt_ns
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
    if !hf_core::security::container_in_cgroup(&cgroup, &candidate.container_id)
        || fs::read_link(format!("{proc}/ns/pid"))? != host_pid_ns
        || fs::read_link(format!("{proc}/ns/mnt"))? != host_mnt_ns
    {
        return Ok(None);
    }
    // Repeat lifetime check AFTER reading namespaces to reject PID reuse races.
    if start_ticks(&fs::read_to_string(format!("{proc}/stat"))?) != Some(candidate.start_ticks) {
        return Ok(None);
    }
    let occurred_at_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?.as_millis() as i64;
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
        payload: json!({"pid":candidate.pid, "container_id":candidate.container_id.clone(),
            "cgroup":cgroup.trim(), "start_ticks":candidate.start_ticks, "observations":2,
            "boot_id":fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
            "trap_tier":match container_kind(&project) { TrapTier::Low => "low", TrapTier::Middle => "middle" },
            "pid_namespace":host_pid_ns.to_string_lossy(), "mount_namespace":host_mnt_ns.to_string_lossy(),
            "host_pid_namespace":host_pid_ns.to_string_lossy(), "host_mount_namespace":host_mnt_ns.to_string_lossy(),
            "container_pid_namespace":container_pid_ns.to_string_lossy(), "container_mount_namespace":container_mnt_ns.to_string_lossy()}),
        metadata: json!({"source":"hf-agent-ebpf", "assessment":"confirmed", "validation":"two_samples_proc_docker_v2"}),
    }))
}

fn container_kind(project: &Path) -> TrapTier {
    if project.join("pritvoryashka.json").is_file() { TrapTier::Middle } else { TrapTier::Low }
}

/// Optional monitor: failure never prevents command or telemetry delivery.
/// A bounded channel limits how much process churn can load the main agent loop.
pub async fn run(trap_root: PathBuf, tx: mpsc::Sender<SecurityObservation>) {
    let mut window_started = Instant::now();
    let mut normal_in_window = 0_usize;
    let mut suspicious_in_window = 0_usize;
    let mut reported_limit = false;
    let mut reported_config = HashSet::new();
    loop {
        let mut containers = match docker_containers(&trap_root).await {
            Ok(containers) => containers,
            Err(error) => {
                tracing::warn!(%error, "security monitor cannot read Docker labels; retrying");
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
        };
        report_config_drift(&containers, &mut reported_config, &tx).await;
        scan_candidates(containers.clone(), &tx).await;
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
        let Some(stdout) = child.stdout.take() else { continue };
        let mut lines = BufReader::new(stdout).lines();
        let mut refresh = tokio::time::interval(Duration::from_secs(10));
        loop {
            tokio::select! {
                _ = refresh.tick() => {
                    match docker_containers(&trap_root).await {
                        Ok(latest) => {
                            containers = latest;
                            report_config_drift(&containers, &mut reported_config, &tx).await;
                            scan_candidates(containers.clone(), &tx).await;
                        },
                        Err(error) => tracing::warn!(%error, "security monitor Docker inventory refresh failed"),
                    }
                }
                line = lines.next_line() => match line {
                    Ok(Some(line)) => {
                        let Some(action) = parse_kernel_action(&line) else { continue };
                        let pid = match action { KernelAction::Execute(pid) | KernelAction::Open(pid, ..) | KernelAction::Connect(pid, ..) => pid };
                        match process_event(pid, &containers) {
                            Ok(Some(mut observation)) => {
                                apply_action(&mut observation, &action);
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
        assert_eq!(start_ticks("12 (a b) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 42"), Some(42));
    }

    #[test]
    fn only_exact_known_container_is_attributed_to_trap() {
        let trap_id = Uuid::new_v4();
        let id = "a".repeat(64);
        let containers = vec![Container { trap_id, container_id: id.clone(), kind: TrapTier::Low, policy_violations: Vec::new(), init_pid: None }];
        assert_eq!(classify(&format!("0::/system.slice/docker-{id}.scope"), &containers), Location::Trap(trap_id, TrapTier::Low));
        assert_eq!(classify("0::/system.slice/ssh.service", &containers), Location::Host);
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
