//! Evidence shape shared by the observer, emergency response and Center.
//! This validates an authenticated observer report, not the honesty of a root-
//! compromised agent. Command text and honeypot simulation are never evidence.
use serde_json::Value;

pub fn container_in_cgroup(cgroup: &str, id: &str) -> bool {
    id.len() == 64
        && id.bytes().all(|b| b.is_ascii_hexdigit())
        && cgroup.lines().any(|line| {
            line.split('/')
                .any(|part| part == id || part == format!("docker-{id}.scope"))
        })
}

pub fn container_runtime_socket(path: &str) -> bool {
    matches!(
        path,
        "/run/docker.sock"
            | "/var/run/docker.sock"
            | "/run/containerd/containerd.sock"
            | "/var/run/containerd/containerd.sock"
            | "/run/podman/podman.sock"
            | "/var/run/podman/podman.sock"
            | "/run/crio/crio.sock"
            | "/var/run/crio/crio.sock"
    )
}

pub fn confirmed_escape(kind: &str, service: &str, protocol: &str, p: &Value, m: &Value) -> bool {
    if kind != "security.escape_confirmed"
        || service != "host_monitor"
        || protocol != "local"
        || m["source"] != "hf-agent-ebpf"
        || m["assessment"] != "confirmed"
        || m["validation"] != "two_samples_proc_docker_v2"
        || !matches!(p["trap_tier"].as_str(), Some("low" | "middle"))
        || p["observations"].as_u64() != Some(2)
        || !p["pid"].as_u64().is_some_and(|v| v > 1)
        || !p["start_ticks"].as_u64().is_some_and(|v| v > 0)
        || p["boot_id"]
            .as_str()
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .is_none()
    {
        return false;
    }
    let Some(id) = p["container_id"].as_str() else {
        return false;
    };
    let Some(cgroup) = p["cgroup"].as_str() else {
        return false;
    };
    if !container_in_cgroup(cgroup, id) {
        return false;
    }
    ["pid", "mount"].iter().all(|ns| {
        let process_key = format!("{ns}_namespace");
        let host_key = format!("host_{ns}_namespace");
        let container_key = format!("container_{ns}_namespace");
        let process = p[process_key.as_str()].as_str();
        let host = p[host_key.as_str()].as_str();
        let container = p[container_key.as_str()].as_str();
        process.is_some_and(|v| !v.is_empty())
            && process == host
            && container.is_some_and(|v| !v.is_empty())
            && container != host
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn full_evidence_is_required_and_high_never_confirms() {
        let mut p = json!({"pid":123,"start_ticks":456,"boot_id":"10000000-0000-4000-8000-000000000001",
                "container_id":"a".repeat(64),"cgroup":format!("0::/docker/{}", "a".repeat(64)),
                "trap_tier":"low","observations":2,
                "pid_namespace":"pid:[1]","host_pid_namespace":"pid:[1]","container_pid_namespace":"pid:[2]",
                "mount_namespace":"mnt:[1]","host_mount_namespace":"mnt:[1]","container_mount_namespace":"mnt:[2]"});
        let m = json!({"source":"hf-agent-ebpf","assessment":"confirmed","validation":"two_samples_proc_docker_v2"});
        assert!(confirmed_escape(
            "security.escape_confirmed",
            "host_monitor",
            "local",
            &p,
            &m
        ));
        p["trap_tier"] = serde_json::json!("high");
        assert!(!confirmed_escape(
            "security.escape_confirmed",
            "host_monitor",
            "local",
            &p,
            &m
        ));
        p["trap_tier"] = serde_json::json!("middle");
        p["container_pid_namespace"] = p["host_pid_namespace"].clone();
        assert!(!confirmed_escape(
            "security.escape_confirmed",
            "host_monitor",
            "local",
            &p,
            &m
        ));
    }
    #[test]
    fn cgroup_attribution_is_a_complete_component() {
        let id = "a".repeat(64);
        assert!(container_in_cgroup(
            &format!("0::/system.slice/docker-{id}.scope"),
            &id
        ));
        assert!(!container_in_cgroup(&format!("0::/fake-{id}-suffix"), &id));
        assert!(!container_in_cgroup("0::/", ""));
    }
    #[test]
    fn labels_alone_are_not_proof_and_high_is_excluded() {
        let m = serde_json::json!({"source":"hf-agent-ebpf","assessment":"confirmed","validation":"two_samples_proc_docker_v2"});
        assert!(!confirmed_escape(
            "security.escape_confirmed",
            "host_monitor",
            "local",
            &serde_json::json!({"trap_tier":"high"}),
            &m
        ));
        assert!(!confirmed_escape(
            "security.escape_confirmed",
            "host_monitor",
            "local",
            &serde_json::json!({}),
            &m
        ));
    }

    #[test]
    fn recognizes_common_container_runtime_sockets_only() {
        assert!(container_runtime_socket("/run/docker.sock"));
        assert!(container_runtime_socket("/var/run/podman/podman.sock"));
        assert!(container_runtime_socket("/run/crio/crio.sock"));
        assert!(!container_runtime_socket("/run/docker.sock.backup"));
        assert!(!container_runtime_socket("/tmp/docker.sock"));
    }
}
