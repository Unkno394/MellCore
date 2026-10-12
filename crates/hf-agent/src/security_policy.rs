//! Resource and runtime policy for the supported Low and Middle trap containers.
//!
//! This is a containment policy, not a command-kill policy: Middle shell commands
//! run against its in-memory virtual filesystem and are audited by the trap itself.

use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TrapTier {
    Low,
    Middle,
}

/// Decision about an observed host syscall. These are audit decisions, not
/// proof that a container crossed into the host namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ActionDecision { Allowed, Alert, IsolateTrap }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Operation { Execute, Open, Connect }

#[derive(Clone, Copy)]
pub(crate) struct ObservedAction<'a> {
    pub tier: TrapTier,
    pub operation: Operation,
    pub resource: &'a str,
    pub succeeded: bool,
    pub inside_trap: bool,
}

pub(crate) fn evaluate(action: ObservedAction<'_>) -> ActionDecision {
    if !action.inside_trap { return ActionDecision::Alert; }
    match action.operation {
        Operation::Execute if action.tier.allowed_executable(action.resource) => ActionDecision::Allowed,
        Operation::Execute => ActionDecision::Alert,
        Operation::Open if hf_core::security::container_runtime_socket(action.resource) => {
            if action.succeeded { ActionDecision::IsolateTrap } else { ActionDecision::Alert }
        }
        Operation::Open if action.resource.starts_with("/host/")
            || matches!(action.resource, "/etc/shadow" | "/etc/passwd" | "/proc/1/root"
                | "/proc/1/ns/pid" | "/proc/1/ns/mnt" | "/var/lib/docker") => ActionDecision::Alert,
        // The honeypots are inbound listeners. Outbound attempts need review,
        // but a connection alone is not proof of host compromise.
        Operation::Connect if action.succeeded => ActionDecision::Alert,
        _ => ActionDecision::Allowed,
    }
}

pub(crate) fn dangerous_configuration(reason: &str) -> bool {
    matches!(reason,
        "privileged mode is enabled" | "host PID namespace is enabled"
        | "host network namespace is enabled" | "host IPC namespace is enabled"
        | "host user or cgroup namespace is explicitly shared"
        | "namespace sharing with another container is forbidden"
        | "additional capabilities or device access are forbidden"
        | "unconfined seccomp or LSM profile is forbidden"
        | "mount set differs from the tier allowlist")
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ResourceLimits {
    pub memory_bytes: u64,
    pub nano_cpus: u64,
    pub pids: u64,
    pub nofile: u64,
}

impl TrapTier {
    pub(crate) fn limits(self) -> ResourceLimits {
        match self {
            // One SSH banner listener; no shell or child processes are expected.
            Self::Low => ResourceLimits {
                memory_bytes: 128 * 1024 * 1024,
                nano_cpus: 500_000_000,
                pids: 64,
                nofile: 256,
            },
            // Rust SSH server, async workers, health listener and virtual shell.
            Self::Middle => ResourceLimits {
                memory_bytes: 512 * 1024 * 1024,
                nano_cpus: 1_000_000_000,
                pids: 256,
                nofile: 1024,
            },
        }
    }

    pub(crate) fn allowed_executable(self, raw: &str) -> bool {
        // A deleted executable has lost its on-disk identity; require review.
        let path = raw;
        match self {
            Self::Low => matches!(
                path,
                "/usr/local/bin/honeyforge-low"
                    | "/usr/libexec/docker-init"
                    | "/usr/bin/docker-init"
                    | "/sbin/docker-init"
            ),
            Self::Middle => matches!(
                path,
                "/usr/local/bin/docker-entrypoint"
                    | "/usr/local/bin/pritvoryashka"
                    | "/usr/libexec/docker-init"
                    | "/usr/bin/docker-init"
                    | "/sbin/docker-init"
                    | "/bin/sh"
                    | "/bin/dash"
                    | "/usr/bin/dash"
                    | "/usr/bin/mkdir"
                    | "/bin/mkdir"
                    | "/usr/bin/ssh-keygen"
                    | "/bin/ssh-keygen"
            ),
        }
    }
}

/// Returns policy violations in a Docker inspect response. Used before trusting a
/// host-namespace process as an escape from a known trap.
pub(crate) fn violations(
    tier: TrapTier,
    inspect: &Value,
    project_dir: &std::path::Path,
) -> Vec<&'static str> {
    let limits = tier.limits();
    let host = &inspect["HostConfig"];
    let mounts = inspect["Mounts"].as_array();
    let expected_project = project_dir.to_string_lossy();
    let expected_mounts: &[(&str, bool)] = match tier {
        TrapTier::Low => &[("/etc/honeyforge/config.json", false)],
        TrapTier::Middle => &[
            ("/etc/honeyforge/pritvoryashka.json", false),
            ("/var/lib/pritvoryashka", true),
        ],
    };
    let mut result = Vec::new();

    if host["Privileged"].as_bool() != Some(false) { result.push("privileged mode is enabled"); }
    if host["PidMode"].as_str() == Some("host") { result.push("host PID namespace is enabled"); }
    if host["NetworkMode"].as_str() == Some("host") { result.push("host network namespace is enabled"); }
    if host["IpcMode"].as_str() == Some("host") { result.push("host IPC namespace is enabled"); }
    for field in ["PidMode", "IpcMode", "NetworkMode"] {
        if host[field].as_str().is_some_and(|v| v.starts_with("container:")) {
            result.push("namespace sharing with another container is forbidden");
        }
    }
    if host["UsernsMode"].as_str() == Some("host") || host["CgroupnsMode"].as_str() == Some("host") {
        result.push("host user or cgroup namespace is explicitly shared");
    }
    for field in ["CapAdd", "Devices", "DeviceRequests", "DeviceCgroupRules"] {
        if !host[field].is_null() && !host[field].as_array().is_some_and(|v| v.is_empty()) {
            result.push("additional capabilities or device access are forbidden");
        }
    }
    if host["SecurityOpt"].as_array().is_some_and(|opts| opts.iter().any(|v|
        v.as_str().is_some_and(|v| v.contains("unconfined")))) {
        result.push("unconfined seccomp or LSM profile is forbidden");
    }
    if tier == TrapTier::Low
        && !matches!(
            inspect["Config"]["User"].as_str(),
            Some("65532" | "65532:65532")
        )
    {
        result.push("Low container is not running as image UID 65532");
    }
    // Middle currently runs as UID 0 inside its namespaces to create/read its
    // persistent host key; CapDrop=ALL and no-new-privileges keep that distinct
    // from privileged mode or host root.
    if host["ReadonlyRootfs"].as_bool() != Some(true) {
        result.push("root filesystem is writable");
    }
    if !host["CapDrop"]
        .as_array()
        .is_some_and(|caps| caps.iter().any(|cap| cap.as_str() == Some("ALL")))
    {
        result.push("not all Linux capabilities are dropped");
    }
    if !host["SecurityOpt"].as_array().is_some_and(|opts| {
        opts.iter().any(|opt| {
            matches!(
                opt.as_str(),
                Some("no-new-privileges") | Some("no-new-privileges:true")
            )
        })
    }) {
        result.push("no-new-privileges is missing");
    }
    if host["Memory"]
        .as_u64()
        .is_none_or(|value| value == 0 || value > limits.memory_bytes)
    {
        result.push("memory limit is missing or exceeds tier policy");
    }
    if host["NanoCpus"]
        .as_u64()
        .is_none_or(|value| value == 0 || value > limits.nano_cpus)
    {
        result.push("CPU limit is missing or exceeds tier policy");
    }
    if host["PidsLimit"]
        .as_i64()
        .is_none_or(|value| value <= 0 || value as u64 > limits.pids)
    {
        result.push("PID limit is missing or exceeds tier policy");
    }

    let has_nofile_limit = host["Ulimits"].as_array().is_some_and(|ulimits| {
        ulimits.iter().any(|item| {
            item["Name"].as_str() == Some("nofile")
                && item["Soft"]
                    .as_u64()
                    .is_some_and(|value| value > 0 && value <= limits.nofile)
                && item["Hard"]
                    .as_u64()
                    .is_some_and(|value| value > 0 && value <= limits.nofile)
        })
    });
    if !has_nofile_limit {
        result.push("nofile limit is missing or exceeds tier policy");
    }

    match mounts {
        Some(mounts) if mounts.len() == expected_mounts.len() => {
            for (destination, writable) in expected_mounts {
                let valid = mounts.iter().any(|mount| {
                    let source = mount["Source"].as_str().unwrap_or("");
                    let destination_ok = mount["Destination"].as_str() == Some(*destination);
                    let write_ok = mount["RW"].as_bool() == Some(*writable);
                    let filename = match *destination {
                        "/etc/honeyforge/config.json" => "config.json",
                        "/etc/honeyforge/pritvoryashka.json" => "pritvoryashka.json",
                        _ => "runtime",
                    };
                    let source_ok = source == format!("{expected_project}/{filename}");
                    let propagation_ok = matches!(mount["Propagation"].as_str(), Some("rprivate" | "private"));
                    destination_ok && write_ok && source_ok && propagation_ok && mount["Type"] == "bind"
                });
                if !valid {
                    result.push("mount set differs from the tier allowlist");
                    break;
                }
            }
        }
        _ => result.push("mount set differs from the tier allowlist"),
    }

    let port_bindings = &host["PortBindings"];
    let expected_container_port = match tier {
        TrapTier::Low => std::fs::read(project_dir.join("config.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .and_then(|config| config["port"].as_u64())
            .map(|port| format!("{port}/tcp")),
        TrapTier::Middle => Some("2222/tcp".to_owned()),
    };
    let manifest = std::fs::read(project_dir.join("manifest.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    let expected_host_port = manifest
        .as_ref()
        .and_then(|value| value["host_port"].as_u64())
        .map(|port| port.to_string());
    let expected_host_ip = manifest
        .as_ref()
        .and_then(|value| value["publish_address"].as_str());
    if let Some(bindings) = port_bindings.as_object() {
        if bindings.len() != 1
            || expected_container_port
                .as_ref()
                .is_none_or(|port| !bindings.contains_key(port))
        {
            result.push("published port set differs from the tier allowlist");
        }
        for (container_port, entries) in bindings {
            let Some(entries) = entries.as_array() else {
                result.push("published port binding is malformed");
                break;
            };
            if entries.len() != 1
                || entries.iter().any(|entry| {
                    Some(container_port) != expected_container_port.as_ref()
                        || Some(entry["HostIp"].as_str().unwrap_or("")) != expected_host_ip
                        || Some(entry["HostPort"].as_str().unwrap_or(""))
                            != expected_host_port.as_deref()
                })
            {
                result.push("published port binding is outside the tier allowlist");
                break;
            }
        }
    } else {
        result.push("published port set is missing");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn executable_allowlists_are_tier_specific() {
        assert!(TrapTier::Low.allowed_executable("/usr/local/bin/honeyforge-low"));
        assert!(!TrapTier::Low.allowed_executable("/bin/sh"));
        assert!(TrapTier::Middle.allowed_executable("/usr/bin/ssh-keygen"));
        assert!(!TrapTier::Middle.allowed_executable("/usr/bin/curl"));
    }

    #[test]
    fn resource_action_outcome_and_environment_change_the_decision() {
        let mut action = ObservedAction { tier: TrapTier::Middle, operation: Operation::Open,
            resource: "/run/docker.sock", succeeded: false, inside_trap: true };
        assert_eq!(evaluate(action), ActionDecision::Alert);
        action.succeeded = true;
        assert_eq!(evaluate(action), ActionDecision::IsolateTrap);
        action.inside_trap = false;
        assert_eq!(evaluate(action), ActionDecision::Alert);
        action.inside_trap = true;
        action.resource = "/etc/honeyforge/pritvoryashka.json";
        assert_eq!(evaluate(action), ActionDecision::Allowed);
        action.operation = Operation::Connect;
        assert_eq!(evaluate(action), ActionDecision::Alert);
        action.succeeded = false;
        assert_eq!(evaluate(action), ActionDecision::Allowed);
    }

    #[test]
    fn all_known_runtime_sockets_are_alerted_or_isolated_by_result() {
        for path in ["/run/docker.sock", "/var/run/containerd/containerd.sock",
            "/run/podman/podman.sock", "/var/run/crio/crio.sock"] {
            let mut action = ObservedAction { tier: TrapTier::Low, operation: Operation::Open,
                resource: path, succeeded: false, inside_trap: true };
            assert_eq!(evaluate(action), ActionDecision::Alert, "{path}");
            action.succeeded = true;
            assert_eq!(evaluate(action), ActionDecision::IsolateTrap, "{path}");
        }
    }

    #[test]
    fn tier_limits_are_bounded_and_distinct() {
        let low = TrapTier::Low.limits();
        let middle = TrapTier::Middle.limits();
        assert!(low.memory_bytes < middle.memory_bytes);
        assert!(low.pids < middle.pids);
        assert!(low.nofile < middle.nofile);
    }

    #[test]
    fn rejects_unbounded_and_host_network_container() {
        let inspect = json!({"HostConfig": {"NetworkMode":"host", "Memory":0, "NanoCpus":0, "PidsLimit":null}});
        let reasons = violations(
            TrapTier::Low,
            &inspect,
            std::path::Path::new("/var/lib/honeyforge/traps/id"),
        );
        assert!(reasons.contains(&"host network namespace is enabled"));
        assert!(reasons.contains(&"memory limit is missing or exceeds tier policy"));
        assert!(reasons.contains(&"PID limit is missing or exceeds tier policy"));
    }

    #[test]
    fn accepts_a_low_container_that_matches_its_resource_and_mount_policy() {
        let root = std::env::temp_dir().join(format!("hf-policy-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("config.json"), r#"{"port":2222}"#).unwrap();
        std::fs::write(
            root.join("manifest.json"),
            r#"{"host_port":2222,"publish_address":"0.0.0.0"}"#,
        )
        .unwrap();
        let inspect = json!({
            "Config": {"User":"65532:65532"},
            "HostConfig": {
                "Privileged":false, "PidMode":"", "NetworkMode":"bridge", "IpcMode":"",
                "ReadonlyRootfs":true, "CapDrop":["ALL"], "SecurityOpt":["no-new-privileges:true"],
                "Memory":134217728, "NanoCpus":500000000, "PidsLimit":64,
                "Ulimits":[{"Name":"nofile","Soft":256,"Hard":256}],
                "PortBindings":{"2222/tcp":[{"HostIp":"0.0.0.0","HostPort":"2222"}]}
            },
            "Mounts":[{"Type":"bind","Propagation":"rprivate","Source":root.join("config.json").to_string_lossy(),"Destination":"/etc/honeyforge/config.json","RW":false}]
        });
        assert!(violations(TrapTier::Low, &inspect, &root).is_empty());
        let mut hostile = inspect.clone();
        hostile["HostConfig"]["CapAdd"] = json!(["SYS_ADMIN"]);
        hostile["HostConfig"]["SecurityOpt"] = json!(["no-new-privileges:true", "seccomp=unconfined"]);
        hostile["Mounts"][0]["Source"] = json!(root.to_string_lossy());
        assert!(violations(TrapTier::Low, &hostile, &root).len() >= 3);
        std::fs::remove_dir_all(root).unwrap();
    }
}
