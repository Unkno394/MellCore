use std::{
    collections::HashMap,
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::Context;
use kazik_protocol::TrapEvent;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct CompromisedAgent {
    pub agent_id: Uuid,
    pub target: Option<String>,
    pub trap_id: Uuid,
    pub event_id: Uuid,
    pub detected_at_unix_ms: i64,
    pub transport_disconnected: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct IsolatedTrap {
    pub agent_id: Uuid,
    pub trap_id: Uuid,
    pub event_id: Uuid,
    pub detected_at_unix_ms: i64,
    #[serde(default = "default_isolated_status")]
    pub status: String,
}

fn default_isolated_status() -> String { "applied".into() }

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AgentTarget {
    address: String,
    #[serde(default = "default_ssh_port")]
    ssh_port: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PendingRemoval {
    pub agent_id: Uuid,
    pub trap_id: Uuid,
}

fn default_ssh_port() -> u16 { 22 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResponseTier { Observe, Alert, IsolateTrap, QuarantineHost }

#[derive(Default, Serialize, Deserialize)]
struct PersistedState {
    #[serde(default)]
    targets: HashMap<Uuid, AgentTarget>,
    #[serde(default)]
    compromised: HashMap<Uuid, CompromisedAgent>,
    #[serde(default)]
    isolated_traps: HashMap<Uuid, IsolatedTrap>,
    #[serde(default)]
    traps: HashMap<Uuid, Uuid>,
    #[serde(default)]
    pending_removals: HashMap<Uuid, PendingRemoval>,
}

pub(crate) struct AgentSecurityStore {
    path: PathBuf,
    state: PersistedState,
}

impl AgentSecurityStore {
    pub(crate) fn response_for_event(event: &TrapEvent) -> ResponseTier {
        if Self::is_confirmed_escape(event) { ResponseTier::QuarantineHost }
        else if Self::is_isolation_event(event) { ResponseTier::IsolateTrap }
        else if event.event_type.starts_with("security.") { ResponseTier::Alert }
        else { ResponseTier::Observe }
    }
    pub(crate) fn is_confirmed_escape(event: &TrapEvent) -> bool {
        !event.trap_id.is_nil() && hf_core::security::confirmed_escape(
            &event.event_type, &event.service_type, &event.protocol, &event.payload, &event.metadata,
        )
    }

    pub(crate) fn is_isolation_event(event: &TrapEvent) -> bool {
        if event.service_type != "host_monitor" || event.protocol != "local"
            || event.metadata["source"] != "hf-agent-ebpf"
            || !matches!(event.event_type.as_str(), "security.trap_quarantined" | "security.trap_quarantine_failed")
            || event.payload["trigger_event_id"].as_str().and_then(|value| Uuid::parse_str(value).ok()).is_none()
            || event.payload["policy_decision"] != "isolate_trap"
            || event.payload["subject"] != "trap_process"
            || !matches!((event.payload["container_id"].as_str(), event.payload["cgroup"].as_str()),
                (Some(id), Some(cgroup)) if hf_core::security::container_in_cgroup(cgroup, id))
            || !matches!(event.payload["trap_tier"].as_str(), Some("low" | "middle")) {
            return false;
        }
        let applied = event.event_type == "security.trap_quarantined"
            && event.payload["quarantine_result"] == "applied"
            && event.metadata["assessment"] == "isolated";
        let failed = event.event_type == "security.trap_quarantine_failed"
            && event.payload["quarantine_result"] == "failed";
        if !applied && !failed { return false; }
        match event.payload["trigger_event_type"].as_str().unwrap_or("") {
            "security.resource_access" => event.payload["operation"] == "open"
                && event.payload["result"].as_i64().is_some_and(|v| v >= 0)
                && event.payload["resource"].as_str()
                    .is_some_and(hf_core::security::container_runtime_socket),
            "security.policy_violation" => event.payload["policy_violations"].as_array()
                .is_some_and(|reasons| reasons.iter().any(|reason|
                    reason.as_str().is_some_and(|value| matches!(value,
                        "privileged mode is enabled" | "host PID namespace is enabled"
                        | "host network namespace is enabled" | "host IPC namespace is enabled"
                        | "host user or cgroup namespace is explicitly shared"
                        | "namespace sharing with another container is forbidden"
                        | "additional capabilities or device access are forbidden"
                        | "unconfined seccomp or LSM profile is forbidden"
                        | "mount set differs from the tier allowlist")))),
            _ => false,
        }
    }

    pub(crate) fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let state = match fs::read(&path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).context("parse Center agent security state")?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => PersistedState::default(),
            Err(error) => return Err(error.into()),
        };
        Ok(Self { path, state })
    }

    pub(crate) fn is_compromised(&self, agent_id: &Uuid) -> bool {
        self.state.compromised.contains_key(agent_id)
    }

    pub(crate) fn target(&self, agent_id: &Uuid) -> Option<(&str, u16)> {
        self.state.targets.get(agent_id).map(|target| (target.address.as_str(), target.ssh_port))
    }

    pub(crate) fn remove_agent(&mut self, agent_id: Uuid) -> anyhow::Result<()> {
        let mut next = clone_state(&self.state)?;
        next.targets.remove(&agent_id);
        next.compromised.remove(&agent_id);
        next.traps.retain(|_, owner| *owner != agent_id);
        next.isolated_traps.retain(|_, trap| trap.agent_id != agent_id);
        next.pending_removals.retain(|_, removal| removal.agent_id != agent_id);
        self.persist(next)
    }

    pub(crate) fn owns_trap(&self, agent_id: Uuid, trap_id: Uuid) -> bool {
        self.state.traps.get(&trap_id) == Some(&agent_id)
    }

    pub(crate) fn is_trap_isolated(&self, trap_id: Uuid) -> bool {
        self.state.isolated_traps.contains_key(&trap_id)
    }

    pub(crate) fn isolated_traps(&self) -> Vec<IsolatedTrap> {
        self.state.isolated_traps.values().cloned().collect()
    }

    pub(crate) fn mark_trap_isolated(&mut self, agent_id: Uuid, event: &TrapEvent) -> anyhow::Result<bool> {
        anyhow::ensure!(self.owns_trap(agent_id, event.trap_id), "isolation event belongs to an unregistered trap");
        anyhow::ensure!(Self::is_isolation_event(event),
            "event is not an agent-observed Low/Middle isolation decision");
        let status = event.payload["quarantine_result"].as_str().unwrap_or("failed");
        if self.state.isolated_traps.get(&event.trap_id).is_some_and(|old| old.status == status) {
            return Ok(false);
        }
        if self.state.isolated_traps.get(&event.trap_id).is_some_and(|old| old.status == "applied") {
            return Ok(false);
        }
        let mut next = clone_state(&self.state)?;
        next.isolated_traps.insert(event.trap_id, IsolatedTrap {
            agent_id, trap_id: event.trap_id, event_id: event.event_id,
            detected_at_unix_ms: event.occurred_at_unix_ms,
            status: status.into(),
        });
        self.persist(next)?;
        Ok(true)
    }

    pub(crate) fn register_trap(&mut self, agent_id: Uuid, trap_id: Uuid) -> anyhow::Result<()> {
        anyhow::ensure!(!agent_id.is_nil() && !trap_id.is_nil(), "invalid agent/trap ID");
        anyhow::ensure!(!self.is_trap_isolated(trap_id), "trap is isolated after a security incident");
        anyhow::ensure!(self.state.traps.get(&trap_id).map_or(true, |owner| *owner == agent_id),
            "trap ID belongs to another agent");
        let mut next = clone_state(&self.state)?;
        next.traps.insert(trap_id, agent_id);
        self.persist(next)
    }

    pub(crate) fn pending_removal(&self, message_id: Uuid) -> Option<PendingRemoval> {
        self.state.pending_removals.get(&message_id).cloned()
    }

    pub(crate) fn record_removal(&mut self, message_id: Uuid, agent_id: Uuid, trap_id: Uuid) -> anyhow::Result<()> {
        anyhow::ensure!(self.owns_trap(agent_id, trap_id), "trap does not belong to agent");
        let mut next = clone_state(&self.state)?;
        next.pending_removals.insert(message_id, PendingRemoval { agent_id, trap_id });
        self.persist(next)
    }

    pub(crate) fn finish_removal(&mut self, message_id: Uuid, applied: bool) -> anyhow::Result<()> {
        let Some(removal) = self.state.pending_removals.get(&message_id) else { return Ok(()) };
        let mut next = clone_state(&self.state)?;
        if applied { next.traps.remove(&removal.trap_id); }
        next.pending_removals.remove(&message_id);
        self.persist(next)
    }

    pub(crate) fn target_is_compromised(&self, target: &str) -> bool {
        self.state
            .compromised
            .values()
            .any(|record| record.target.as_deref() == Some(target))
    }

    pub(crate) fn compromised(&self) -> Vec<CompromisedAgent> {
        let mut records: Vec<_> = self.state.compromised.values().cloned().collect();
        records.sort_by_key(|record| (record.detected_at_unix_ms, record.agent_id));
        records
    }

    pub(crate) fn set_target(&mut self, agent_id: Uuid, address: String, ssh_port: u16) -> anyhow::Result<()> {
        let mut next = clone_state(&self.state)?;
        next.targets.insert(agent_id, AgentTarget { address, ssh_port });
        self.persist(next)
    }

    pub(crate) fn mark_compromised(
        &mut self,
        agent_id: Uuid,
        event: &TrapEvent,
    ) -> anyhow::Result<bool> {
        if !Self::is_confirmed_escape(event) {
            anyhow::bail!("only a confirmed escape event can compromise an agent");
        }
        if self.state.compromised.contains_key(&agent_id) {
            return Ok(false);
        }
        let target = self
            .state
            .targets
            .get(&agent_id)
            .map(|target| target.address.clone());
        let mut next = clone_state(&self.state)?;
        next.compromised.insert(
            agent_id,
            CompromisedAgent {
                agent_id,
                target,
                trap_id: event.trap_id,
                event_id: event.event_id,
                detected_at_unix_ms: event.occurred_at_unix_ms,
                transport_disconnected: false,
            },
        );
        self.persist(next)?;
        Ok(true)
    }

    pub(crate) fn set_transport_disconnected(
        &mut self,
        agent_id: Uuid,
        disconnected: bool,
    ) -> anyhow::Result<()> {
        let Some(current) = self.state.compromised.get(&agent_id) else {
            return Ok(());
        };
        if current.transport_disconnected == disconnected {
            return Ok(());
        }
        let mut next = clone_state(&self.state)?;
        if let Some(record) = next.compromised.get_mut(&agent_id) {
            record.transport_disconnected = disconnected;
        }
        self.persist(next)
    }

    fn persist(&mut self, next: PersistedState) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        let temporary = self.path.with_extension("tmp");
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o600);
        let mut file = options.open(&temporary)?;
        file.write_all(&serde_json::to_vec(&next)?)?;
        file.sync_all()?;
        fs::rename(&temporary, &self.path)?;
        fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))?;
        if let Some(parent) = self.path.parent() {
            fs::File::open(parent)?.sync_all()?;
        }
        self.state = next;
        Ok(())
    }
}

fn clone_state(state: &PersistedState) -> anyhow::Result<PersistedState> {
    Ok(serde_json::from_slice(&serde_json::to_vec(state)?)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn incident() -> TrapEvent {
        TrapEvent {
            event_id: Uuid::new_v4(), trap_id: Uuid::new_v4(), session_id: None,
            source_sequence_no: None, occurred_at_unix_ms: 1_800_000_000_000,
            event_type: "security.escape_confirmed".into(), source_ip: None, source_port: None,
            destination_port: None, protocol: "local".into(), service_type: "host_monitor".into(),
            payload: json!({"pid":123,"start_ticks":456,"boot_id":"10000000-0000-4000-8000-000000000001",
                "container_id":"a".repeat(64),"cgroup":format!("0::/docker/{}", "a".repeat(64)),
                "trap_tier":"low","observations":2,
                "pid_namespace":"pid:[1]","host_pid_namespace":"pid:[1]","container_pid_namespace":"pid:[2]",
                "mount_namespace":"mnt:[1]","host_mount_namespace":"mnt:[1]","container_mount_namespace":"mnt:[2]"}), metadata: json!({"source":"hf-agent-ebpf","assessment":"confirmed","validation":"two_samples_proc_docker_v2"}),
        }
    }

    #[test]
    fn compromise_and_target_survive_restart_and_are_idempotent() {
        let dir = std::env::temp_dir().join(format!("hf-agent-security-{}", Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("state.json");
        let agent = Uuid::new_v4();
        let event = incident();
        let mut store = AgentSecurityStore::open(&path).unwrap();
        store.set_target(agent, "192.0.2.10".into(), 22).unwrap();
        assert!(store.mark_compromised(agent, &event).unwrap());
        assert!(!store.mark_compromised(agent, &event).unwrap());
        let restored = AgentSecurityStore::open(&path).unwrap();
        assert!(restored.is_compromised(&agent));
        assert_eq!(restored.compromised()[0].target.as_deref(), Some("192.0.2.10"));
        assert!(!restored.compromised()[0].transport_disconnected);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn ordinary_security_events_do_not_compromise_an_agent() {
        let dir = std::env::temp_dir().join(format!("hf-agent-security-{}", Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let agent = Uuid::new_v4();
        let mut store = AgentSecurityStore::open(dir.join("state.json")).unwrap();
        let mut event = incident();
        event.event_type = "security.unexpected_executable".into();
        assert!(store.mark_compromised(agent, &event).is_err());
        assert_eq!(AgentSecurityStore::response_for_event(&event), ResponseTier::Alert);
        assert!(!store.is_compromised(&agent));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn isolation_requires_applied_result_and_persists_without_compromising_agent() {
        let dir = std::env::temp_dir().join(format!("hf-trap-isolation-{}", Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("state.json");
        let agent = Uuid::new_v4();
        let mut store = AgentSecurityStore::open(&path).unwrap();
        let mut event = incident();
        store.register_trap(agent, event.trap_id).unwrap();
        event.event_type = "security.trap_quarantined".into();
        event.metadata = json!({"source":"hf-agent-ebpf","assessment":"isolated"});
        event.payload = json!({"trap_tier":"middle","policy_decision":"isolate_trap",
            "subject":"trap_process","container_id":"a".repeat(64),
            "cgroup":format!("0::/docker/{}", "a".repeat(64)),
            "quarantine_result":"applied","trigger_event_id":Uuid::new_v4(),
            "trigger_event_type":"security.resource_access","operation":"open",
            "resource":"/run/docker.sock","result":4});
        let mut failed = event.clone();
        failed.event_type = "security.trap_quarantine_failed".into();
        failed.payload["quarantine_result"] = json!("failed");
        failed.metadata["assessment"] = json!("suspicious_unconfirmed");
        assert!(AgentSecurityStore::is_isolation_event(&failed));
        assert_eq!(AgentSecurityStore::response_for_event(&failed), ResponseTier::IsolateTrap);
        assert!(store.mark_trap_isolated(agent, &failed).unwrap());
        assert_eq!(store.isolated_traps()[0].status, "failed");
        assert!(store.mark_trap_isolated(agent, &event).unwrap());
        assert!(!store.mark_trap_isolated(agent, &event).unwrap());
        let mut restored = AgentSecurityStore::open(&path).unwrap();
        assert!(restored.is_trap_isolated(event.trap_id));
        assert_eq!(restored.isolated_traps()[0].status, "applied");
        assert!(!restored.is_compromised(&agent));
        assert!(restored.register_trap(agent, event.trap_id).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn trap_ownership_survives_restart_and_cannot_move_between_agents() {
        let dir = std::env::temp_dir().join(format!("hf-agent-trap-registry-{}", Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("state.json");
        let agent = Uuid::new_v4();
        let other = Uuid::new_v4();
        let trap = Uuid::new_v4();
        let mut store = AgentSecurityStore::open(&path).unwrap();
        store.set_target(agent, "192.0.2.40".into(), 1488).unwrap();
        store.register_trap(agent, trap).unwrap();
        store.register_trap(agent, trap).unwrap();
        assert!(store.register_trap(other, trap).is_err());
        let removal = Uuid::new_v4();
        store.record_removal(removal, agent, trap).unwrap();
        let reopened = AgentSecurityStore::open(&path).unwrap();
        assert_eq!(reopened.target(&agent), Some(("192.0.2.40", 1488)));
        assert!(reopened.owns_trap(agent, trap));
        assert!(!reopened.owns_trap(other, trap));
        assert_eq!(reopened.pending_removal(removal).unwrap().trap_id, trap);
        let mut reopened = reopened;
        reopened.finish_removal(removal, true).unwrap();
        assert!(!AgentSecurityStore::open(&path).unwrap().owns_trap(agent, trap));
        fs::remove_dir_all(dir).unwrap();
    }
}
