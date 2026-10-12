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
struct AgentTarget {
    address: String,
}

#[derive(Default, Serialize, Deserialize)]
struct PersistedState {
    #[serde(default)]
    targets: HashMap<Uuid, AgentTarget>,
    #[serde(default)]
    compromised: HashMap<Uuid, CompromisedAgent>,
}

pub(crate) struct AgentSecurityStore {
    path: PathBuf,
    state: PersistedState,
}

impl AgentSecurityStore {
    pub(crate) fn is_confirmed_escape(event: &TrapEvent) -> bool {
        event.event_type == "security.escape_confirmed"
            && !event.trap_id.is_nil()
            && event.service_type == "host_monitor"
            && event.metadata["source"].as_str() == Some("hf-agent-ebpf")
            && event.metadata["assessment"].as_str() == Some("confirmed")
            && event.metadata["validation"].as_str()
                == Some("second_proc_sample_and_docker_inspect")
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

    pub(crate) fn set_target(&mut self, agent_id: Uuid, address: String) -> anyhow::Result<()> {
        let mut next = clone_state(&self.state)?;
        next.targets.insert(agent_id, AgentTarget { address });
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
            event_id: Uuid::new_v4(),
            trap_id: Uuid::new_v4(),
            session_id: None,
            source_sequence_no: None,
            occurred_at_unix_ms: 1_800_000_000_000,
            event_type: "security.escape_confirmed".into(),
            source_ip: None,
            source_port: None,
            destination_port: None,
            protocol: "local".into(),
            service_type: "host_monitor".into(),
            payload: json!({}),
            metadata: json!({
                "source":"hf-agent-ebpf",
                "assessment":"confirmed",
                "validation":"second_proc_sample_and_docker_inspect"
            }),
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
        store.set_target(agent, "192.0.2.10:22".into()).unwrap();
        assert!(store.mark_compromised(agent, &event).unwrap());
        assert!(!store.mark_compromised(agent, &event).unwrap());
        let restored = AgentSecurityStore::open(&path).unwrap();
        assert!(restored.is_compromised(&agent));
        assert_eq!(
            restored.compromised()[0].target.as_deref(),
            Some("192.0.2.10:22")
        );
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
        assert!(!store.is_compromised(&agent));
        fs::remove_dir_all(dir).unwrap();
    }
}
