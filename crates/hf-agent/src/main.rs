use std::{
    fs,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::Duration,
};

mod emergency;
#[cfg(unix)]
mod high_telemetry;
mod sandbox;
mod security_monitor;
mod security_policy;
mod telemetry;

use anyhow::Context;
use clap::Parser;
use hf_core::{
    AgentCommand, AgentRegistration, CommandResult, CoreError, HighUbuntuDeployment,
    HysteriaConnection, KozyavkaDeployment, PacketTransport, PritvoryashkaDeployment,
    RegisteredAgent, RegistrationTransport, SharedTcpTrapKind, TcpPortGroup, TrapSpec,
};
use hf_services::{
    FailoverSender, HysteriaSocks5UdpTransport,
    kazik_outbox::{SqliteKazikOutbox, send_pending_once},
};
use kazik_protocol::{
    AckDisposition, Acknowledgement, AgentStatus, DurableOutbox, KazikBody, KazikEnvelope,
};
use sandbox::{HighDomainState, LibvirtSandboxManager, UbuntuSshVm, default_recipe_dir};
use serde::{Deserialize, Serialize};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Parser)]
struct Args {
    #[arg(long, env = "HF_CENTER_URL")]
    center_url: String,
    #[arg(
        long,
        env = "HF_ENROLLMENT_TOKEN_FILE",
        default_value = "/etc/honeyforge/enrollment-token"
    )]
    enrollment_token_file: String,
    /// Root-owned durable state: agent identity, transport credential and prepared trap projects.
    #[arg(long, env = "HF_STATE_DIR", default_value = "/var/lib/honeyforge")]
    state_dir: PathBuf,
    /// Register (if necessary) and stop. Useful for smoke tests; omit in systemd.
    #[arg(long)]
    once: bool,
    /// Applies one decoded HFSP AgentCommand from a root-owned JSON file. This is the local
    /// integration harness until the Hysteria/HFSP receive loop is enabled.
    #[arg(long)]
    command_file: Option<PathBuf>,
    /// Immutable or locally loaded image reference for the Low SSH honeypot.
    #[arg(
        long,
        env = "HF_KOZYAVKA_IMAGE",
        default_value = "honeyforge-low:local"
    )]
    kozyavka_image: String,
    /// Immutable or locally loaded image reference for the Middle SSH honeypot.
    #[arg(
        long,
        env = "HF_PRITVORYASHKA_IMAGE",
        default_value = "honeyforge-pritvoryashka:local"
    )]
    pritvoryashka_image: String,
    /// Local SOCKS5 UDP listener exposed by the Hysteria client. Both Kazik transport options
    /// must be set to enable the persistent protocol loop.
    #[arg(long, env = "HF_KAZIK_HYSTERIA_SOCKS")]
    kazik_hysteria_socks: Option<SocketAddr>,
    /// Center's loopback UDP Kazik receiver as reached through Hysteria.
    #[arg(long, env = "HF_KAZIK_CENTER_UDP")]
    kazik_center_udp: Option<SocketAddr>,
    /// Upper bound for High events waiting on this host for future Kazik delivery.
    #[arg(
        long,
        env = "HF_HIGH_TELEMETRY_MAX_PENDING",
        default_value_t = hf_services::high_telemetry::DEFAULT_MAX_PENDING_HIGH_EVENTS
    )]
    high_telemetry_max_pending: usize,
    /// Host-side libvirt/SSH health polling interval; values below five seconds are rejected.
    #[arg(
        long,
        env = "HF_HIGH_OPERATIONAL_INTERVAL_SECONDS",
        default_value_t = 30
    )]
    high_operational_interval_seconds: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct AgentIdentity {
    agent_id: uuid::Uuid,
    transport_credential: String,
    #[serde(default)]
    hysteria: Option<HysteriaConnection>,
}

/// Infrastructure service. It owns project files but deliberately does not contain trap recipes.
#[derive(Clone)]
struct ComposeProjectStore {
    root: PathBuf,
    mutation_lock: Arc<std::sync::Mutex<()>>,
}

#[derive(Serialize, Deserialize)]
struct QuarantineMarker {
    trigger: kazik_protocol::TrapEvent,
    result_event_id: uuid::Uuid,
}

fn quarantine_result(marker: &QuarantineMarker, applied: bool) -> kazik_protocol::TrapEvent {
    let mut event = marker.trigger.clone();
    event.payload["trigger_event_type"] = serde_json::json!(event.event_type.clone());
    event.payload["trigger_event_id"] = serde_json::json!(event.event_id);
    event.event_type = if applied { "security.trap_quarantined" } else { "security.trap_quarantine_failed" }.into();
    event.payload["quarantine_result"] = serde_json::json!(if applied { "applied" } else { "failed" });
    event.metadata["assessment"] = serde_json::json!(if applied { "isolated" } else { "suspicious_unconfirmed" });
    event.event_id = marker.result_event_id;
    event.occurred_at_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|value| value.as_millis() as i64).unwrap_or_default();
    event
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum HighDesiredState {
    Running,
    Stopped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HighRuntimeManifest {
    version: u8,
    kind: String,
    deployment: HighUbuntuDeployment,
    desired_state: HighDesiredState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_error: Option<String>,
}

#[derive(Clone)]
enum SharedTcpDeployment {
    Kozyavka(KozyavkaDeployment),
    Pritvoryashka(PritvoryashkaDeployment),
}

impl SharedTcpDeployment {
    fn trap_id(&self) -> uuid::Uuid {
        match self {
            Self::Kozyavka(deployment) => deployment.trap_id,
            Self::Pritvoryashka(deployment) => deployment.trap_id,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DispatcherConfig {
    version: u8,
    listeners: Vec<DispatcherListener>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DispatcherListener {
    listen: SocketAddr,
    targets: Vec<DispatcherTarget>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DispatcherTarget {
    trap_id: uuid::Uuid,
    address: SocketAddr,
    weight: u8,
}

impl DispatcherConfig {
    /// Remove every route to this trap. Remaining weights keep their relative proportions.
    fn without_trap(mut self, trap_id: uuid::Uuid) -> anyhow::Result<Option<Self>> {
        anyhow::ensure!(self.version == 1, "unsupported Dispatcher config version");
        anyhow::ensure!(!self.listeners.is_empty(), "Dispatcher has no listeners");
        let mut seen = std::collections::HashSet::new();
        for listener in &self.listeners {
            anyhow::ensure!(
                seen.insert(listener.listen),
                "duplicate Dispatcher listener"
            );
            anyhow::ensure!(
                !listener.targets.is_empty(),
                "Dispatcher listener has no targets"
            );
            anyhow::ensure!(
                listener
                    .targets
                    .iter()
                    .map(|target| u32::from(target.weight))
                    .sum::<u32>()
                    == 100,
                "Dispatcher target weights do not total 100"
            );
            anyhow::ensure!(
                listener
                    .targets
                    .iter()
                    .all(|target| target.weight > 0 && target.address.ip().is_loopback()),
                "invalid Dispatcher target"
            );
        }
        let mut changed = false;
        for listener in &mut self.listeners {
            let before = listener.targets.len();
            listener.targets.retain(|target| target.trap_id != trap_id);
            if listener.targets.len() != before {
                changed = true;
                if !listener.targets.is_empty() {
                    normalize_dispatcher_weights(&mut listener.targets)?;
                }
            }
        }
        if !changed {
            return Ok(None);
        }
        self.listeners
            .retain(|listener| !listener.targets.is_empty());
        Ok(Some(self))
    }
}

fn normalize_dispatcher_weights(targets: &mut [DispatcherTarget]) -> anyhow::Result<()> {
    let total: u32 = targets.iter().map(|target| u32::from(target.weight)).sum();
    anyhow::ensure!(
        total > 0 && targets.len() <= 100,
        "invalid Dispatcher target weights"
    );
    let mut assigned = 0_u32;
    let mut remainder = Vec::with_capacity(targets.len());
    for (index, target) in targets.iter_mut().enumerate() {
        let scaled = u32::from(target.weight) * 100;
        let weight = scaled / total;
        anyhow::ensure!(weight > 0, "Dispatcher target weight would become zero");
        target.weight = weight as u8;
        assigned += weight;
        remainder.push((index, scaled % total));
    }
    remainder.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    for (index, _) in remainder.into_iter().take((100 - assigned) as usize) {
        targets[index].weight += 1;
    }
    Ok(())
}

impl ComposeProjectStore {
    fn new(state_dir: &Path) -> Self {
        Self {
            root: state_dir.join("traps"),
            mutation_lock: Arc::new(std::sync::Mutex::new(())),
        }
    }

    fn high_manager(&self) -> LibvirtSandboxManager {
        let state_dir = self
            .root
            .parent()
            .unwrap_or(Path::new("/var/lib/honeyforge"));
        LibvirtSandboxManager::with_high_root(default_recipe_dir(), state_dir.join("high"))
    }

    fn high_manifest_path(&self, trap_id: uuid::Uuid) -> PathBuf {
        self.root.join(trap_id.to_string()).join("high.json")
    }

    fn has_high_runtime(&self, trap_id: uuid::Uuid) -> bool {
        self.root
            .parent()
            .unwrap_or(Path::new("/var/lib/honeyforge"))
            .join("high")
            .join(trap_id.to_string())
            .is_dir()
    }

    fn load_high_manifest(
        &self,
        trap_id: uuid::Uuid,
    ) -> anyhow::Result<Option<HighRuntimeManifest>> {
        let path = self.high_manifest_path(trap_id);
        if !path.is_file() {
            return Ok(None);
        }
        let manifest: HighRuntimeManifest = serde_json::from_slice(&fs::read(&path)?)?;
        if manifest.version != 1
            || manifest.kind != "high_ubuntu_ssh"
            || manifest.deployment.trap_id != trap_id
        {
            anyhow::bail!("invalid High manifest {}", path.display());
        }
        Ok(Some(manifest))
    }

    fn save_high_manifest(&self, manifest: &HighRuntimeManifest) -> anyhow::Result<()> {
        let path = self.high_manifest_path(manifest.deployment.trap_id);
        fs::create_dir_all(path.parent().expect("High manifest parent"))?;
        atomic_write(&path, &serde_json::to_vec_pretty(manifest)?)
    }

    fn high_vm(deployment: &HighUbuntuDeployment) -> UbuntuSshVm {
        UbuntuSshVm {
            instance_id: deployment.trap_id,
            base_image: PathBuf::from(&deployment.base_image),
            external_ssh_port: deployment.external_ssh_port,
        }
    }

    fn deploy_high(&self, deployment: HighUbuntuDeployment) -> anyhow::Result<()> {
        if deployment.trap_id.is_nil()
            || deployment.external_ssh_port == 0
            || deployment.base_image.trim().is_empty()
        {
            anyhow::bail!("invalid High Ubuntu deployment command");
        }
        let changed = self
            .load_high_manifest(deployment.trap_id)?
            .is_some_and(|current| {
                current.deployment.base_image != deployment.base_image
                    || current.deployment.external_ssh_port != deployment.external_ssh_port
            });
        let mut manifest = HighRuntimeManifest {
            version: 1,
            kind: "high_ubuntu_ssh".into(),
            deployment: deployment.clone(),
            desired_state: HighDesiredState::Running,
            last_error: None,
        };
        self.save_high_manifest(&manifest)?;
        if changed {
            self.high_manager().reset(deployment.trap_id)?;
        }
        let result = self
            .high_manager()
            .reconcile(&Self::high_vm(&deployment), true);
        if let Err(error) = &result {
            manifest.last_error = Some(error.to_string());
            self.save_high_manifest(&manifest)?;
        }
        result
    }

    fn reset_high(&self, trap_id: uuid::Uuid) -> anyhow::Result<()> {
        let mut manifest = self
            .load_high_manifest(trap_id)?
            .ok_or_else(|| anyhow::anyhow!("High trap {trap_id} has no durable manifest"))?;
        manifest.desired_state = HighDesiredState::Running;
        manifest.last_error = None;
        self.save_high_manifest(&manifest)?;
        self.high_manager().reset(trap_id)?;
        let result = self
            .high_manager()
            .reconcile(&Self::high_vm(&manifest.deployment), true);
        if let Err(error) = &result {
            manifest.last_error = Some(error.to_string());
            self.save_high_manifest(&manifest)?;
        }
        result
    }

    fn stop_high(&self, trap_id: uuid::Uuid) -> anyhow::Result<()> {
        let mut manifest = self
            .load_high_manifest(trap_id)?
            .ok_or_else(|| anyhow::anyhow!("High trap {trap_id} has no durable manifest"))?;
        manifest.desired_state = HighDesiredState::Stopped;
        manifest.last_error = None;
        self.save_high_manifest(&manifest)?;
        let result = self.high_manager().stop(trap_id);
        if let Err(error) = &result {
            manifest.last_error = Some(error.to_string());
            self.save_high_manifest(&manifest)?;
        }
        result
    }

    fn remove_high(&self, trap_id: uuid::Uuid) -> anyhow::Result<()> {
        self.high_manager().remove(trap_id)?;
        let project = self.root.join(trap_id.to_string());
        if project.exists() {
            fs::remove_dir_all(project)?;
        }
        Ok(())
    }

    fn reconcile_high_manifests(&self) {
        let Ok(entries) = fs::read_dir(&self.root) else {
            return;
        };
        for entry in entries.flatten().filter(|entry| entry.path().is_dir()) {
            let Ok(trap_id) = Uuid::parse_str(&entry.file_name().to_string_lossy()) else {
                continue;
            };
            let Ok(Some(mut manifest)) = self.load_high_manifest(trap_id) else {
                continue;
            };
            let desired_running = manifest.desired_state == HighDesiredState::Running;
            match self
                .high_manager()
                .reconcile(&Self::high_vm(&manifest.deployment), desired_running)
            {
                Ok(()) => {
                    manifest.last_error = None;
                    let _ = self.save_high_manifest(&manifest);
                }
                Err(error) => {
                    tracing::error!(trap_id = %trap_id, %error, "High reconciliation failed");
                    manifest.last_error = Some(error.to_string());
                    let _ = self.save_high_manifest(&manifest);
                }
            }
        }
    }

    fn cached_command_is_satisfied(&self, command: &AgentCommand) -> anyhow::Result<bool> {
        match command {
            AgentCommand::DeployHighUbuntu(deployment) => {
                let Some(manifest) = self.load_high_manifest(deployment.trap_id)? else {
                    return Ok(false);
                };
                Ok(manifest.desired_state == HighDesiredState::Running
                    && self
                        .high_manager()
                        .healthy(&Self::high_vm(&manifest.deployment))?)
            }
            AgentCommand::ResetHighUbuntu { trap_id, .. } => {
                let Some(manifest) = self.load_high_manifest(*trap_id)? else {
                    return Ok(false);
                };
                Ok(manifest.desired_state == HighDesiredState::Running
                    && self
                        .high_manager()
                        .healthy(&Self::high_vm(&manifest.deployment))?)
            }
            AgentCommand::StopTrap { trap_id, .. } => {
                if let Some(manifest) = self.load_high_manifest(*trap_id)? {
                    Ok(manifest.desired_state == HighDesiredState::Stopped
                        && self.high_manager().domain_state(*trap_id)? == HighDomainState::Stopped
                        && !self.high_manager().has_dnat(*trap_id))
                } else if self.has_high_runtime(*trap_id) {
                    Ok(
                        self.high_manager().domain_state(*trap_id)? == HighDomainState::Stopped
                            && !self.high_manager().has_dnat(*trap_id),
                    )
                } else {
                    Ok(true)
                }
            }
            AgentCommand::RemoveTrap { trap_id, .. } => {
                if self.load_high_manifest(*trap_id)?.is_some() {
                    Ok(false)
                } else if self.has_high_runtime(*trap_id) {
                    Ok(self.high_manager().domain_state(*trap_id)? == HighDomainState::Missing)
                } else {
                    Ok(true)
                }
            }
            _ => Ok(true),
        }
    }

    fn active_trap_count(&self) -> u32 {
        let Ok(entries) = fs::read_dir(&self.root) else {
            return 0;
        };
        entries
            .flatten()
            .filter(|entry| entry.path().is_dir())
            .filter(|entry| {
                let Ok(trap_id) = Uuid::parse_str(&entry.file_name().to_string_lossy()) else {
                    return false;
                };
                match self.load_high_manifest(trap_id) {
                    Ok(Some(_)) => self.high_manager().is_running(trap_id).unwrap_or(false),
                    Ok(None) => entry.path().join("manifest.json").is_file(),
                    Err(_) => false,
                }
            })
            .count()
            .min(u32::MAX as usize) as u32
    }

    /// Prepares one isolated Compose project. Applying it is intentionally deferred until a
    /// trusted recipe exists for the requested tier/protocol.
    #[allow(dead_code)] // Invoked by the forthcoming authenticated HFSP control adapter.
    fn prepare(&self, spec: &TrapSpec) -> anyhow::Result<PathBuf> {
        if spec.protocol.trim().is_empty()
            || spec.ports.is_empty()
            || spec.ports.iter().any(|port| *port == 0)
        {
            anyhow::bail!("trap spec needs a protocol and at least one valid port");
        }
        let project_dir = self.root.join(spec.trap_id.to_string());
        fs::create_dir_all(&project_dir)?;
        let manifest = serde_json::to_vec_pretty(spec)?;
        atomic_write(&project_dir.join("manifest.json"), &manifest)?;
        atomic_write(
            &project_dir.join("compose.yaml"),
            b"# HoneyForge project placeholder. A signed recipe will add services here.\nname: honeyforge-placeholder\nservices: {}\n",
        )?;
        Ok(project_dir)
    }

    fn apply(
        &self,
        command: AgentCommand,
        kozyavka_image: &str,
        pritvoryashka_image: &str,
        agent_id: uuid::Uuid,
    ) -> anyhow::Result<CommandResult> {
        let _mutation = self.mutation_lock.lock()
            .map_err(|_| anyhow::anyhow!("trap mutation lock is poisoned"))?;
        let command_id = command.command_id();
        let trap_id = match &command {
            AgentCommand::DeployKozyavka(deployment) => deployment.trap_id,
            AgentCommand::DeployPritvoryashka(deployment) => deployment.trap_id,
            AgentCommand::DeployHighUbuntu(deployment) => deployment.trap_id,
            AgentCommand::ResetHighUbuntu { trap_id, .. } => *trap_id,
            AgentCommand::ReconcileTcpPortGroup(group) => {
                group
                    .members
                    .first()
                    .ok_or_else(|| anyhow::anyhow!("TCP port group has no members"))?
                    .trap_id
            }
            AgentCommand::StopTrap { trap_id, .. } | AgentCommand::RemoveTrap { trap_id, .. } => {
                *trap_id
            }
        };
        let completed = self
            .root
            .join("commands")
            .join(format!("{command_id}.json"));
        if completed.exists() {
            let cached = serde_json::from_slice(&fs::read(&completed)?)?;
            if self.cached_command_is_satisfied(&command)? {
                return Ok(cached);
            }
            tracing::warn!(command_id = %command_id, trap_id = %trap_id, "cached command state is absent or unhealthy; reconciling it again");
        }
        let deploying_quarantined = match &command {
            AgentCommand::DeployKozyavka(_) | AgentCommand::DeployPritvoryashka(_) =>
                self.root.join(trap_id.to_string()).join("security-quarantine.json").exists(),
            AgentCommand::ReconcileTcpPortGroup(group) => group.members.iter().any(|member|
                self.root.join(member.trap_id.to_string()).join("security-quarantine.json").exists()),
            _ => false,
        };
        anyhow::ensure!(!deploying_quarantined, "trap is isolated after a security incident");
        let high_manifest = matches!(
            &command,
            AgentCommand::StopTrap { .. } | AgentCommand::RemoveTrap { .. }
        )
        .then(|| self.load_high_manifest(trap_id))
        .transpose()?
        .flatten();
        let high_runtime = high_manifest.is_none() && self.has_high_runtime(trap_id);
        let compose_runtime = self
            .root
            .join(trap_id.to_string())
            .join("compose.yaml")
            .is_file();
        let deferred_remove = matches!(&command, AgentCommand::RemoveTrap { .. })
            && high_manifest.is_none()
            && !high_runtime
            && compose_runtime;
        let result = match command {
            AgentCommand::DeployKozyavka(deployment) => {
                ensure_docker_runtime()?;
                self.deploy_kozyavka(deployment, kozyavka_image)
            }
            AgentCommand::DeployPritvoryashka(deployment) => {
                ensure_docker_runtime()?;
                self.deploy_pritvoryashka(deployment, pritvoryashka_image, agent_id)
            }
            AgentCommand::DeployHighUbuntu(deployment) => {
                ensure_high_vm_runtime()?;
                self.deploy_high(deployment)
            }
            AgentCommand::ResetHighUbuntu { trap_id, .. } => self.reset_high(trap_id),
            AgentCommand::ReconcileTcpPortGroup(group) => {
                ensure_docker_runtime()?;
                self.reconcile_tcp_port_group(group, kozyavka_image, pritvoryashka_image, agent_id)
            }
            AgentCommand::StopTrap { .. } => {
                if high_manifest.is_some() {
                    self.stop_high(trap_id)
                } else if high_runtime {
                    self.high_manager().stop(trap_id)
                } else {
                    self.compose_down(trap_id, false)
                }
            }
            AgentCommand::RemoveTrap { .. } => {
                if high_manifest.is_some() {
                    self.remove_high(trap_id)
                } else if high_runtime {
                    self.high_manager().remove(trap_id)
                } else if deferred_remove {
                    self.prepare_remove(trap_id)
                } else {
                    anyhow::bail!("unknown trap {trap_id}")
                }
            }
        };
        let result = match result {
            Ok(()) => CommandResult {
                command_id,
                trap_id,
                success: true,
                detail: "applied".into(),
            },
            Err(error) => CommandResult {
                command_id,
                trap_id,
                success: false,
                detail: error.to_string(),
            },
        };
        if result.success && !deferred_remove {
            fs::create_dir_all(completed.parent().expect("command parent"))?;
            atomic_write(&completed, &serde_json::to_vec(&result)?)?;
        }
        Ok(result)
    }

    fn deploy_kozyavka(&self, deployment: KozyavkaDeployment, image: &str) -> anyhow::Result<()> {
        if deployment.host_port == 0
            || deployment.container_port == 0
            || deployment.banner.is_empty()
            || deployment.banner.len() > 253
            || !deployment
                .banner
                .bytes()
                .all(|byte| (32..=126).contains(&byte))
            || !deployment.resources.within(0.5, 128, 64)
        {
            anyhow::bail!("invalid kozyavka deployment command");
        }
        if deployment.publish_address != "0.0.0.0" && deployment.publish_address != "127.0.0.1" {
            anyhow::bail!("kozyavka publish address must be 0.0.0.0 or 127.0.0.1");
        }
        validate_container_image(image, "kozyavka")?;
        let project_dir = self.root.join(deployment.trap_id.to_string());
        fs::create_dir_all(&project_dir)?;
        atomic_write(
            &project_dir.join("manifest.json"),
            &serde_json::to_vec_pretty(&deployment)?,
        )?;
        let container_config = serde_json::json!({
            "bind_address": "0.0.0.0",
            "port": deployment.container_port,
            "banner": deployment.banner,
            "trap_id": deployment.trap_id,
        });
        atomic_write(
            &project_dir.join("config.json"),
            &serde_json::to_vec_pretty(&container_config)?,
        )?;
        // This public banner configuration must be readable by the image's UID 65532.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                project_dir.join("config.json"),
                fs::Permissions::from_mode(0o644),
            )?;
        }
        let compose = format!(
            "name: hf-{}\nservices:\n  honeypot:\n    image: {}\n    restart: unless-stopped\n    command: [\"--config\", \"/etc/honeyforge/config.json\"]\n    ports:\n      - \"{}:{}:{}/tcp\"\n    volumes:\n      - ./config.json:/etc/honeyforge/config.json:ro\n    read_only: true\n    cap_drop: [ALL]\n    security_opt: [no-new-privileges:true]\n    mem_limit: {}m\n    cpus: {:.3}\n    pids_limit: {}\n    ulimits:\n      nofile:\n        soft: 256\n        hard: 256\n    init: true\n",
            deployment.trap_id.simple(),
            image,
            deployment.publish_address,
            deployment.host_port,
            deployment.container_port,
            deployment.resources.memory_mb,
            deployment.resources.cpu_cores,
            deployment.resources.pids,
        );
        atomic_write(&project_dir.join("compose.yaml"), compose.as_bytes())?;
        self.compose(
            &project_dir,
            deployment.trap_id,
            ["up", "-d", "--remove-orphans"],
        )
    }

    fn deploy_pritvoryashka(
        &self,
        deployment: PritvoryashkaDeployment,
        image: &str,
        agent_id: uuid::Uuid,
    ) -> anyhow::Result<()> {
        if deployment.trap_id.is_nil()
            || deployment.server_id.is_nil()
            || deployment.host_port == 0
            || !(1..=128).contains(&deployment.max_connections)
            || !deployment.resources.within(1.0, 512, 256)
            || deployment.hostname.is_empty()
            || deployment.hostname.len() > 64
            || !deployment
                .hostname
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-".contains(&byte))
        {
            anyhow::bail!("invalid pritvoryashka deployment command");
        }
        if deployment.publish_address != "0.0.0.0" && deployment.publish_address != "127.0.0.1" {
            anyhow::bail!("pritvoryashka publish address must be 0.0.0.0 or 127.0.0.1");
        }
        validate_container_image(image, "pritvoryashka")?;
        let project_dir = self.root.join(deployment.trap_id.to_string());
        fs::create_dir_all(project_dir.join("runtime"))?;
        let telemetry_endpoint = std::env::var("HF_TELEMETRY_PUBLIC_ENDPOINT").ok();
        let telemetry_enabled = telemetry_endpoint.is_some();
        if telemetry_enabled && std::env::var("HF_TELEMETRY_INGEST_TOKEN").is_err() {
            anyhow::bail!("HF_TELEMETRY_INGEST_TOKEN is required with telemetry endpoint");
        }
        atomic_write(
            &project_dir.join("manifest.json"),
            &serde_json::to_vec_pretty(&deployment)?,
        )?;
        let container_config = serde_json::json!({
            "bind": "0.0.0.0:2222",
            "health_bind": "127.0.0.1:9091",
            "trap_id": deployment.trap_id,
            "server_id": deployment.server_id,
            "agent_id": agent_id,
            "hostname": deployment.hostname,
            "host_key": "/var/lib/pritvoryashka/host_ed25519",
            "auth": {"policy": "accept_all", "capture": "username", "max_attempts": 6},
            "telemetry": {
                "endpoint": telemetry_endpoint,
                "token_env": if telemetry_enabled { Some("HF_TELEMETRY_INGEST_TOKEN") } else { None },
                "jsonl_path": "/var/lib/pritvoryashka/events.jsonl",
                "queue_capacity": 1024,
                "batch_size": 50,
                "flush_interval_ms": 500,
            "max_event_bytes": 49152
            },
            "max_connections": deployment.max_connections,
            "idle_timeout_seconds": 600,
            "max_input_bytes": 8192
        });
        atomic_write(
            &project_dir.join("pritvoryashka.json"),
            &serde_json::to_vec_pretty(&container_config)?,
        )?;
        let mut compose = format!(
            "name: hf-{}\nservices:\n  honeypot:\n    image: {}\n    restart: unless-stopped\n    ports:\n      - \"{}:{}:2222/tcp\"\n    volumes:\n      - ./pritvoryashka.json:/etc/honeyforge/pritvoryashka.json:ro\n      - ./runtime:/var/lib/pritvoryashka\n    read_only: true\n    cap_drop: [ALL]\n    security_opt: [no-new-privileges:true]\n    mem_limit: {}m\n    cpus: {:.3}\n    pids_limit: {}\n    ulimits:\n      nofile:\n        soft: 1024\n        hard: 1024\n    init: true\n",
            deployment.trap_id.simple(),
            image,
            deployment.publish_address,
            deployment.host_port,
            deployment.resources.memory_mb,
            deployment.resources.cpu_cores,
            deployment.resources.pids,
        );
        if telemetry_enabled {
            compose.push_str("    environment:\n      HF_TELEMETRY_INGEST_TOKEN: ${HF_TELEMETRY_INGEST_TOKEN:?Telemetry token required}\n");
        }
        atomic_write(&project_dir.join("compose.yaml"), compose.as_bytes())?;
        self.compose(
            &project_dir,
            deployment.trap_id,
            ["up", "-d", "--remove-orphans"],
        )
    }

    fn reconcile_tcp_port_group(
        &self,
        group: TcpPortGroup,
        kozyavka_image: &str,
        pritvoryashka_image: &str,
        agent_id: uuid::Uuid,
    ) -> anyhow::Result<()> {
        if group.listener_port == 0 || group.members.len() < 2 {
            anyhow::bail!("TCP port group needs an external port and at least two traps");
        }
        let total: u16 = group
            .members
            .iter()
            .map(|member| u16::from(member.weight))
            .sum();
        if total != 100
            || group
                .members
                .iter()
                .any(|member| member.weight == 0 || member.backend_port == 0)
        {
            anyhow::bail!(
                "TCP port group weights must total 100 and backend ports must be nonzero"
            );
        }
        let mut originals = Vec::new();
        for member in &group.members {
            let manifest = self
                .root
                .join(member.trap_id.to_string())
                .join("manifest.json");
            let manifest = fs::read(&manifest)
                .with_context(|| format!("missing deployed trap {}", member.trap_id))?;
            let deployment = match member.trap_kind {
                SharedTcpTrapKind::Kozyavka => {
                    SharedTcpDeployment::Kozyavka(serde_json::from_slice(&manifest)?)
                }
                SharedTcpTrapKind::Pritvoryashka => {
                    SharedTcpDeployment::Pritvoryashka(serde_json::from_slice(&manifest)?)
                }
            };
            if deployment.trap_id() != member.trap_id {
                anyhow::bail!("dispatcher member does not match its deployed trap manifest");
            }
            originals.push(deployment);
        }
        let result = (|| -> anyhow::Result<()> {
            for (member, deployment) in group.members.iter().zip(&originals) {
                self.deploy_shared_backend(
                    deployment.clone(),
                    member.backend_port,
                    kozyavka_image,
                    pritvoryashka_image,
                    agent_id,
                )?;
            }
            let targets: Vec<_> = group
                .members
                .iter()
                .map(|member| {
                    serde_json::json!({
                        "trap_id": member.trap_id,
                        "address": format!("127.0.0.1:{}", member.backend_port),
                        "weight": member.weight,
                    })
                })
                .collect();
            let config = serde_json::json!({"version": 1, "listeners": [{
                "listen": format!("0.0.0.0:{}", group.listener_port), "targets": targets,
            }]});
            atomic_write(
                Path::new("/etc/honeyforge/dispatcher.json"),
                &serde_json::to_vec_pretty(&config)?,
            )?;
            run_program("systemctl", &["enable", "--now", "hf-dispatcher"])
        })();
        if let Err(error) = result {
            tracing::error!(%error, port = group.listener_port, "dispatcher transition failed; restoring prior trap publications");
            for deployment in originals {
                if let Err(rollback) = self.deploy_shared_original(
                    deployment,
                    kozyavka_image,
                    pritvoryashka_image,
                    agent_id,
                ) {
                    tracing::error!(%rollback, "dispatcher rollback failed");
                }
            }
            return Err(error);
        }
        Ok(())
    }

    fn deploy_shared_backend(
        &self,
        deployment: SharedTcpDeployment,
        backend_port: u16,
        kozyavka_image: &str,
        pritvoryashka_image: &str,
        agent_id: uuid::Uuid,
    ) -> anyhow::Result<()> {
        match deployment {
            SharedTcpDeployment::Kozyavka(mut deployment) => {
                deployment.host_port = backend_port;
                deployment.publish_address = "127.0.0.1".into();
                self.deploy_kozyavka(deployment, kozyavka_image)
            }
            SharedTcpDeployment::Pritvoryashka(mut deployment) => {
                deployment.host_port = backend_port;
                deployment.publish_address = "127.0.0.1".into();
                self.deploy_pritvoryashka(deployment, pritvoryashka_image, agent_id)
            }
        }
    }

    fn deploy_shared_original(
        &self,
        deployment: SharedTcpDeployment,
        kozyavka_image: &str,
        pritvoryashka_image: &str,
        agent_id: uuid::Uuid,
    ) -> anyhow::Result<()> {
        match deployment {
            SharedTcpDeployment::Kozyavka(deployment) => {
                self.deploy_kozyavka(deployment, kozyavka_image)
            }
            SharedTcpDeployment::Pritvoryashka(deployment) => {
                self.deploy_pritvoryashka(deployment, pritvoryashka_image, agent_id)
            }
        }
    }

    fn compose_down(&self, trap_id: uuid::Uuid, remove_directory: bool) -> anyhow::Result<()> {
        let project_dir = self.root.join(trap_id.to_string());
        if project_dir.exists() {
            self.compose(&project_dir, trap_id, ["down", "--remove-orphans"])?;
            if remove_directory {
                fs::remove_dir_all(project_dir)?;
            }
        }
        Ok(())
    }

    fn prepare_remove(&self, trap_id: uuid::Uuid) -> anyhow::Result<()> {
        let project_dir = self.root.join(trap_id.to_string());
        anyhow::ensure!(
            project_dir.join("compose.yaml").is_file(),
            "unknown Compose trap {trap_id}"
        );
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(project_dir.join("manifest.json"))?)?;
        let shared_backend = manifest["publish_address"].as_str() == Some("127.0.0.1");
        let previous_dispatcher = self.detach_dispatcher_target(trap_id, shared_backend)?;
        if let Err(error) = self.compose(&project_dir, trap_id, ["stop"]) {
            if let Some(previous) = previous_dispatcher {
                // `compose stop` may have stopped the container despite returning an error.
                // Restore the backend before publishing its old Dispatcher route again.
                if let Err(restart) = self.compose(&project_dir, trap_id, ["up", "-d"]) {
                    return Err(anyhow::anyhow!(
                        "could not stop trap ({error}); backend restart failed ({restart}); Dispatcher route remains detached"
                    ));
                }
                if let Err(rollback) = self.restore_dispatcher(&previous) {
                    return Err(anyhow::anyhow!(
                        "could not stop trap ({error}); Dispatcher rollback also failed: {rollback}"
                    ));
                }
            }
            return Err(error);
        }
        Ok(())
    }

    /// Unlike normal deletion, security isolation never rolls back to a running
    /// container when route removal or Docker stop fails. Both are attempted.
    fn isolate_project(&self, trap_id: uuid::Uuid) -> anyhow::Result<()> {
        let project = self.root.join(trap_id.to_string());
        let route = fs::read(project.join("manifest.json"))
            .map_err(anyhow::Error::from)
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).map_err(Into::into))
            .and_then(|manifest| self.detach_dispatcher_target(trap_id,
                manifest["publish_address"].as_str() == Some("127.0.0.1")).map(|_| ()));
        let stopped = self.compose(&project, trap_id, ["stop"]);
        route?;
        stopped?;
        Ok(())
    }

    /// Preserve the trap and its evidence, detach only its Dispatcher route and
    /// stop its container. Docker stop closes its established network sockets.
    fn quarantine_trap(&self, trigger: &kazik_protocol::TrapEvent) -> anyhow::Result<kazik_protocol::TrapEvent> {
        let _mutation = self.mutation_lock.lock()
            .map_err(|_| anyhow::anyhow!("trap mutation lock is poisoned"))?;
        let trap_id = trigger.trap_id;
        let project = self.root.join(trap_id.to_string());
        anyhow::ensure!(project.join("compose.yaml").is_file()
            && (project.join("config.json").is_file() || project.join("pritvoryashka.json").is_file()),
            "only an existing Low/Middle trap may be quarantined");
        let marker = project.join("security-quarantine.json");
        let record: QuarantineMarker = if marker.exists() {
            serde_json::from_slice(&fs::read(&marker)?)?
        } else {
            let record = QuarantineMarker { trigger: trigger.clone(), result_event_id: uuid::Uuid::new_v4() };
            atomic_write(&marker, &serde_json::to_vec(&record)?)?;
            fs::File::open(&marker)?.sync_all()?;
            fs::File::open(&project)?.sync_all()?;
            record
        };
        anyhow::ensure!(record.trigger.trap_id == trap_id, "quarantine marker trap ID mismatch");
        self.isolate_project(trap_id)?;
        Ok(quarantine_result(&record, true))
    }

    fn recover_quarantines(&self) -> anyhow::Result<Vec<kazik_protocol::TrapEvent>> {
        let mut results = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let Ok(trap_id) = uuid::Uuid::parse_str(&entry.file_name().to_string_lossy()) else { continue };
            let marker = entry.path().join("security-quarantine.json");
            if marker.is_file() {
                let result = (|| -> anyhow::Result<kazik_protocol::TrapEvent> {
                    let record: QuarantineMarker = serde_json::from_slice(&fs::read(&marker)?)?;
                    anyhow::ensure!(record.trigger.trap_id == trap_id, "quarantine marker trap ID mismatch");
                    self.isolate_project(trap_id)?;
                    Ok(quarantine_result(&record, true))
                })();
                match result {
                    Ok(event) => results.push(event),
                    Err(error) => tracing::error!(%trap_id, %error, "could not reapply trap quarantine after restart"),
                }
            }
        }
        Ok(results)
    }

    fn detach_dispatcher_target(&self, trap_id: uuid::Uuid, shared_backend: bool) -> anyhow::Result<Option<Vec<u8>>> {
        let path = Path::new("/etc/honeyforge/dispatcher.json");
        let previous = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if shared_backend {
                    let status = Command::new("systemctl")
                        .args(["is-active", "--quiet", "hf-dispatcher.service"])
                        .status()?;
                    anyhow::ensure!(
                        !status.success(),
                        "Dispatcher is active without its configuration; refusing to stop a shared trap"
                    );
                }
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        let config: DispatcherConfig = serde_json::from_slice(&previous)
            .context("invalid Dispatcher configuration; refusing to remove a trap")?;
        let Some(updated) = config.without_trap(trap_id)? else {
            if shared_backend {
                // A previous attempt may have written the new config before a crash. Restart
                // before stopping the backend so no process keeps serving stale routes.
                run_program("systemctl", &["restart", "hf-dispatcher.service"])?;
                run_program(
                    "systemctl",
                    &["is-active", "--quiet", "hf-dispatcher.service"],
                )?;
            }
            return Ok(None);
        };
        let transition = if updated.listeners.is_empty() {
            // No public routes remain. Stop the listener and prevent it from starting on boot.
            run_program("systemctl", &["disable", "--now", "hf-dispatcher.service"])
                .and_then(|_| fs::remove_file(path).map_err(Into::into))
        } else {
            atomic_write(path, &serde_json::to_vec_pretty(&updated)?)?;
            run_program("systemctl", &["restart", "hf-dispatcher.service"]).and_then(|_| {
                run_program(
                    "systemctl",
                    &["is-active", "--quiet", "hf-dispatcher.service"],
                )
            })
        };
        if let Err(error) = transition {
            if let Err(rollback) = self.restore_dispatcher(&previous) {
                return Err(anyhow::anyhow!(
                    "Dispatcher update failed ({error}); rollback also failed: {rollback}"
                ));
            }
            return Err(error);
        }
        tracing::info!(%trap_id, "Dispatcher route removed before stopping trap");
        Ok(Some(previous))
    }

    fn restore_dispatcher(&self, previous: &[u8]) -> anyhow::Result<()> {
        atomic_write(Path::new("/etc/honeyforge/dispatcher.json"), previous)?;
        run_program("systemctl", &["enable", "--now", "hf-dispatcher.service"])?;
        run_program("systemctl", &["restart", "hf-dispatcher.service"])
    }

    fn finish_remove(&self, trap_id: uuid::Uuid, result: &CommandResult) -> anyhow::Result<()> {
        // The caller has put final Low/Middle events into SQLite before `down` removes the
        // Docker container and the Middle runtime directory.
        self.compose_down(trap_id, true)?;
        let completed = self
            .root
            .join("commands")
            .join(format!("{}.json", result.command_id));
        fs::create_dir_all(completed.parent().expect("command parent"))?;
        atomic_write(&completed, &serde_json::to_vec(result)?)
    }

    fn compose<const N: usize>(
        &self,
        project_dir: &Path,
        trap_id: uuid::Uuid,
        args: [&str; N],
    ) -> anyhow::Result<()> {
        let project_name = format!("hf-{}", trap_id.simple());
        let status = Command::new("docker")
            .args(["compose", "--project-name", &project_name, "--file"])
            .arg(project_dir.join("compose.yaml"))
            .args(args)
            .status()?;
        if !status.success() {
            anyhow::bail!("docker compose exited with {status}");
        }
        Ok(())
    }
}

struct HttpRegistrationTransport {
    client: reqwest::Client,
    center_url: String,
}

#[async_trait::async_trait]
impl RegistrationTransport for HttpRegistrationTransport {
    async fn register(
        &self,
        registration: AgentRegistration,
    ) -> Result<RegisteredAgent, CoreError> {
        let url = format!(
            "{}/v1/agents/register",
            self.center_url.trim_end_matches('/')
        );
        let response = self
            .client
            .post(url)
            .json(&registration)
            .send()
            .await
            .map_err(|error| CoreError::Transport(error.to_string()))?
            .error_for_status()
            .map_err(|error| CoreError::Transport(error.to_string()))?;
        response
            .json()
            .await
            .map_err(|error| CoreError::Transport(error.to_string()))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "hf_agent=info".into()),
        )
        .init();
    let args = Args::parse();
    fs::create_dir_all(&args.state_dir)?;
    if let Err(error) = emergency::install(&args.state_dir) {
        if emergency::armed() {
            return Err(error.context("armed emergency service could not be installed"));
        }
        tracing::warn!(%error, "emergency service installation failed; monitoring will continue unarmed");
    }
    let identity_path = args.state_dir.join("identity.json");
    let identity = match load_identity(&identity_path)? {
        Some(identity) => identity,
        None => {
            tracing::info!("no local identity found; registering agent with center");
            let token = fs::read_to_string(&args.enrollment_token_file)?
                .trim()
                .to_owned();
            let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".into());
            let transport = HttpRegistrationTransport {
                client: reqwest::Client::new(),
                center_url: args.center_url,
            };
            let agent = transport
                .register(AgentRegistration {
                    enrollment_token: token,
                    hostname,
                    agent_version: env!("CARGO_PKG_VERSION").into(),
                })
                .await?;
            tracing::info!(agent_id = %agent.agent_id, "registration accepted by center");
            let identity = AgentIdentity {
                agent_id: agent.agent_id,
                transport_credential: agent.transport_credential,
                hysteria: agent.hysteria,
            };
            atomic_write(&identity_path, &serde_json::to_vec(&identity)?)?;
            identity
        }
    };
    tracing::info!(agent_id = %identity.agent_id, "agent is registered and running");
    if let Some(connection) = &identity.hysteria {
        ensure_hysteria_client(connection, &identity.transport_credential)?;
    }
    let compose_projects = ComposeProjectStore::new(&args.state_dir);
    fs::create_dir_all(&compose_projects.root)?;
    if emergency::pending(&args.state_dir)?.is_none() {
        let reconciliation_projects = compose_projects.clone();
        tokio::task::spawn_blocking(move || reconciliation_projects.reconcile_high_manifests())
            .await
            .map_err(|error| anyhow::anyhow!("High reconciliation worker failed: {error}"))?;
    } else {
        tracing::warn!(
            "High reconciliation skipped while a confirmed security incident is pending"
        );
    }
    if let Some(command_file) = args.command_file {
        anyhow::ensure!(
            emergency::pending(&args.state_dir)?.is_none(),
            "confirmed security incident blocks local commands"
        );
        let command: AgentCommand = serde_json::from_slice(&fs::read(command_file)?)?;
        let deferred_remove = compose_remove_id(&compose_projects, &command);
        let mut result = compose_projects.apply(
            command,
            &args.kozyavka_image,
            &args.pritvoryashka_image,
            identity.agent_id,
        )?;
        if let Some(trap_id) = deferred_remove.filter(|_| result.success) {
            let mut outbox = SqliteKazikOutbox::open(args.state_dir.join("kazik-outbox.sqlite"))?;
            result = finalize_removed_trap(
                &compose_projects,
                &args.state_dir,
                &identity,
                &mut outbox,
                trap_id,
                result,
            )?;
        }
        println!("{}", serde_json::to_string(&result)?);
        if !result.success {
            anyhow::bail!("command application failed: {}", result.detail);
        }
    }
    if args.once {
        return Ok(());
    }
    #[cfg(unix)]
    let _high_telemetry = high_telemetry::start(
        &args.state_dir,
        identity.agent_id,
        args.high_telemetry_max_pending,
        Duration::from_secs(args.high_operational_interval_seconds),
    )?;
    // Initial SSH bootstrap may seed one root-owned command here. Later commands arrive through
    // Kazik and use the same idempotent `apply` implementation.
    let inbox = args.state_dir.join("inbox");
    fs::create_dir_all(&inbox)?;
    let configured_transport = match (args.kazik_hysteria_socks, args.kazik_center_udp) {
        (Some(socks), Some(center_udp)) => Some((socks, center_udp)),
        (None, None) if identity.hysteria.is_some() => {
            Some(("127.0.0.1:1080".parse()?, "127.0.0.1:44000".parse()?))
        }
        (None, None) => None,
        _ => anyhow::bail!("HF_KAZIK_HYSTERIA_SOCKS and HF_KAZIK_CENTER_UDP must be set together"),
    };
    if let Some((socks, center_udp)) = configured_transport {
        return run_kazik_hysteria_loop(
            &args.state_dir,
            &inbox,
            &compose_projects,
            &args.kozyavka_image,
            &args.pritvoryashka_image,
            identity,
            socks,
            center_udp,
        )
        .await;
    }
    loop {
        if emergency::pending(&args.state_dir)?.is_none() {
            process_inbox(
                &inbox,
                &compose_projects,
                &args.kozyavka_image,
                &args.pritvoryashka_image,
                &identity,
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn run_kazik_hysteria_loop(
    state_dir: &Path,
    inbox: &Path,
    projects: &ComposeProjectStore,
    kozyavka_image: &str,
    pritvoryashka_image: &str,
    identity: AgentIdentity,
    socks: SocketAddr,
    center_udp: SocketAddr,
) -> anyhow::Result<()> {
    let mut transport: Option<Arc<HysteriaSocks5UdpTransport>> = None;
    let mut sender: Option<FailoverSender> = None;
    let mut reconnect = tokio::time::interval(Duration::from_secs(5));
    let mut outbox_retry = tokio::time::interval(Duration::from_secs(5));
    let mut outbox = SqliteKazikOutbox::open(state_dir.join("kazik-outbox.sqlite"))?;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(20));
    let mut telemetry_poll = tokio::time::interval(Duration::from_secs(5));
    let mut emergency_tick = tokio::time::interval(Duration::from_secs(1));
    let existing_incident = emergency::pending(state_dir)?;
    let mut incident_message_id = existing_incident.as_ref().map(|incident| incident.message_id);
    let mut missing_alert = None;
    if let Some(incident) = existing_incident.as_ref() {
        if emergency::alert_was_acknowledged(state_dir, incident.message_id)? {
            // The ACK marker is durable before the SQLite deletion. Finish an
            // interrupted deletion without resurrecting an acknowledged alert.
            outbox.acknowledge(incident.message_id)?;
        } else if outbox.contains(incident.message_id)? {
            outbox.prioritize(incident.message_id)?;
        } else {
            let event = emergency::alert_event(state_dir, incident)?;
            let mut envelope = KazikEnvelope::new(
                identity.agent_id,
                identity.transport_credential.clone(),
                event.occurred_at_unix_ms,
                KazikBody::Telemetry { events: vec![event] },
            );
            envelope.message_id = incident.message_id;
            missing_alert = Some(envelope);
        }
    }
    let mut incident_active = existing_incident.is_some();
    let mut pending_emergency = existing_incident
        .filter(|incident| incident.response_armed)
        .map(|incident| PendingEmergency {
            message_id: incident.message_id,
            began: std::time::Instant::now(),
            last_attempt: None,
        });
    let incident_flag = Arc::new(std::sync::atomic::AtomicBool::new(incident_active));
    let (security_tx, mut security_rx) = tokio::sync::mpsc::channel(256);
    tokio::spawn(security_monitor::run(projects.root.clone(), security_tx));
    let (confirmed_tx, mut confirmed_rx) = tokio::sync::mpsc::channel(8);
    let (quarantine_tx, mut quarantine_rx) = tokio::sync::mpsc::channel(32);
    let validation_slots = Arc::new(tokio::sync::Semaphore::new(4));
    let (command_tx, mut command_rx) = tokio::sync::mpsc::channel::<CommandJob>(32);
    let (result_tx, mut result_rx) = tokio::sync::mpsc::channel::<CommandExecution>(32);
    match projects.recover_quarantines() {
        Ok(events) => for event in events {
            outbox.enqueue(KazikEnvelope::new(identity.agent_id,
                identity.transport_credential.clone(), event.occurred_at_unix_ms,
                KazikBody::Telemetry { events: vec![event] }))?;
        },
        Err(error) => tracing::error!(%error, "could not scan persisted trap quarantines"),
    }
    let worker_projects = projects.clone();
    let worker_kozyavka_image = kozyavka_image.to_owned();
    let worker_pritvoryashka_image = pritvoryashka_image.to_owned();
    let worker_agent_id = identity.agent_id;
    let worker_incident_flag = incident_flag.clone();
    tokio::spawn(async move {
        while let Some(job) = command_rx.recv().await {
            let removed_trap = compose_remove_id(&worker_projects, &job.command);
            let projects = worker_projects.clone();
            let kozyavka_image = worker_kozyavka_image.clone();
            let pritvoryashka_image = worker_pritvoryashka_image.clone();
            let incident_flag = worker_incident_flag.clone();
            let result = tokio::task::spawn_blocking(move || {
                anyhow::ensure!(
                    !incident_flag.load(std::sync::atomic::Ordering::SeqCst),
                    "confirmed security incident blocks new commands"
                );
                projects.apply(
                    job.command,
                    &kozyavka_image,
                    &pritvoryashka_image,
                    worker_agent_id,
                )
            })
            .await
            .map_err(|error| anyhow::anyhow!("command worker panicked: {error}"))
            .and_then(|result| result);
            let (completion, completion_rx) = tokio::sync::oneshot::channel();
            if result_tx
                .send(CommandExecution {
                    message_id: job.message_id,
                    removed_trap,
                    completion: removed_trap.map(|_| completion),
                    result,
                })
                .await
                .is_err()
            {
                break;
            }
            if removed_trap.is_some() {
                let _ = completion_rx.await;
            }
        }
    });
    tracing::info!(agent_id = %identity.agent_id, "Kazik loop and independent security monitor started");
    loop {
        if !incident_active {
            process_inbox(
                inbox,
                projects,
                kozyavka_image,
                pritvoryashka_image,
                &identity,
            );
        }
        let receiving_transport = transport.clone();
        tokio::select! {
            _ = outbox_retry.tick() => {
                if let Some(alert) = missing_alert.clone() {
                    let message_id = alert.message_id;
                    match outbox.enqueue(alert).and_then(|_| outbox.prioritize(message_id)) {
                        Ok(()) => missing_alert = None,
                        Err(error) => tracing::error!(%error, %message_id, "escape alert could not be restored to SQLite; will retry"),
                    }
                }
                if let Some(sender) = sender.as_ref() {
                    if let Err(error) = send_pending_once(&mut outbox, sender, 64).await {
                        tracing::warn!(%error, "Kazik outbox delivery retry failed");
                    }
                }
            }
            _ = reconnect.tick(), if transport.is_none() => {
                match HysteriaSocks5UdpTransport::connect(socks, center_udp).await {
                    Ok(connected) => {
                        let connected = Arc::new(connected);
                        match FailoverSender::new(vec![connected.clone()]) {
                            Ok(ready) => {
                                tracing::info!(transport = connected.name(), "Kazik transport connected");
                                transport = Some(connected);
                                sender = Some(ready);
                                if let Some(sender) = sender.as_ref() {
                                    if let Err(error) = send_pending_once(&mut outbox, sender, 64).await {
                                        tracing::warn!(%error, "queued Kazik packets await retry");
                                    }
                                }
                            }
                            Err(error) => tracing::warn!(%error, "Kazik transport setup failed"),
                        }
                    }
                    Err(error) => tracing::warn!(%error, "Hysteria SOCKS5 is unavailable; security monitor remains active"),
                }
            }
            Some(observation) = security_rx.recv() => {
                if observation.event.payload["policy_decision"] == "isolate_trap"
                    && !incident_active {
                    let projects = projects.clone();
                    let trap_id = observation.event.trap_id;
                    let event_id = observation.event.event_id;
                    let candidate_is_being_validated = observation.candidate.is_some();
                    let tx = quarantine_tx.clone();
                    let trigger = observation.event.clone();
                    tokio::spawn(async move {
                        // Give the independent second-sample host-escape check a
                        // brief chance to preserve evidence before stopping the trap.
                        if candidate_is_being_validated {
                            tokio::time::sleep(Duration::from_millis(500)).await;
                        }
                        let fallback = trigger.clone();
                        let outcome = match tokio::task::spawn_blocking(move || projects.quarantine_trap(&trigger)).await {
                            Ok(Ok(event)) => {
                                tracing::error!(%trap_id, %event_id, "Low/Middle trap isolated; existing sessions closed");
                                event
                            }
                            result => {
                                tracing::error!(%trap_id, ?result, "trap quarantine failed; manual intervention required");
                                quarantine_result(&QuarantineMarker { trigger: fallback,
                                    result_event_id: uuid::Uuid::new_v4() }, false)
                            }
                        };
                        let _ = tx.send(outcome).await;
                    });
                }
                if !incident_active {
                    if let Some(candidate) = observation.candidate {
                        if let Ok(permit) = validation_slots.clone().try_acquire_owned() {
                            let tx = confirmed_tx.clone();
                            let trap_root = projects.root.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
                                match security_monitor::confirm_escape(&candidate, &trap_root).await {
                                    Ok(Some(event)) => { let _ = tx.send(event).await; }
                                    Ok(None) => {}
                                    Err(error) => tracing::warn!(%error, "escape confirmation failed; host remains online"),
                                }
                            });
                        } else {
                            tracing::warn!("escape validation slots are full; candidate was not validated");
                        }
                    }
                }
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_millis() as i64;
                outbox.enqueue(KazikEnvelope::new(
                    identity.agent_id,
                    identity.transport_credential.clone(),
                    now,
                    KazikBody::Telemetry { events: vec![observation.event] },
                ))?;
                if let Some(sender) = sender.as_ref() {
                    if let Err(error) = send_pending_once(&mut outbox, sender, 64).await {
                        tracing::warn!(%error, "security event remains in SQLite outbox");
                    }
                }
            }
            Some(event) = quarantine_rx.recv() => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?.as_millis() as i64;
                outbox.enqueue(KazikEnvelope::new(identity.agent_id,
                    identity.transport_credential.clone(), now,
                    KazikBody::Telemetry { events: vec![event] }))?;
                if let Some(sender) = sender.as_ref() {
                    if let Err(error) = send_pending_once(&mut outbox, sender, 64).await {
                        tracing::warn!(%error, "quarantine result remains in SQLite outbox");
                    }
                }
            }
            Some(event) = confirmed_rx.recv() => {
                if !incident_active {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_millis() as i64;
                    let envelope = KazikEnvelope::new(
                        identity.agent_id,
                        identity.transport_credential.clone(),
                        now,
                        KazikBody::Telemetry { events: vec![event.clone()] },
                    );
                    let message_id = envelope.message_id;
                    let response_armed = emergency::armed();
                    emergency::record(state_dir, &event, message_id)?;
                    incident_active = true;
                    incident_message_id = Some(message_id);
                    incident_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    if response_armed {
                        pending_emergency = Some(PendingEmergency {
                            message_id,
                            began: std::time::Instant::now(),
                            last_attempt: None,
                        });
                    }
                    // A database failure must not cancel an already recorded local response.
                    match outbox.enqueue(envelope.clone()).and_then(|_| outbox.prioritize(message_id)) {
                        Ok(()) => tracing::error!(trap_id = %event.trap_id, %message_id, "confirmed escape recorded; alert queued before emergency response"),
                        Err(error) => {
                            missing_alert = Some(envelope);
                            tracing::error!(%error, %message_id, "could not queue escape alert; local response remains active and queueing will retry");
                        }
                    }
                    if let Some(sender) = sender.as_ref() {
                        if let Err(error) = send_pending_once(&mut outbox, sender, 64).await {
                            tracing::warn!(%error, "confirmed escape alert remains in SQLite outbox");
                        }
                    }
                }
            }
            _ = emergency_tick.tick(), if pending_emergency.is_some() => {
                let should_attempt = pending_emergency.as_ref().is_some_and(|pending| {
                    pending.began.elapsed() >= Duration::from_secs(15)
                        && pending.last_attempt.is_none_or(|last| last.elapsed() >= Duration::from_secs(30))
                });
                if should_attempt {
                    if let Some(pending) = pending_emergency.as_mut() {
                        pending.last_attempt = Some(std::time::Instant::now());
                    }
                    match emergency::start(state_dir) {
                        Ok(()) => pending_emergency = None,
                        Err(error) => tracing::error!(%error, "could not start emergency service; will retry"),
                    }
                }
            }
            Some(execution) = result_rx.recv() => {
                let mut result = execution.result;
                let finalization = match (execution.removed_trap, &result) {
                    (Some(trap_id), Ok(command_result)) if command_result.success => {
                        Some((trap_id, command_result.clone()))
                    }
                    _ => None,
                };
                if let Some((trap_id, command_result)) = finalization {
                    result = finalize_removed_trap(
                        projects, state_dir, &identity, &mut outbox, trap_id, command_result,
                    );
                }
                if let Some(completion) = execution.completion {
                    let _ = completion.send(());
                }
                let (disposition, detail) = match result {
                    Ok(result) if result.success => (AckDisposition::Applied, None),
                    Ok(result) => (AckDisposition::Rejected, Some(result.detail)),
                    Err(error) => (AckDisposition::Rejected, Some(error.to_string())),
                };
                enqueue_ack(&mut outbox, &identity, execution.message_id, disposition, detail)?;
                if let Some(sender) = sender.as_ref() {
                    if let Err(error) = send_pending_once(&mut outbox, sender, 64).await {
                        tracing::warn!(%error, "command result ACK remains in SQLite outbox");
                    }
                }
            }
            _ = telemetry_poll.tick() => {
                match telemetry::collect_new_events(
                    &projects.root,
                    state_dir,
                    &identity,
                    &mut outbox,
                ) {
                    Ok(count) if count > 0 => {
                        tracing::info!(events = count, "trap telemetry queued for Center");
                        if let Some(sender) = sender.as_ref() {
                            if let Err(error) = send_pending_once(&mut outbox, sender, 64).await {
                                tracing::warn!(%error, "trap telemetry remains in durable outbox");
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(error) => tracing::warn!(%error, "trap telemetry collection failed"),
                }
            }
            _ = heartbeat.tick() => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|duration| duration.as_millis() as i64)
                    .unwrap_or_default();
                let active_trap_count = projects.active_trap_count();
                outbox.enqueue(KazikEnvelope::new(
                    identity.agent_id,
                    identity.transport_credential.clone(),
                    now,
                    KazikBody::Heartbeat { status: AgentStatus {
                        hostname: std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".into()),
                        active_trap_count,
                    }},
                ))?;
                if let Some(sender) = sender.as_ref() {
                    if let Err(error) = send_pending_once(&mut outbox, sender, 64).await {
                        tracing::warn!(%error, "Kazik pending packets remain in SQLite outbox");
                    }
                }
            }
            received = async move {
                match receiving_transport {
                    Some(transport) => transport.receive().await,
                    None => std::future::pending().await,
                }
            } => match received {
                Ok(packet) => match KazikEnvelope::decode_hfsp(&packet) {
                    Ok((envelope, _, _)) if envelope.agent_id == identity.agent_id
                        && envelope.transport_credential == identity.transport_credential => {
                        match envelope.body {
                            KazikBody::Ack(ack)
                                if matches!(ack.disposition, AckDisposition::Accepted | AckDisposition::Applied | AckDisposition::Duplicate) => {
                                    if incident_message_id == Some(ack.acknowledged_message_id) {
                                        emergency::record_alert_ack(state_dir, ack.acknowledged_message_id)?;
                                        missing_alert = None;
                                    }
                                    outbox.acknowledge(ack.acknowledged_message_id)?;
                                    if pending_emergency.as_ref().is_some_and(|pending| pending.message_id == ack.acknowledged_message_id) {
                                        match emergency::start(state_dir) {
                                            Ok(()) => pending_emergency = None,
                                            Err(error) => tracing::error!(%error, "alert acknowledged but emergency service could not start"),
                                        }
                                    }
                                }
                            KazikBody::Command { command } => {
                                if incident_active || command_tx.try_send(CommandJob { message_id: envelope.message_id, command }).is_err() {
                                    enqueue_ack(
                                        &mut outbox,
                                        &identity,
                                        envelope.message_id,
                                        AckDisposition::Rejected,
                                        Some("agent is handling a confirmed security incident, or command queue is unavailable".into()),
                                    )?;
                                }
                            }
                            KazikBody::Ack(_) => {}
                            _ => {
                                enqueue_ack(
                                    &mut outbox,
                                    &identity,
                                    envelope.message_id,
                                    AckDisposition::Rejected,
                                    Some("message body is not valid from center to agent".into()),
                                )?;
                            }
                        }
                    }
                    Ok(_) => tracing::warn!("discarded Kazik packet with mismatched agent credential"),
                    Err(error) => tracing::warn!(%error, "discarded malformed Kazik packet"),
                },
                Err(error) => {
                    tracing::warn!(%error, "Kazik transport receive failed; retrying");
                    transport = None;
                    sender = None;
                }
            }
        }
    }
}

struct CommandJob {
    message_id: uuid::Uuid,
    command: AgentCommand,
}

struct PendingEmergency {
    message_id: uuid::Uuid,
    began: std::time::Instant,
    last_attempt: Option<std::time::Instant>,
}

struct CommandExecution {
    message_id: uuid::Uuid,
    removed_trap: Option<uuid::Uuid>,
    completion: Option<tokio::sync::oneshot::Sender<()>>,
    result: anyhow::Result<CommandResult>,
}

fn enqueue_ack(
    outbox: &mut SqliteKazikOutbox,
    identity: &AgentIdentity,
    acknowledged_message_id: uuid::Uuid,
    disposition: AckDisposition,
    detail: Option<String>,
) -> anyhow::Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default();
    outbox.enqueue(KazikEnvelope::new(
        identity.agent_id,
        identity.transport_credential.clone(),
        now,
        KazikBody::Ack(Acknowledgement {
            acknowledged_message_id,
            disposition,
            detail,
        }),
    ))?;
    Ok(())
}

/// Materialize the per-agent Hysteria client only after the center has consumed the one-time
/// enrollment token. The transport credential is root-readable only and TLS verification stays
/// enabled by deliberately omitting Hysteria's `insecure` option.
fn ensure_hysteria_client(connection: &HysteriaConnection, credential: &str) -> anyhow::Result<()> {
    validate_hysteria_config_value("server", &connection.server)?;
    validate_hysteria_config_value("sni", &connection.sni)?;
    validate_hysteria_config_value("credential", credential)?;
    if !Path::new("/usr/local/bin/hysteria").is_file() {
        anyhow::bail!(
            "Hysteria endpoint was issued but /usr/local/bin/hysteria is absent; bootstrap with HF_HYSTERIA_BINARY"
        );
    }
    if !Command::new("systemctl")
        .arg("--version")
        .status()
        .is_ok_and(|status| status.success())
    {
        anyhow::bail!("Hysteria client service currently requires systemd");
    }
    fs::create_dir_all("/etc/honeyforge")?;
    let client_config = format!(
        "server: \"{}\"\nauth: \"{}\"\ntls:\n  sni: \"{}\"\nsocks5:\n  listen: 127.0.0.1:1080\n  disableUDP: false\n",
        connection.server, credential, connection.sni
    );
    atomic_write(
        Path::new("/etc/honeyforge/hysteria-client.yaml"),
        client_config.as_bytes(),
    )?;
    atomic_write(
        Path::new("/etc/systemd/system/hf-hysteria-client.service"),
        b"[Unit]\nDescription=HoneyForge Hysteria client\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=simple\nExecStart=/usr/local/bin/hysteria client -c /etc/honeyforge/hysteria-client.yaml\nRestart=always\nRestartSec=3\nNoNewPrivileges=true\n[Install]\nWantedBy=multi-user.target\n",
    )?;
    run_program("systemctl", &["daemon-reload"])?;
    run_program(
        "systemctl",
        &["enable", "--now", "hf-hysteria-client.service"],
    )?;
    tracing::info!(server = %connection.server, sni = %connection.sni, "Hysteria client service is enabled");
    Ok(())
}

fn validate_hysteria_config_value(name: &str, value: &str) -> anyhow::Result<()> {
    if value.is_empty()
        || value.len() > 253
        || value
            .chars()
            .any(|c| c.is_control() || c == '"' || c == '\\')
    {
        anyhow::bail!("unsafe Hysteria {name} value");
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Platform {
    Debian,
    Fedora,
    Rhel,
    Arch,
    Alpine,
}

fn parse_platform(os_release: &str) -> anyhow::Result<Platform> {
    let id = os_release
        .lines()
        .find_map(|line| line.strip_prefix("ID="))
        .map(|value| value.trim_matches('"').to_ascii_lowercase())
        .ok_or_else(|| anyhow::anyhow!("/etc/os-release has no ID field"))?;
    match id.as_str() {
        "debian" | "ubuntu" | "linuxmint" => Ok(Platform::Debian),
        "fedora" => Ok(Platform::Fedora),
        "rhel" | "centos" | "rocky" | "almalinux" => Ok(Platform::Rhel),
        "arch" | "manjaro" => Ok(Platform::Arch),
        "alpine" => Ok(Platform::Alpine),
        _ => anyhow::bail!(
            "unsupported Linux distribution '{id}'; supported: Debian/Ubuntu, Fedora, RHEL/Rocky/Alma/CentOS, Arch/Manjaro, Alpine"
        ),
    }
}

fn detect_platform() -> anyhow::Result<Platform> {
    parse_platform(&fs::read_to_string("/etc/os-release")?)
}

/// Idempotently installs Docker Engine and the Compose v2 plugin using the platform's package
/// manager. The service bootstrap runs this as root before it accepts any trap command.
fn ensure_docker_runtime() -> anyhow::Result<()> {
    if docker_compose_available() {
        tracing::info!("Docker Engine and Compose plugin are ready");
        return Ok(());
    }
    let platform = detect_platform()?;
    tracing::warn!(
        ?platform,
        "Docker Compose is absent; provisioning Docker runtime"
    );
    match platform {
        Platform::Debian => {
            run_program("apt-get", &["update"])?;
            run_program(
                "apt-get",
                &["install", "-y", "docker.io", "docker-compose-v2"],
            )?;
            run_program("systemctl", &["enable", "--now", "docker"])?;
        }
        Platform::Fedora => {
            run_program("dnf", &["install", "-y", "dnf-plugins-core"])?;
            run_program(
                "dnf",
                &[
                    "config-manager",
                    "--add-repo",
                    "https://download.docker.com/linux/fedora/docker-ce.repo",
                ],
            )?;
            install_docker_ce_with_dnf()?;
        }
        Platform::Rhel => {
            run_program("dnf", &["install", "-y", "dnf-plugins-core"])?;
            run_program(
                "dnf",
                &[
                    "config-manager",
                    "--add-repo",
                    "https://download.docker.com/linux/rhel/docker-ce.repo",
                ],
            )?;
            install_docker_ce_with_dnf()?;
        }
        Platform::Arch => {
            run_program(
                "pacman",
                &["-Sy", "--noconfirm", "docker", "docker-compose"],
            )?;
            run_program("systemctl", &["enable", "--now", "docker"])?;
        }
        Platform::Alpine => {
            run_program("apk", &["add", "docker", "docker-cli-compose"])?;
            run_program("rc-update", &["add", "docker", "default"])?;
            run_program("service", &["docker", "start"])?;
        }
    }
    if !docker_compose_available() {
        anyhow::bail!("Docker installation completed but docker compose is unavailable");
    }
    Ok(())
}

fn install_docker_ce_with_dnf() -> anyhow::Result<()> {
    run_program(
        "dnf",
        &[
            "install",
            "-y",
            "docker-ce",
            "docker-ce-cli",
            "containerd.io",
            "docker-buildx-plugin",
            "docker-compose-plugin",
        ],
    )?;
    run_program("systemctl", &["enable", "--now", "docker"])
}

/// KVM/libvirt dependencies are separate from Docker because High runs a real guest VM.
fn ensure_high_vm_runtime() -> anyhow::Result<()> {
    let required_tools = [
        "virsh",
        "virt-install",
        "qemu-img",
        "cloud-localds",
        "iptables",
        "ss",
    ];
    let tools_ready = required_tools
        .iter()
        .all(|program| Command::new(program).arg("--version").output().is_ok());
    if !tools_ready {
        match detect_platform()? {
            Platform::Debian => {
                run_program("apt-get", &["update"])?;
                run_program(
                    "apt-get",
                    &[
                        "install",
                        "-y",
                        "qemu-kvm",
                        "libvirt-daemon-system",
                        "libvirt-clients",
                        "virtinst",
                        "cloud-image-utils",
                        "iptables",
                        "iproute2",
                        "curl",
                    ],
                )?;
                run_program("systemctl", &["enable", "--now", "libvirtd"])?;
            }
            Platform::Fedora | Platform::Rhel => {
                run_program(
                    "dnf",
                    &[
                        "install",
                        "-y",
                        "qemu-kvm",
                        "libvirt",
                        "virt-install",
                        "cloud-utils",
                        "iptables-nft",
                        "curl",
                    ],
                )?;
                run_program("systemctl", &["enable", "--now", "libvirtd"])?;
            }
            Platform::Arch => {
                run_program(
                    "pacman",
                    &[
                        "-Sy",
                        "--noconfirm",
                        "qemu-desktop",
                        "libvirt",
                        "virt-install",
                        "cloud-image-utils",
                        "iptables-nft",
                        "curl",
                    ],
                )?;
                run_program("systemctl", &["enable", "--now", "libvirtd"])?;
            }
            Platform::Alpine => anyhow::bail!("High Ubuntu VM is not supported on Alpine yet"),
        }
    }
    anyhow::ensure!(
        required_tools
            .iter()
            .all(|program| Command::new(program).arg("--version").output().is_ok()),
        "High VM runtime installation did not provide every required tool"
    );
    anyhow::ensure!(
        Path::new("/dev/kvm").exists(),
        "KVM is unavailable; this VPS/provider does not permit High VM traps"
    );
    Ok(())
}

fn docker_compose_available() -> bool {
    Command::new("docker")
        .args(["compose", "version"])
        .status()
        .is_ok_and(|status| status.success())
}

fn validate_container_image(image: &str, trap_name: &str) -> anyhow::Result<()> {
    if image.is_empty()
        || image
            .chars()
            .any(|character| !(character.is_ascii_alphanumeric() || "._/-:@".contains(character)))
    {
        anyhow::bail!("unsafe {trap_name} image reference");
    }
    Ok(())
}

fn run_program(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new(program).args(args).status()?;
    if !status.success() {
        anyhow::bail!("{program} exited with {status}");
    }
    Ok(())
}

fn compose_remove_id(projects: &ComposeProjectStore, command: &AgentCommand) -> Option<uuid::Uuid> {
    match command {
        AgentCommand::RemoveTrap { trap_id, .. }
            if !projects.high_manifest_path(*trap_id).is_file()
                && !projects.has_high_runtime(*trap_id)
                && projects
                    .root
                    .join(trap_id.to_string())
                    .join("compose.yaml")
                    .is_file() =>
        {
            Some(*trap_id)
        }
        _ => None,
    }
}

fn finalize_removed_trap(
    projects: &ComposeProjectStore,
    state_dir: &Path,
    identity: &AgentIdentity,
    outbox: &mut SqliteKazikOutbox,
    trap_id: uuid::Uuid,
    result: CommandResult,
) -> anyhow::Result<CommandResult> {
    let count = telemetry::collect_new_events(&projects.root, state_dir, identity, outbox)?;
    if count > 0 {
        tracing::info!(events = count, %trap_id, "final trap telemetry queued before removal");
    }
    projects.finish_remove(trap_id, &result)?;
    Ok(result)
}

fn process_inbox(
    inbox: &Path,
    projects: &ComposeProjectStore,
    kozyavka_image: &str,
    pritvoryashka_image: &str,
    identity: &AgentIdentity,
) {
    let entries = match fs::read_dir(inbox) {
        Ok(entries) => entries,
        Err(error) => {
            tracing::error!(%error, "cannot read command inbox");
            return;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let result = fs::read(&path)
            .map_err(anyhow::Error::from)
            .and_then(|bytes| Ok(serde_json::from_slice::<AgentCommand>(&bytes)?))
            .and_then(|command| {
                let deferred_remove = compose_remove_id(projects, &command);
                let result = projects.apply(
                    command,
                    kozyavka_image,
                    pritvoryashka_image,
                    identity.agent_id,
                )?;
                if let Some(trap_id) = deferred_remove.filter(|_| result.success) {
                    let state_dir = inbox.parent().expect("inbox parent");
                    let mut outbox =
                        SqliteKazikOutbox::open(state_dir.join("kazik-outbox.sqlite"))?;
                    finalize_removed_trap(
                        projects,
                        state_dir,
                        identity,
                        &mut outbox,
                        trap_id,
                        result,
                    )
                } else {
                    Ok(result)
                }
            });
        match result {
            Ok(result) if result.success => {
                let processed = inbox.join("processed");
                if let Err(error) = fs::create_dir_all(&processed)
                    .and_then(|_| fs::rename(&path, processed.join(entry.file_name())))
                {
                    tracing::error!(%error, path = %path.display(), "command was applied but could not be archived");
                } else {
                    tracing::info!(command_id = %result.command_id, trap_id = %result.trap_id, "trap command applied");
                }
            }
            Ok(result) => archive_failed_command(inbox, &path, &entry.file_name(), &result.detail),
            Err(error) => {
                archive_failed_command(inbox, &path, &entry.file_name(), &error.to_string())
            }
        }
    }
}

fn archive_failed_command(inbox: &Path, path: &Path, file_name: &std::ffi::OsStr, detail: &str) {
    tracing::error!(path = %path.display(), %detail, "trap command failed");
    let failed = inbox.join("failed");
    if let Err(error) =
        fs::create_dir_all(&failed).and_then(|_| fs::rename(path, failed.join(file_name)))
    {
        tracing::error!(%error, path = %path.display(), "could not archive failed command");
    }
}

fn load_identity(path: &Path) -> anyhow::Result<Option<AgentIdentity>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn atomic_write(path: &Path, content: &[u8]) -> anyhow::Result<()> {
    let temporary = path.with_extension("tmp");
    let mut file = fs::File::create(&temporary)?;
    file.write_all(content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
    }
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, path)?;
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{DispatcherConfig, DispatcherListener, DispatcherTarget, Platform, QuarantineMarker, quarantine_result, parse_platform};

    fn detach_dispatcher_target(
        &self,
        trap_id: uuid::Uuid,
        shared_backend: bool,
    ) -> anyhow::Result<Option<Vec<u8>>> {
    use uuid::Uuid;

    #[test]
    fn quarantine_recovery_reuses_the_same_event_id() {
        let trigger = kazik_protocol::TrapEvent {
            event_id: Uuid::new_v4(), trap_id: Uuid::new_v4(), session_id: None,
            source_sequence_no: None, occurred_at_unix_ms: 1, event_type: "security.resource_access".into(),
            source_ip: None, source_port: None, destination_port: None,
            protocol: "local".into(), service_type: "host_monitor".into(),
            payload: serde_json::json!({"policy_decision":"isolate_trap"}),
            metadata: serde_json::json!({"source":"hf-agent-ebpf"}),
        };
        let marker = QuarantineMarker { trigger, result_event_id: Uuid::new_v4() };
        let first = quarantine_result(&marker, true);
        let replay = quarantine_result(&marker, true);
        assert_eq!(first.event_id, replay.event_id);
        assert_eq!(first.payload["trigger_event_id"], marker.trigger.event_id.to_string());
        assert_eq!(first.event_type, "security.trap_quarantined");
        assert_eq!(quarantine_result(&marker, false).event_type, "security.trap_quarantine_failed");
    }

    fn target(weight: u8) -> DispatcherTarget {
        DispatcherTarget {
            trap_id: Uuid::new_v4(),
            address: "127.0.0.1:31001".parse().unwrap(),
            weight,
        }
    }

    #[test]
    fn removing_a_shared_trap_rebalances_remaining_routes() {
        let first = target(25);
        let removed = target(25);
        let third = target(50);
        let config = DispatcherConfig {
            version: 1,
            listeners: vec![DispatcherListener {
                listen: "0.0.0.0:2222".parse().unwrap(),
                targets: vec![first.clone(), removed.clone(), third.clone()],
            }],
        };
        let updated = config.without_trap(removed.trap_id).unwrap().unwrap();
        assert_eq!(updated.listeners[0].targets.len(), 2);
        assert_eq!(updated.listeners[0].targets[0].trap_id, first.trap_id);
        assert_eq!(updated.listeners[0].targets[0].weight, 33);
        assert_eq!(updated.listeners[0].targets[1].trap_id, third.trap_id);
        assert_eq!(updated.listeners[0].targets[1].weight, 67);
        let pair = DispatcherConfig {
            version: 1,
            listeners: vec![DispatcherListener {
                listen: "0.0.0.0:2222".parse().unwrap(),
                targets: vec![target(50), target(50)],
            }],
        };
        let removed = pair.listeners[0].targets[0].trap_id;
        let updated = pair.without_trap(removed).unwrap().unwrap();
        assert_eq!(updated.listeners[0].targets[0].weight, 100);
    }

    #[test]
    fn removing_last_group_member_drops_only_its_listener() {
        let removed = target(100);
        let survivor = target(100);
        let config = DispatcherConfig {
            version: 1,
            listeners: vec![
                DispatcherListener {
                    listen: "0.0.0.0:2222".parse().unwrap(),
                    targets: vec![removed.clone()],
                },
                DispatcherListener {
                    listen: "0.0.0.0:2223".parse().unwrap(),
                    targets: vec![survivor.clone()],
                },
            ],
        };
        let updated = config.without_trap(removed.trap_id).unwrap().unwrap();
        assert_eq!(updated.listeners.len(), 1);
        assert_eq!(updated.listeners[0].listen, "0.0.0.0:2223".parse().unwrap());
        assert_eq!(updated.listeners[0].targets[0].trap_id, survivor.trap_id);
        assert!(
            updated
                .without_trap(survivor.trap_id)
                .unwrap()
                .unwrap()
                .listeners
                .is_empty()
        );
    }

    #[test]
    fn malformed_dispatcher_routes_are_not_rewritten() {
        let removed = target(40);
        let config = DispatcherConfig {
            version: 1,
            listeners: vec![DispatcherListener {
                listen: "0.0.0.0:2222".parse().unwrap(),
                targets: vec![removed.clone()],
            }],
        };
        assert!(config.without_trap(removed.trap_id).is_err());
    }

    #[test]
    fn recognizes_supported_distribution_ids() {
        assert_eq!(
            parse_platform("NAME=Ubuntu\nID=ubuntu\n").unwrap(),
            Platform::Debian
        );
        assert_eq!(parse_platform("ID=rocky\n").unwrap(), Platform::Rhel);
        assert_eq!(parse_platform("ID=fedora\n").unwrap(), Platform::Fedora);
        assert_eq!(parse_platform("ID=manjaro\n").unwrap(), Platform::Arch);
        assert_eq!(parse_platform("ID=alpine\n").unwrap(), Platform::Alpine);
    }

    #[test]
    fn rejects_unknown_distribution() {
        assert!(parse_platform("ID=gentoo\n").is_err());
        assert!(parse_platform("NAME=missing-id\n").is_err());
    }

    #[test]
    fn high_manifest_round_trip_preserves_reset_configuration_and_desired_state() {
        let directory = std::env::temp_dir().join(format!("hf-high-manifest-{}", Uuid::new_v4()));
        let store = ComposeProjectStore::new(&directory);
        let trap_id = Uuid::new_v4();
        let manifest = HighRuntimeManifest {
            version: 1,
            kind: "high_ubuntu_ssh".into(),
            deployment: HighUbuntuDeployment {
                command_id: Uuid::new_v4(),
                trap_id,
                base_image: "/images/prepared.qcow2".into(),
                external_ssh_port: 2222,
            },
            desired_state: HighDesiredState::Stopped,
            last_error: Some("test error".into()),
        };
        store.save_high_manifest(&manifest).unwrap();
        let recovered = store.load_high_manifest(trap_id).unwrap().unwrap();
        assert_eq!(
            recovered.deployment.base_image,
            manifest.deployment.base_image
        );
        assert_eq!(recovered.deployment.external_ssh_port, 2222);
        assert_eq!(recovered.desired_state, HighDesiredState::Stopped);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn compose_remove_is_deferred_for_compose_traps() {
        let directory = std::env::temp_dir().join(format!("hf-compose-remove-{}", Uuid::new_v4()));
        let store = ComposeProjectStore::new(&directory);
        let trap_id = Uuid::new_v4();
        let project = store.root.join(trap_id.to_string());
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("compose.yaml"), "services: {}\n").unwrap();
        let command = AgentCommand::RemoveTrap {
            command_id: Uuid::new_v4(),
            trap_id,
        };

        assert_eq!(compose_remove_id(&store, &command), Some(trap_id));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn high_manifest_prevents_accidental_compose_deferred_removal() {
        let directory = std::env::temp_dir().join(format!("hf-high-remove-{}", Uuid::new_v4()));
        let store = ComposeProjectStore::new(&directory);
        let trap_id = Uuid::new_v4();
        let project = store.root.join(trap_id.to_string());
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("compose.yaml"), "services: {}\n").unwrap();
        store
            .save_high_manifest(&HighRuntimeManifest {
                version: 1,
                kind: "high_ubuntu_ssh".into(),
                deployment: HighUbuntuDeployment {
                    command_id: Uuid::new_v4(),
                    trap_id,
                    base_image: "/images/prepared.qcow2".into(),
                    external_ssh_port: 2222,
                },
                desired_state: HighDesiredState::Running,
                last_error: None,
            })
            .unwrap();
        let command = AgentCommand::RemoveTrap {
            command_id: Uuid::new_v4(),
            trap_id,
        };

        assert_eq!(compose_remove_id(&store, &command), None);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn legacy_high_runtime_prevents_accidental_compose_deferred_removal() {
        let directory =
            std::env::temp_dir().join(format!("hf-legacy-high-remove-{}", Uuid::new_v4()));
        let store = ComposeProjectStore::new(&directory);
        let trap_id = Uuid::new_v4();
        let project = store.root.join(trap_id.to_string());
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("compose.yaml"), "services: {}\n").unwrap();
        fs::create_dir_all(directory.join("high").join(trap_id.to_string())).unwrap();
        let command = AgentCommand::RemoveTrap {
            command_id: Uuid::new_v4(),
            trap_id,
        };

        assert_eq!(compose_remove_id(&store, &command), None);
        fs::remove_dir_all(directory).unwrap();
    }
}
