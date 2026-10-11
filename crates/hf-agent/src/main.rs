use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::Duration,
};

mod sandbox;

use anyhow::Context;
use clap::Parser;
use hf_core::{
    AgentCommand, AgentRegistration, CommandResult, CoreError, HysteriaConnection,
    KozyavkaDeployment, PacketTransport, PritvoryashkaDeployment, RegisteredAgent,
    RegistrationTransport, SharedTcpTrapKind, TcpPortGroup, TrapSpec,
};
use hf_services::{
    FailoverSender, HysteriaSocks5UdpTransport,
    kazik_outbox::{SqliteKazikOutbox, send_pending_once},
};
use kazik_protocol::{
    AckDisposition, Acknowledgement, AgentStatus, DurableOutbox, KazikBody, KazikEnvelope,
};
use sandbox::{LibvirtSandboxManager, UbuntuSshVm, default_recipe_dir};
use serde::{Deserialize, Serialize};
use tracing_subscriber::EnvFilter;

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

impl ComposeProjectStore {
    fn new(state_dir: &Path) -> Self {
        Self {
            root: state_dir.join("traps"),
        }
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
            return Ok(serde_json::from_slice(&fs::read(completed)?)?);
        }
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
                let base_image = PathBuf::from(deployment.base_image);
                LibvirtSandboxManager::new(default_recipe_dir()).create_and_start(&UbuntuSshVm {
                    instance_id: deployment.trap_id,
                    base_image,
                    external_ssh_port: deployment.external_ssh_port,
                })
            }
            AgentCommand::ResetHighUbuntu { trap_id, .. } => {
                LibvirtSandboxManager::new(default_recipe_dir()).reset(trap_id)
            }
            AgentCommand::ReconcileTcpPortGroup(group) => {
                ensure_docker_runtime()?;
                self.reconcile_tcp_port_group(group, kozyavka_image, pritvoryashka_image, agent_id)
            }
            AgentCommand::StopTrap { .. } => self.compose_down(trap_id, false),
            AgentCommand::RemoveTrap { .. } => self.compose_down(trap_id, true),
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
        if result.success {
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
        let compose = format!(
            "name: hf-{}\nservices:\n  honeypot:\n    image: {}\n    restart: unless-stopped\n    command: [\"--config\", \"/etc/honeyforge/config.json\"]\n    ports:\n      - \"{}:{}:{}/tcp\"\n    volumes:\n      - ./config.json:/etc/honeyforge/config.json:ro\n    read_only: true\n    cap_drop: [ALL]\n    security_opt: [no-new-privileges:true]\n    init: true\n",
            deployment.trap_id.simple(),
            image,
            deployment.publish_address,
            deployment.host_port,
            deployment.container_port,
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
            || !(1..=10_000).contains(&deployment.max_connections)
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
                "endpoint": null,
                "token_env": null,
                "jsonl_path": "/var/lib/pritvoryashka/events.jsonl",
                "queue_capacity": 1024,
                "batch_size": 50,
                "flush_interval_ms": 500,
                "max_event_bytes": 65536
            },
            "max_connections": deployment.max_connections,
            "idle_timeout_seconds": 600,
            "max_input_bytes": 8192
        });
        atomic_write(
            &project_dir.join("pritvoryashka.json"),
            &serde_json::to_vec_pretty(&container_config)?,
        )?;
        let compose = format!(
            "name: hf-{}\nservices:\n  honeypot:\n    image: {}\n    restart: unless-stopped\n    ports:\n      - \"{}:{}:2222/tcp\"\n    volumes:\n      - ./pritvoryashka.json:/etc/honeyforge/pritvoryashka.json:ro\n      - ./runtime:/var/lib/pritvoryashka\n    read_only: true\n    cap_drop: [ALL]\n    security_opt: [no-new-privileges:true]\n    init: true\n",
            deployment.trap_id.simple(),
            image,
            deployment.publish_address,
            deployment.host_port,
        );
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
    if let Some(command_file) = args.command_file {
        let command: AgentCommand = serde_json::from_slice(&fs::read(command_file)?)?;
        let result = compose_projects.apply(
            command,
            &args.kozyavka_image,
            &args.pritvoryashka_image,
            identity.agent_id,
        )?;
        println!("{}", serde_json::to_string(&result)?);
        if !result.success {
            anyhow::bail!("command application failed: {}", result.detail);
        }
    }
    if args.once {
        return Ok(());
    }
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
        process_inbox(
            &inbox,
            &compose_projects,
            &args.kozyavka_image,
            &args.pritvoryashka_image,
            identity.agent_id,
        );
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
    let transport = Arc::new(HysteriaSocks5UdpTransport::connect(socks, center_udp).await?);
    let sender = FailoverSender::new(vec![transport.clone()])
        .map_err(|error| anyhow::anyhow!("Kazik transport setup failed: {error}"))?;
    let mut outbox = SqliteKazikOutbox::open(state_dir.join("kazik-outbox.sqlite"))?;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(20));
    let (command_tx, mut command_rx) = tokio::sync::mpsc::channel::<CommandJob>(32);
    let (result_tx, mut result_rx) = tokio::sync::mpsc::channel::<CommandExecution>(32);
    let worker_projects = projects.clone();
    let worker_kozyavka_image = kozyavka_image.to_owned();
    let worker_pritvoryashka_image = pritvoryashka_image.to_owned();
    let worker_agent_id = identity.agent_id;
    tokio::spawn(async move {
        while let Some(job) = command_rx.recv().await {
            let projects = worker_projects.clone();
            let kozyavka_image = worker_kozyavka_image.clone();
            let pritvoryashka_image = worker_pritvoryashka_image.clone();
            let result = tokio::task::spawn_blocking(move || {
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
            if result_tx
                .send(CommandExecution {
                    message_id: job.message_id,
                    result,
                })
                .await
                .is_err()
            {
                break;
            }
        }
    });
    tracing::info!(agent_id = %identity.agent_id, transport = transport.name(), "Kazik Hysteria loop started");
    loop {
        process_inbox(
            inbox,
            projects,
            kozyavka_image,
            pritvoryashka_image,
            identity.agent_id,
        );
        tokio::select! {
            Some(execution) = result_rx.recv() => {
                let (disposition, detail) = match execution.result {
                    Ok(result) if result.success => (AckDisposition::Applied, None),
                    Ok(result) => (AckDisposition::Rejected, Some(result.detail)),
                    Err(error) => (AckDisposition::Rejected, Some(error.to_string())),
                };
                enqueue_ack(&mut outbox, &identity, execution.message_id, disposition, detail)?;
                if let Err(error) = send_pending_once(&mut outbox, &sender, 64).await {
                    tracing::warn!(%error, "command result ACK remains in SQLite outbox");
                }
            }
            _ = heartbeat.tick() => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|duration| duration.as_millis() as i64)
                    .unwrap_or_default();
                let active_trap_count = fs::read_dir(state_dir.join("traps"))
                    .map(|entries| entries.flatten().count() as u32)
                    .unwrap_or_default();
                outbox.enqueue(KazikEnvelope::new(
                    identity.agent_id,
                    identity.transport_credential.clone(),
                    now,
                    KazikBody::Heartbeat { status: AgentStatus {
                        hostname: std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".into()),
                        active_trap_count,
                    }},
                ))?;
                if let Err(error) = send_pending_once(&mut outbox, &sender, 64).await {
                    tracing::warn!(%error, "Kazik pending packets remain in SQLite outbox");
                }
            }
            received = transport.receive() => match received {
                Ok(packet) => match KazikEnvelope::decode_hfsp(&packet) {
                    Ok((envelope, _, _)) if envelope.agent_id == identity.agent_id
                        && envelope.transport_credential == identity.transport_credential => {
                        match envelope.body {
                            KazikBody::Ack(ack)
                                if matches!(ack.disposition, AckDisposition::Accepted | AckDisposition::Applied | AckDisposition::Duplicate) => {
                                    outbox.acknowledge(ack.acknowledged_message_id)?;
                                }
                            KazikBody::Command { command } => {
                                if command_tx.try_send(CommandJob { message_id: envelope.message_id, command }).is_err() {
                                    enqueue_ack(
                                        &mut outbox,
                                        &identity,
                                        envelope.message_id,
                                        AckDisposition::Rejected,
                                        Some("agent command queue is full or unavailable".into()),
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
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
}

struct CommandJob {
    message_id: uuid::Uuid,
    command: AgentCommand,
}

struct CommandExecution {
    message_id: uuid::Uuid,
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
    let tools_ready = Command::new("virsh")
        .arg("--version")
        .status()
        .is_ok_and(|status| status.success())
        && Command::new("virt-install")
            .arg("--version")
            .status()
            .is_ok_and(|status| status.success());
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

fn process_inbox(
    inbox: &Path,
    projects: &ComposeProjectStore,
    kozyavka_image: &str,
    pritvoryashka_image: &str,
    agent_id: uuid::Uuid,
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
                projects.apply(command, kozyavka_image, pritvoryashka_image, agent_id)
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
    fs::write(&temporary, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(temporary, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Platform, parse_platform};

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
}
