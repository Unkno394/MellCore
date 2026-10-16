use std::{
    collections::{BTreeMap, HashMap, HashSet},
    env, fs,
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const DEFAULT_STATE_DIR: &str = "/var/lib/honeyforge/local";

mod guest;
mod high_local;
mod high_prerequisites;
mod shared;

#[derive(Parser)]
#[command(name = "hf", about = "Локальное управление ловушками HoneyForge")]
struct Cli {
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    Deploy {
        #[command(subcommand)]
        kind: DeployKind,
    },
    List,
    Stop {
        id: String,
    },
    Remove {
        id: String,
    },
}

#[derive(Subcommand)]
enum DeployKind {
    Low(LowArgs),
    Medium(MediumArgs),
    High(HighArgs),
}

#[derive(Debug, Clone, Copy, ValueEnum)]
#[value(rename_all = "snake_case")]
enum LowAuthMode {
    CaptureCredentials,
    Configured,
    AnyPassword,
    Passwordless,
}

impl LowAuthMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::CaptureCredentials => "capture_credentials",
            Self::Configured => "configured",
            Self::AnyPassword => "any_password",
            Self::Passwordless => "passwordless",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "snake_case")]
enum MiddleOs {
    Ubuntu,
    Debian,
    Arch,
    Windows,
}

impl MiddleOs {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ubuntu => "ubuntu",
            Self::Debian => "debian",
            Self::Arch => "arch",
            Self::Windows => "windows",
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
#[value(rename_all = "snake_case")]
enum MiddleAuthMode {
    Adaptive,
    Realistic,
}

impl MiddleAuthMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Adaptive => "adaptive",
            Self::Realistic => "realistic",
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
#[value(rename_all = "snake_case")]
enum GuestShell {
    Bash,
    Sh,
    Zsh,
}

impl GuestShell {
    fn as_path(self) -> &'static str {
        match self {
            Self::Bash => "/bin/bash",
            Self::Sh => "/bin/sh",
            Self::Zsh => "/bin/zsh",
        }
    }
}

#[derive(Debug, Clone, Args)]
struct ResourceArgs {
    /// Maximum CPU cores for this container.
    #[arg(long)]
    cpu: Option<f64>,
    /// Maximum container memory in MiB.
    #[arg(long)]
    memory_mb: Option<u32>,
    /// Maximum number of container processes.
    #[arg(long)]
    pids: Option<u32>,
}

#[derive(Debug, Clone, Args)]
struct SharedArgs {
    /// Serve this SSH trap through the local Dispatcher on --port.
    #[arg(long)]
    shared: bool,
    /// Share of Dispatcher connections when joining an existing group, 1..99.
    #[arg(long, requires = "shared")]
    weight: Option<u8>,
}

#[derive(Debug, Clone, Args)]
struct LowArgs {
    #[arg(long)]
    port: u16,
    #[arg(long, value_enum, default_value = "capture_credentials")]
    auth_mode: LowAuthMode,
    /// Login accepted in configured mode.
    #[arg(long)]
    username: Option<String>,
    /// Root-readable text file containing the accepted password.
    #[arg(long)]
    password_file: Option<PathBuf>,
    #[command(flatten)]
    resources: ResourceArgs,
    #[command(flatten)]
    shared: SharedArgs,
}

#[derive(Debug, Clone, Args)]
struct MediumArgs {
    #[arg(long)]
    port: u16,
    #[arg(long, value_enum, default_value = "ubuntu")]
    os: MiddleOs,
    #[arg(long, default_value = "honeyforge-local")]
    hostname: String,
    #[arg(long, default_value = "admin")]
    username: String,
    #[arg(long, value_enum, default_value = "adaptive")]
    ssh_auth_mode: MiddleAuthMode,
    /// Root-readable text file containing the SSH password in realistic mode.
    #[arg(long)]
    password_file: Option<PathBuf>,
    /// Supported vulnerability ID; can be repeated.
    #[arg(long = "vulnerability")]
    vulnerabilities: Vec<String>,
    /// Exposed service port as SERVICE=PORT; can be repeated.
    #[arg(long = "service-port")]
    service_ports: Vec<String>,
    /// Decoy file as GUEST_PATH=HOST_FILE; can be repeated.
    #[arg(long = "bait")]
    baits: Vec<String>,
    #[command(flatten)]
    resources: ResourceArgs,
    #[command(flatten)]
    shared: SharedArgs,
}

#[derive(Debug, Clone, Args)]
struct HighArgs {
    /// Use a prepared local image for this operating system.
    #[arg(long, value_enum, default_value = "ubuntu")]
    os: HighOs,
    /// Existing prepared QCOW2 image; overrides the standard path for --os.
    #[arg(long, conflicts_with = "iso")]
    image: Option<PathBuf>,
    /// Locally downloaded installation ISO; installs a new VM before publishing its port.
    #[arg(long, conflicts_with = "image")]
    iso: Option<PathBuf>,
    #[arg(long)]
    port: u16,
    #[arg(long)]
    hostname: Option<String>,
    #[arg(long)]
    username: Option<String>,
    #[arg(long, value_enum)]
    shell: Option<GuestShell>,
    /// Root-readable text file containing this guest user's SSH password.
    #[arg(long)]
    password_file: Option<PathBuf>,
    /// Linux guest profile: ssh_weak_credentials, ssh_root_login_enabled or sudo_nopasswd.
    #[arg(long = "vulnerability")]
    vulnerabilities: Vec<String>,
    /// Decoy file as GUEST_PATH=HOST_FILE; can be repeated.
    #[arg(long = "bait")]
    baits: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lower")]
enum HighOs {
    Ubuntu,
    Debian,
    Arch,
    Windows,
}

impl HighOs {
    fn prepared_path(self) -> &'static str {
        match self {
            // Keep HoneyForge-prepared copies separate from older upstream images that
            // may still back running overlays and lack qemu-guest-agent.
            Self::Ubuntu => "/var/lib/honeyforge/images/noble-server-cloudimg-amd64-hf-qga.qcow2",
            Self::Debian => "/var/lib/honeyforge/images/debian-12-genericcloud-amd64-hf-qga.qcow2",
            Self::Arch => "/var/lib/honeyforge/images/arch-linux-x86_64-cloudimg.qcow2",
            Self::Windows => "/var/lib/honeyforge/images/windows-server-prepared.qcow2",
        }
    }

    fn service_port(self) -> &'static str {
        if self == Self::Windows { "3389" } else { "22" }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum TrapKind {
    Low,
    Medium,
    High,
}

impl TrapKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Status {
    Starting,
    Running,
    Stopped,
    Failed,
    Unknown,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        }
    }
}

/// The inventory intentionally stores only the requested local lifecycle fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Trap {
    id: String,
    kind: TrapKind,
    port: u16,
    status: Status,
}

struct State {
    root: PathBuf,
    traps: Vec<Trap>,
}

impl State {
    fn open() -> anyhow::Result<Self> {
        let root = env::var_os("HF_LOCAL_STATE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR));
        anyhow::ensure!(root.is_absolute(), "HF_LOCAL_STATE_DIR must be absolute");
        anyhow::ensure!(root != Path::new("/"), "local state directory cannot be /");
        fs::create_dir_all(&root)
            .with_context(|| format!("cannot create local state directory {}", root.display()))?;
        anyhow::ensure!(
            fs::symlink_metadata(&root)?.file_type().is_dir(),
            "local state path must be a real directory, not a symlink"
        );
        let root = fs::canonicalize(root)?;
        anyhow::ensure!(
            ![
                Path::new("/var/lib/honeyforge"),
                Path::new("/var/lib/honeyforge/traps"),
                Path::new("/var/lib/honeyforge/high"),
            ]
            .contains(&root.as_path()),
            "local CLI state must be separate from hf-agent service state"
        );
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let path = root.join("traps.json");
        let traps = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("invalid local state file {}", path.display()))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error.into()),
        };
        Ok(Self { root, traps })
    }

    fn save(&self) -> anyhow::Result<()> {
        atomic_write(
            &self.root.join("traps.json"),
            &serde_json::to_vec_pretty(&self.traps)?,
            0o600,
        )
    }

    fn next_id(&self, kind: TrapKind) -> String {
        let prefix = kind.as_str();
        let next = self
            .traps
            .iter()
            .filter_map(|trap| trap.id.strip_prefix(&format!("{prefix}-")))
            .filter_map(|suffix| suffix.parse::<u64>().ok())
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        format!("{prefix}-{next}")
    }

    fn find(&self, id: &str) -> anyhow::Result<usize> {
        self.traps
            .iter()
            .position(|trap| trap.id == id)
            .ok_or_else(|| anyhow::anyhow!("unknown local trap '{id}'"))
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mut state = State::open()?;
    match cli.command {
        Action::Deploy { kind } => deploy(&mut state, kind),
        Action::List => list(&mut state),
        Action::Stop { id } => stop(&mut state, &id),
        Action::Remove { id } => remove(&mut state, &id),
    }
}

fn deploy(state: &mut State, kind: DeployKind) -> anyhow::Result<()> {
    let (trap_kind, port) = match &kind {
        DeployKind::Low(args) => (TrapKind::Low, args.port),
        DeployKind::Medium(args) => (TrapKind::Medium, args.port),
        DeployKind::High(args) => (TrapKind::High, args.port),
    };
    anyhow::ensure!(port != 0, "port must be in 1..65535");
    let shared = match &kind {
        DeployKind::Low(args) => args.shared.shared,
        DeployKind::Medium(args) => args.shared.shared,
        DeployKind::High(_) => false,
    };
    anyhow::ensure!(
        trap_kind != TrapKind::High || port != 2222,
        "High SSH publication cannot use reserved management port 2222"
    );
    if shared {
        anyhow::ensure!(
            shared::has_listener(state, port)? || !state.traps.iter().any(|trap| trap.port == port),
            "port {port} belongs to a direct local trap"
        );
    } else {
        anyhow::ensure!(
            !state.traps.iter().any(|trap| trap.port == port),
            "port {port} is already assigned to a local trap"
        );
    }
    if !shared || !shared::has_listener(state, port)? {
        TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port))
            .with_context(|| format!("host TCP port {port} is already in use"))?;
    }

    let candidate_uuid = trap_uuid(&state.next_id(trap_kind));
    match &kind {
        DeployKind::Low(_) | DeployKind::Medium(_) => anyhow::ensure!(
            !project_dir(state, candidate_uuid).exists(),
            "refusing to replace an untracked Docker project for port {port}"
        ),
        DeployKind::High(args) => {
            anyhow::ensure!(
                !state
                    .root
                    .join("high")
                    .join(candidate_uuid.to_string())
                    .exists(),
                "refusing to replace an untracked High VM for port {port}"
            );
            high_prerequisites::ensure(args)?;
            let domain = format!("hf-high-{candidate_uuid}");
            let output = Command::new("virsh")
                .env("LIBVIRT_DEFAULT_URI", "qemu:///system")
                .args(["list", "--all", "--name"])
                .output();
            let output = output.context("cannot inspect libvirt domains before High deployment")?;
            if !output.status.success() {
                let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
                bail!("cannot inspect libvirt domains before High deployment: {detail}");
            }
            anyhow::ensure!(
                !String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .any(|existing| existing.trim() == domain),
                "refusing to adopt untracked libvirt domain {domain}"
            );
        }
    }
    let id = state.next_id(trap_kind);
    let trap_id = trap_uuid(&id);
    state.traps.push(Trap {
        id: id.clone(),
        kind: trap_kind,
        port,
        status: Status::Starting,
    });
    state.save()?;

    let result = deploy_runtime(state, &id, trap_id, kind);
    match result {
        Ok(()) => {
            let index = state.find(&id)?;
            state.traps[index].status = Status::Running;
            state.save()?;
            println!("Ловушка {id} запущена на порту {port}");
            Ok(())
        }
        Err(error) => {
            let cleanup = cleanup_runtime(state, &id, trap_id, trap_kind);
            let index = state.find(&id)?;
            if cleanup.is_ok() {
                state.traps.remove(index);
            } else {
                state.traps[index].status = Status::Failed;
            }
            state.save()?;
            if let Err(cleanup_error) = cleanup {
                bail!(
                    "deployment failed: {error:#}; cleanup also failed: {cleanup_error:#}; record kept as {id}"
                );
            }
            Err(error)
        }
    }
}

fn deploy_runtime(state: &State, id: &str, trap_id: Uuid, kind: DeployKind) -> anyhow::Result<()> {
    match kind {
        DeployKind::Low(args) => deploy_low(state, trap_id, &args),
        DeployKind::Medium(args) => deploy_medium(state, trap_id, &args),
        DeployKind::High(args) => deploy_high(state, id, trap_id, &args),
    }
}

fn deploy_low(state: &State, trap_id: Uuid, args: &LowArgs) -> anyhow::Result<()> {
    ensure_docker_available()?;
    let (cpu, memory_mb, pids) = args.resources.resolve(TrapKind::Low)?;
    anyhow::ensure!(
        matches!(args.auth_mode, LowAuthMode::Configured)
            || (args.username.is_none() && args.password_file.is_none()),
        "--username and --password-file are only valid with --auth-mode configured"
    );
    let credentials = if matches!(args.auth_mode, LowAuthMode::Configured) {
        let username = args
            .username
            .as_deref()
            .context("configured mode needs --username")?;
        let password_file = args
            .password_file
            .as_deref()
            .context("configured mode needs --password-file")?;
        validate_username(username)?;
        vec![
            serde_json::json!({"username": username, "password": read_password_file(password_file)?}),
        ]
    } else {
        Vec::new()
    };
    let image = env::var("HF_KOZYAVKA_IMAGE").unwrap_or_else(|_| "honeyforge-low:local".into());
    validate_image(&image)?;
    let project = project_dir(state, trap_id);
    create_project(&project)?;
    let runtime = project.join("runtime");
    fs::create_dir(&runtime)?;
    set_owner_and_mode(&runtime, 65_532, 0o700)?;
    let backend_port = if args.shared.shared {
        shared::backend_port()?
    } else {
        args.port
    };
    let (bind_ip, identity_mount, banner) = if args.shared.shared {
        let identity = shared::identity(state, args.port)?;
        (
            "127.0.0.1",
            format!("{}:/var/lib/honeyforge-low:ro", identity.display()),
            "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
        )
    } else {
        (
            "0.0.0.0",
            "./runtime:/var/lib/honeyforge-low".to_owned(),
            "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        )
    };
    let config = serde_json::json!({
        "bind_address": "0.0.0.0",
        "port": 22,
        "banner": banner,
        "auth_mode": args.auth_mode.as_str(),
        "credentials": credentials,
        "trap_id": trap_id,
        "host_key_path": "/var/lib/honeyforge-low/host_ed25519"
    });
    atomic_write(
        &project.join("config.json"),
        &serde_json::to_vec_pretty(&config)?,
        0o600,
    )?;
    set_owner_and_mode(&project.join("config.json"), 65_532, 0o600)?;
    let port = backend_port;
    let compose_yaml = format!(
        "name: hf-{name}\nservices:\n  honeypot:\n    image: {image}\n    restart: unless-stopped\n    pull_policy: never\n    logging:\n      driver: \"none\"\n    command: [\"--config\", \"/etc/honeyforge/config.json\"]\n    ports:\n      - \"{bind_ip}:{port}:22/tcp\"\n    volumes:\n      - ./config.json:/etc/honeyforge/config.json:ro\n      - {identity_mount}\n    read_only: true\n    cap_drop: [ALL]\n    security_opt: [no-new-privileges:true]\n    mem_limit: {memory_mb}m\n    cpus: {cpu:.3}\n    pids_limit: {pids}\n    ulimits:\n      nofile:\n        soft: 256\n        hard: 256\n    init: true\n",
        name = trap_id.simple(),
    );
    atomic_write(
        &project.join("compose.yaml"),
        compose_yaml.as_bytes(),
        0o600,
    )?;
    compose(&project, trap_id, &["up", "-d", "--remove-orphans"])?;
    if args.shared.shared {
        shared::add(
            state,
            args.port,
            trap_id,
            backend_port,
            args.shared.weight,
            None,
        )?;
    }
    Ok(())
}

fn deploy_medium(state: &State, trap_id: Uuid, args: &MediumArgs) -> anyhow::Result<()> {
    ensure_docker_available()?;
    let (cpu, memory_mb, pids) = args.resources.resolve(TrapKind::Medium)?;
    validate_hostname(&args.hostname)?;
    validate_username(&args.username)?;
    anyhow::ensure!(
        args.username != "root",
        "Middle virtual username cannot be root"
    );
    let ssh_credentials = match args.ssh_auth_mode {
        MiddleAuthMode::Adaptive => {
            anyhow::ensure!(
                args.password_file.is_none(),
                "--password-file requires --ssh-auth-mode realistic"
            );
            Vec::new()
        }
        MiddleAuthMode::Realistic => {
            let file = args
                .password_file
                .as_deref()
                .context("realistic mode needs --password-file")?;
            vec![
                serde_json::json!({"username": args.username, "password": read_password_file(file)?}),
            ]
        }
    };
    let baits = read_baits(&args.baits, args.os == MiddleOs::Windows, &args.username)?;
    let endpoints = middle_endpoints(
        &args.vulnerabilities,
        args.os,
        &args.service_ports,
        args.port,
    )?;
    let network_listeners: Vec<_> = endpoints.iter().map(|(service, host, container)| serde_json::json!({
        "service_type": service, "bind": format!("0.0.0.0:{container}"), "public_port": host,
    })).collect();
    let additional_ports: String = endpoints
        .iter()
        .map(|(_, host, container)| format!("      - \"0.0.0.0:{host}:{container}/tcp\"\n"))
        .collect();
    let image = env::var("HF_PRITVORYASHKA_IMAGE")
        .unwrap_or_else(|_| "honeyforge-pritvoryashka:local".into());
    validate_image(&image)?;
    let project = project_dir(state, trap_id);
    create_project(&project)?;
    fs::create_dir(project.join("runtime"))?;
    if args.shared.shared {
        atomic_write(&project.join("runtime/host_ed25519"), b"", 0o600)?;
    }
    let server_id = Uuid::new_v4();
    let agent_id = Uuid::new_v4();
    let backend_port = if args.shared.shared {
        shared::backend_port()?
    } else {
        args.port
    };
    let port = args.port;
    let (bind_ip, identity_mount, proxy_secret) = if args.shared.shared {
        let identity = shared::identity(state, port)?;
        (
            "127.0.0.1",
            format!(
                "./runtime:/var/lib/pritvoryashka\n      - {}:/var/lib/pritvoryashka/host_ed25519:ro",
                identity.join("host_ed25519").display()
            ),
            Some(shared::proxy_secret()),
        )
    } else {
        (
            "0.0.0.0",
            "./runtime:/var/lib/pritvoryashka".to_owned(),
            None,
        )
    };
    let config = serde_json::json!({
        "bind": "0.0.0.0:2222",
        "ssh_public_port": port,
        "health_bind": "127.0.0.1:9091",
        "trap_id": trap_id,
        "server_id": server_id,
        "agent_id": agent_id,
        "hostname": args.hostname,
        "username": args.username,
        "distribution": args.os.as_str(),
        "ssh_auth_mode": args.ssh_auth_mode.as_str(),
        "ssh_credentials": ssh_credentials,
        "dispatcher_proxy_secret": proxy_secret,
        "shared_ssh_identity": args.shared.shared,
        "vulnerability_profiles": args.vulnerabilities,
        "network_listeners": network_listeners,
        "host_key": "/var/lib/pritvoryashka/host_ed25519",
        "auth": {"policy": "accept_all", "capture": "username", "max_attempts": 6},
        "telemetry": {
            "endpoint": null,
            "token_env": null,
            "jsonl_path": "/dev/null",
            "queue_capacity": 1024,
            "batch_size": 50,
            "flush_interval_ms": 500,
            "max_event_bytes": 49152
        },
        "max_connections": 128,
        "idle_timeout_seconds": 600,
        "max_input_bytes": 8192,
        "baits": baits,
        "virtual_processes": []
    });
    let config_path = project.join("pritvoryashka.json");
    atomic_write(&config_path, &serde_json::to_vec_pretty(&config)?, 0o600)?;
    check_middle_config(&image, &config_path)?;
    let compose_yaml = format!(
        "name: hf-{name}\nservices:\n  honeypot:\n    image: {image}\n    restart: unless-stopped\n    pull_policy: never\n    logging:\n      driver: \"none\"\n    ports:\n      - \"{bind_ip}:{backend_port}:2222/tcp\"\n{additional_ports}    volumes:\n      - ./pritvoryashka.json:/etc/honeyforge/pritvoryashka.json:ro\n      - {identity_mount}\n    read_only: true\n    cap_drop: [ALL]\n    security_opt: [no-new-privileges:true]\n    mem_limit: {memory_mb}m\n    cpus: {cpu:.3}\n    pids_limit: {pids}\n    ulimits:\n      nofile:\n        soft: 1024\n        hard: 1024\n    init: true\n",
        name = trap_id.simple(),
    );
    atomic_write(
        &project.join("compose.yaml"),
        compose_yaml.as_bytes(),
        0o600,
    )?;
    compose(&project, trap_id, &["up", "-d", "--remove-orphans"])?;
    if args.shared.shared {
        shared::add(
            state,
            port,
            trap_id,
            backend_port,
            args.shared.weight,
            proxy_secret,
        )?;
    }
    Ok(())
}

impl ResourceArgs {
    fn resolve(&self, kind: TrapKind) -> anyhow::Result<(f64, u32, u32)> {
        let (max_cpu, max_memory, max_pids) = match kind {
            TrapKind::Low => (1.0, 256, 128),
            TrapKind::Medium => (1.0, 512, 256),
            TrapKind::High => bail!("High resource limits are configured in the VM image"),
        };
        let cpu = self.cpu.unwrap_or(max_cpu);
        let memory = self.memory_mb.unwrap_or(max_memory);
        let pids = self.pids.unwrap_or(max_pids);
        anyhow::ensure!(
            cpu.is_finite() && (0.05..=max_cpu).contains(&cpu),
            "CPU limit must be in 0.05..={max_cpu}"
        );
        anyhow::ensure!(
            (32..=max_memory).contains(&memory),
            "memory limit must be in 32..={max_memory} MiB"
        );
        anyhow::ensure!(
            (16..=max_pids).contains(&pids),
            "PID limit must be in 16..={max_pids}"
        );
        Ok((cpu, memory, pids))
    }
}

fn validate_username(value: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        value.len() <= 32
            && value
                .as_bytes()
                .first()
                .is_some_and(|byte| byte.is_ascii_lowercase() || *byte == b'_')
            && value.bytes().all(|byte| byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'_' | b'-')),
        "username must contain 1..32 lowercase ASCII letters, digits, '_' or '-', starting with a letter or '_'"
    );
    Ok(())
}

fn validate_hostname(value: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
            && !value.starts_with(['.', '-'])
            && !value.ends_with(['.', '-']),
        "hostname must contain 1..64 DNS-style ASCII characters"
    );
    Ok(())
}

fn read_password_file(path: &Path) -> anyhow::Result<String> {
    let metadata = fs::symlink_metadata(path)?;
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "password file must be a regular file"
    );
    anyhow::ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "password file must not be readable by group or others (chmod 600)"
    );
    anyhow::ensure!(metadata.len() <= 4096, "password file is too large");
    let raw = fs::read_to_string(path)?;
    let password = raw.trim_end_matches(['\r', '\n']).to_owned();
    anyhow::ensure!(
        !password.is_empty() && password.len() <= 128 && !password.chars().any(char::is_control),
        "password must contain 1..128 printable characters"
    );
    Ok(password)
}

fn read_baits(
    specs: &[String],
    windows: bool,
    username: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
    anyhow::ensure!(specs.len() <= 32, "at most 32 bait files are supported");
    let mut paths = HashSet::new();
    let mut result = Vec::new();
    for spec in specs {
        let (guest_path, host_path) = spec
            .split_once('=')
            .context("bait must be GUEST_PATH=HOST_FILE")?;
        validate_bait_path(guest_path, windows, username)?;
        anyhow::ensure!(paths.insert(guest_path), "duplicate bait path {guest_path}");
        let content = fs::read_to_string(host_path)
            .with_context(|| format!("cannot read bait source {host_path}"))?;
        anyhow::ensure!(
            content.len() <= 4096 && !content.contains('\0'),
            "bait content must be text of at most 4096 bytes"
        );
        let name = Path::new(guest_path)
            .file_name()
            .and_then(|value| value.to_str())
            .context("bait path has no filename")?;
        anyhow::ensure!(name.len() <= 80, "bait filename is too long");
        result.push(serde_json::json!({
            "id": Uuid::new_v4(), "name": name, "path": guest_path,
            "content": content, "category": "file", "implementation": "virtual_file",
        }));
    }
    Ok(result)
}

fn validate_bait_path(path: &str, windows: bool, username: &str) -> anyhow::Result<()> {
    let allowed = if windows {
        &[
            "/C/Users/",
            "/C/Windows/",
            "/C/Program Files/",
            "/C/ProgramData/",
        ][..]
    } else {
        &[
            "/root/",
            "/tmp/",
            "/opt/",
            "/srv/",
            "/var/backups/",
            "/var/log/",
            "/etc/",
        ][..]
    };
    let user_home = format!("/home/{username}/");
    anyhow::ensure!(
        path.len() <= 256
            && (allowed.iter().any(|prefix| path.starts_with(prefix))
                || (!windows && path.starts_with(&user_home)))
            && path
                .split('/')
                .skip(1)
                .all(|part| !part.is_empty() && part != "." && part != ".." && part.len() <= 255)
            && !path.chars().any(char::is_control),
        "bait path is outside the supported virtual guest directories"
    );
    Ok(())
}

fn middle_endpoints(
    profiles: &[String],
    os: MiddleOs,
    port_overrides: &[String],
    ssh_port: u16,
) -> anyhow::Result<Vec<(String, u16, u16)>> {
    let mut selected = HashSet::new();
    let mut services = BTreeMap::<u16, &'static str>::new();
    for profile in profiles {
        anyhow::ensure!(
            selected.insert(profile.as_str()),
            "duplicate vulnerability profile {profile}"
        );
        let windows_profile = profile.starts_with("win_");
        anyhow::ensure!(
            windows_profile == (os == MiddleOs::Windows),
            "vulnerability {profile} does not match the selected Middle OS"
        );
        match profile.as_str() {
            "ssh_weak_credentials"
            | "ssh_root_login_enabled"
            | "win_autologon_credentials"
            | "win_always_install_elevated"
            | "win_writable_service_binary"
            | "win_guest_share" => {}
            "redis_unauthenticated_access" => {
                services.insert(6379, "redis");
            }
            "docker_api_exposed" => {
                services.insert(2375, "docker_api");
            }
            "http_admin_panel_exposure" | "web_path_traversal" | "web_command_injection" => {
                services.insert(8080, "http");
            }
            "sql_database_weak_credentials" => {
                services.insert(13306, "mysql");
                services.insert(15432, "postgres");
            }
            "ftp_anonymous_login" => {
                services.insert(2021, "ftp_data");
                services.insert(2121, "ftp");
            }
            _ => bail!("unknown Middle vulnerability profile {profile}"),
        }
    }
    let mut overrides = HashMap::<String, u16>::new();
    for value in port_overrides {
        let (service, port) = value
            .split_once('=')
            .context("service port must be SERVICE=PORT")?;
        let service = match service {
            "docker" => "docker_api",
            "postgresql" => "postgres",
            _ => service,
        };
        let port: u16 = port
            .parse()
            .with_context(|| format!("invalid service port {value}"))?;
        anyhow::ensure!(
            port != 0 && overrides.insert(service.into(), port).is_none(),
            "invalid or duplicate service port {value}"
        );
    }
    anyhow::ensure!(
        overrides
            .keys()
            .all(|service| services.values().any(|value| *value == service)),
        "service port override has no matching vulnerability"
    );
    let mut used = HashSet::from([ssh_port]);
    let mut result = Vec::new();
    for (container_port, service) in services {
        let host_port = if let Some(port) = overrides.get(service) {
            *port
        } else {
            (30000..=65535)
                .find(|candidate| {
                    !used.contains(candidate)
                        && TcpListener::bind((Ipv4Addr::UNSPECIFIED, *candidate)).is_ok()
                })
                .context("no free public port for Middle vulnerability service")?
        };
        anyhow::ensure!(
            used.insert(host_port),
            "Middle service ports must be distinct from each other and SSH"
        );
        TcpListener::bind((Ipv4Addr::UNSPECIFIED, host_port))
            .with_context(|| format!("service port {host_port} is already in use"))?;
        result.push((service.to_owned(), host_port, container_port));
    }
    Ok(result)
}

fn check_middle_config(image: &str, config_path: &Path) -> anyhow::Result<()> {
    let mount = format!("{}:/tmp/hf-middle-config.json:ro", config_path.display());
    let output = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--pull=never",
            "--network=none",
            "--read-only",
            "--volume",
        ])
        .arg(mount)
        .args([
            "--entrypoint",
            "/usr/local/bin/pritvoryashka",
            image,
            "--check-config",
            "/tmp/hf-middle-config.json",
        ])
        .output()
        .context("could not validate Middle config with the local image")?;
    if !output.status.success() {
        let detail: String = String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(500)
            .collect();
        bail!("Middle image rejected the local config: {}", detail.trim());
    }
    Ok(())
}

fn deploy_high(state: &State, id: &str, trap_id: Uuid, args: &HighArgs) -> anyhow::Result<()> {
    let settings = if args.os == HighOs::Windows {
        anyhow::ensure!(
            args.shell.is_none() && args.vulnerabilities.is_empty() && args.baits.is_empty(),
            "Windows High supports --hostname, --username and --password-file; Linux shell, vulnerabilities and baits do not apply"
        );
        None
    } else {
        high_guest_settings(args)?
    };
    let device = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .context("High traps require readable and writable /dev/kvm")?;
    drop(device);
    let source = if let Some(iso) = &args.iso {
        high_local::validate_iso(iso, args.os)?
    } else {
        let image_path = match &args.image {
            Some(path) => path.clone(),
            None => high_local::ensure_prepared_image(state, args.os)?,
        };
        high_local::validate_qcow2(&image_path)?
    };
    let image = fs::canonicalize(&source)
        .with_context(|| format!("cannot read High VM image {}", source.display()))?;
    let image = image
        .to_str()
        .context("High image path is not valid UTF-8")?;
    let recipe = recipe_dir(state)?;
    let high_root = state.root.join("high");
    fs::create_dir_all(&high_root)?;
    fs::set_permissions(&high_root, fs::Permissions::from_mode(0o700))?;
    let trap_id = trap_id.to_string();
    let port = args.port.to_string();
    if args.iso.is_some() {
        high_local::install_iso(state, &recipe, image, &trap_id, args)?;
    } else {
        high_local::prepare_prepared(state, &trap_id, args)?;
        let os = match args.os {
            HighOs::Ubuntu => "ubuntu",
            HighOs::Debian => "debian",
            HighOs::Arch => "arch",
            HighOs::Windows => "windows",
        };
        high_local::run_launch(state, &recipe, &high_root, image, &trap_id, &port, os)
            .with_context(|| format!("could not start High VM {id}"))?;
    }
    if let Some(settings) = settings {
        guest::apply(trap_id.as_str(), &settings)
            .with_context(|| format!("could not customize High guest {id}"))?;
    }
    high_local::wait_guest_service(&trap_id, args.os.service_port().parse()?)?;
    run_high_script(
        &recipe,
        &high_root,
        "publish-ssh.sh",
        &[&trap_id, &port, args.os.service_port()],
    )
    .with_context(|| format!("could not publish SSH for High VM {id}"))
}

fn high_guest_settings(args: &HighArgs) -> anyhow::Result<Option<guest::Settings>> {
    if args.hostname.is_none()
        && args.username.is_none()
        && args.shell.is_none()
        && args.password_file.is_none()
        && args.vulnerabilities.is_empty()
        && args.baits.is_empty()
    {
        return Ok(None);
    }
    if let Some(hostname) = &args.hostname {
        validate_hostname(hostname)?;
    }
    if let Some(username) = &args.username {
        validate_username(username)?;
    }
    anyhow::ensure!(
        args.shell.is_none() || args.username.is_some(),
        "--shell requires --username"
    );
    anyhow::ensure!(
        args.password_file.is_none() || args.username.is_some(),
        "--password-file requires --username"
    );
    let mut selected = HashSet::new();
    for vulnerability in &args.vulnerabilities {
        anyhow::ensure!(
            selected.insert(vulnerability),
            "duplicate High vulnerability {vulnerability}"
        );
        anyhow::ensure!(
            matches!(
                vulnerability.as_str(),
                "ssh_weak_credentials" | "ssh_root_login_enabled" | "sudo_nopasswd"
            ),
            "unsupported High vulnerability {vulnerability}"
        );
    }
    anyhow::ensure!(
        !selected.contains(&"ssh_weak_credentials".to_owned()) || args.password_file.is_some(),
        "ssh_weak_credentials requires --password-file"
    );
    anyhow::ensure!(
        !selected.contains(&"ssh_root_login_enabled".to_owned()) || args.password_file.is_some(),
        "ssh_root_login_enabled requires --password-file"
    );
    anyhow::ensure!(
        !selected.contains(&"sudo_nopasswd".to_owned()) || args.username.is_some(),
        "sudo_nopasswd requires --username"
    );
    let baits = read_high_baits(&args.baits, args.username.as_deref())?;
    let password_hash = args
        .password_file
        .as_deref()
        .map(hash_password)
        .transpose()?;
    Ok(Some(guest::Settings {
        hostname: args.hostname.clone(),
        username: args.username.clone(),
        shell: args.shell.map(|shell| shell.as_path().to_owned()),
        password_hash,
        vulnerabilities: args.vulnerabilities.clone(),
        baits,
    }))
}

fn read_high_baits(specs: &[String], username: Option<&str>) -> anyhow::Result<Vec<guest::Bait>> {
    anyhow::ensure!(
        specs.len() <= 32,
        "at most 32 High bait files are supported"
    );
    let mut paths = HashSet::new();
    let mut result = Vec::new();
    for spec in specs {
        let (guest_path, host_path) = spec
            .split_once('=')
            .context("bait must be GUEST_PATH=HOST_FILE")?;
        let user_home = username.map(|value| format!("/home/{value}/"));
        anyhow::ensure!(
            guest_path.len() <= 256
                && (["/srv/", "/opt/", "/var/backups/"]
                    .iter()
                    .any(|prefix| guest_path.starts_with(prefix))
                    || user_home
                        .as_deref()
                        .is_some_and(|prefix| guest_path.starts_with(prefix)))
                && guest_path
                    .split('/')
                    .skip(1)
                    .all(|part| !part.is_empty() && part != "." && part != "..")
                && paths.insert(guest_path),
            "High bait path must be unique and under /srv, /opt, /var/backups or the selected user's home"
        );
        let content = fs::read_to_string(host_path)
            .with_context(|| format!("cannot read bait source {host_path}"))?;
        anyhow::ensure!(
            content.len() <= 4096 && !content.contains('\0'),
            "bait content must be text of at most 4096 bytes"
        );
        result.push(guest::Bait {
            path: guest_path.to_owned(),
            content,
        });
    }
    Ok(result)
}

fn hash_password(path: &Path) -> anyhow::Result<String> {
    let password = read_password_file(path)?;
    let mut child = Command::new("openssl")
        .args(["passwd", "-6", "-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("openssl is required for High guest password hashing")?;
    child
        .stdin
        .take()
        .context("openssl stdin unavailable")?
        .write_all(password.as_bytes())?;
    let output = child.wait_with_output()?;
    anyhow::ensure!(
        output.status.success(),
        "could not hash High guest password"
    );
    let hash = String::from_utf8(output.stdout)?.trim().to_owned();
    anyhow::ensure!(
        hash.starts_with("$6$"),
        "openssl did not produce a SHA-512 password hash"
    );
    Ok(hash)
}

fn stop(state: &mut State, id: &str) -> anyhow::Result<()> {
    let index = state.find(id)?;
    let trap = state.traps[index].clone();
    let trap_id = trap_uuid(id);
    shared::remove(state, trap_id)?;
    match trap.kind {
        TrapKind::Low | TrapKind::Medium => {
            compose(&project_dir(state, trap_id), trap_id, &["stop"])?
        }
        TrapKind::High => run_high_script(
            &recipe_dir(state)?,
            &state.root.join("high"),
            "stop.sh",
            &[&trap_id.to_string()],
        )?,
    }
    state.traps[index].status = Status::Stopped;
    state.save()?;
    println!("Ловушка {id} остановлена");
    Ok(())
}

fn remove(state: &mut State, id: &str) -> anyhow::Result<()> {
    let index = state.find(id)?;
    let trap = state.traps[index].clone();
    cleanup_runtime(state, id, trap_uuid(id), trap.kind)?;
    state.traps.remove(index);
    state.save()?;
    println!("Ловушка {id} удалена");
    Ok(())
}

fn cleanup_runtime(state: &State, id: &str, trap_id: Uuid, kind: TrapKind) -> anyhow::Result<()> {
    shared::remove(state, trap_id)?;
    match kind {
        TrapKind::Low | TrapKind::Medium => {
            let project = project_dir(state, trap_id);
            if project.join("compose.yaml").is_file() {
                compose(&project, trap_id, &["down", "--remove-orphans"])?;
                fs::remove_dir_all(project)?;
            } else if project.exists() {
                fs::remove_dir_all(project)?;
            }
            Ok(())
        }
        TrapKind::High => run_high_script(
            &recipe_dir(state)?,
            &state.root.join("high"),
            "reset.sh",
            &[&trap_id.to_string()],
        )
        .with_context(|| format!("cannot remove High VM {id}")),
    }
}

fn list(state: &mut State) -> anyhow::Result<()> {
    for index in 0..state.traps.len() {
        let trap = state.traps[index].clone();
        state.traps[index].status = runtime_status(state, &trap)?;
    }
    state.save()?;
    println!("ID\tТИП\tПОРТ\tСТАТУС");
    for trap in &state.traps {
        println!(
            "{}\t{}\t{}\t{}",
            trap.id,
            trap.kind.as_str(),
            trap.port,
            trap.status.as_str()
        );
    }
    Ok(())
}

fn runtime_status(state: &State, trap: &Trap) -> anyhow::Result<Status> {
    let id = trap_uuid(&trap.id);
    match trap.kind {
        TrapKind::Low | TrapKind::Medium => {
            let project = project_dir(state, id);
            if !project.join("compose.yaml").is_file() {
                return Ok(Status::Failed);
            }
            let routed = shared::is_member(state, id)?;
            let output = Command::new("docker")
                .args([
                    "compose",
                    "--project-name",
                    &format!("hf-{}", id.simple()),
                    "--file",
                ])
                .arg(project.join("compose.yaml"))
                .args(["ps", "--status", "running", "-q"])
                .output();
            Ok(match output {
                Ok(output)
                    if output.status.success()
                        && !output.stdout.is_empty()
                        && routed
                        && !shared::service_active() =>
                {
                    Status::Failed
                }
                Ok(output) if output.status.success() && !output.stdout.is_empty() => {
                    Status::Running
                }
                Ok(output) if output.status.success() => Status::Stopped,
                _ => Status::Unknown,
            })
        }
        TrapKind::High => {
            let output = Command::new("virsh")
                .env("LIBVIRT_DEFAULT_URI", "qemu:///system")
                .args(["domstate", &format!("hf-high-{id}")])
                .output();
            Ok(match output {
                Ok(output) if output.status.success() => {
                    let value = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
                    if value.contains("running") || value.contains("idle") {
                        Status::Running
                    } else {
                        Status::Stopped
                    }
                }
                Ok(_) if !state.root.join("high").join(id.to_string()).exists() => Status::Stopped,
                _ => Status::Unknown,
            })
        }
    }
}

fn ensure_docker_available() -> anyhow::Result<()> {
    let output = Command::new("docker")
        .args(["compose", "version"])
        .output()
        .context("Docker Engine and Docker Compose v2 must already be installed")?;
    anyhow::ensure!(
        output.status.success(),
        "Docker Engine and Docker Compose v2 must already be installed"
    );
    Ok(())
}

fn validate_image(image: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !image.is_empty()
            && image
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "._/-:@".contains(c)),
        "unsafe Docker image reference"
    );
    Ok(())
}

fn compose(project: &Path, id: Uuid, args: &[&str]) -> anyhow::Result<()> {
    let output = Command::new("docker")
        .args([
            "compose",
            "--project-name",
            &format!("hf-{}", id.simple()),
            "--file",
        ])
        .arg(project.join("compose.yaml"))
        .args(args)
        .output()
        .context("could not run docker compose")?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        bail!("docker compose failed: {}", detail.trim());
    }
    Ok(())
}

fn project_dir(state: &State, id: Uuid) -> PathBuf {
    state.root.join("traps").join(id.to_string())
}

fn create_project(project: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(project.parent().expect("project path has parent"))?;
    fs::create_dir(project).with_context(|| {
        format!(
            "refusing to reuse existing project directory {}",
            project.display()
        )
    })
}

fn set_owner_and_mode(path: &Path, uid: u32, mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::chown;
    chown(path, Some(uid), Some(0))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes)?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn recipe_dir(state: &State) -> anyhow::Result<PathBuf> {
    let root = state.root.join("recipes/high-ubuntu-ssh/scripts");
    fs::create_dir_all(&root)?;
    const SCRIPTS: [(&str, &str); 7] = [
        (
            "launch-local.sh",
            include_str!("../recipes/high-ubuntu-ssh/scripts/launch-local.sh"),
        ),
        (
            "firewall-common.sh",
            include_str!("../recipes/high-ubuntu-ssh/scripts/firewall-common.sh"),
        ),
        (
            "create-network.sh",
            include_str!("../recipes/high-ubuntu-ssh/scripts/create-network.sh"),
        ),
        (
            "publish-ssh.sh",
            include_str!("../recipes/high-ubuntu-ssh/scripts/publish-ssh.sh"),
        ),
        (
            "unpublish-ssh.sh",
            include_str!("../recipes/high-ubuntu-ssh/scripts/unpublish-ssh.sh"),
        ),
        (
            "stop.sh",
            include_str!("../recipes/high-ubuntu-ssh/scripts/stop.sh"),
        ),
        (
            "reset.sh",
            include_str!("../recipes/high-ubuntu-ssh/scripts/reset.sh"),
        ),
    ];
    for (name, content) in SCRIPTS {
        let path = root.join(name);
        if fs::read(&path).ok().as_deref() != Some(content.as_bytes()) {
            atomic_write(&path, content.as_bytes(), 0o700)?;
        }
    }
    const ISO_SCRIPTS: [(&str, &str); 10] = [
        (
            "launch-iso.sh",
            include_str!("../recipes/high-custom-iso/scripts/launch-iso.sh"),
        ),
        (
            "create-network.sh",
            include_str!("../recipes/high-custom-iso/scripts/create-network.sh"),
        ),
        (
            "prepare-unattended-iso.sh",
            include_str!("../recipes/high-custom-iso/scripts/prepare-unattended-iso.sh"),
        ),
        (
            "prepare-arch-repository.py",
            include_str!("../recipes/high-custom-iso/scripts/prepare-arch-repository.py"),
        ),
        (
            "install-arch.sh",
            include_str!("../recipes/high-custom-iso/scripts/install-arch.sh"),
        ),
        (
            "arch-console.exp",
            include_str!("../recipes/high-custom-iso/scripts/arch-console.exp"),
        ),
        (
            "archinstall-guest-install.sh",
            include_str!("../recipes/high-custom-iso/scripts/archinstall-guest-install.sh"),
        ),
        (
            "arch-guest-install.sh",
            include_str!("../recipes/high-custom-iso/scripts/arch-guest-install.sh"),
        ),
        (
            "finalize-linux-install.sh",
            include_str!("../recipes/high-custom-iso/scripts/finalize-linux-install.sh"),
        ),
        (
            "firewall-common.sh",
            include_str!("../recipes/high-custom-iso/scripts/firewall-common.sh"),
        ),
    ];
    let iso_dir = state.root.join("recipes/high-custom-iso/scripts");
    fs::create_dir_all(&iso_dir)?;
    for (name, content) in ISO_SCRIPTS {
        let path = iso_dir.join(name);
        if fs::read(&path).ok().as_deref() != Some(content.as_bytes()) {
            atomic_write(&path, content.as_bytes(), 0o700)?;
        }
    }
    const WINDOWS_SCRIPTS: [(&str, &str); 5] = [
        (
            "launch.sh",
            include_str!("../recipes/high-windows-rdp/scripts/launch.sh"),
        ),
        (
            "create-network.sh",
            include_str!("../recipes/high-windows-rdp/scripts/create-network.sh"),
        ),
        (
            "verify-windows-media.sh",
            include_str!("../recipes/high-windows-rdp/scripts/verify-windows-media.sh"),
        ),
        (
            "create-overlay.sh",
            include_str!("../recipes/high-windows-rdp/scripts/create-overlay.sh"),
        ),
        (
            "install-windows.sh",
            include_str!("../recipes/high-windows-rdp/scripts/install-windows.sh"),
        ),
    ];
    let windows_dir = state.root.join("recipes/high-windows-rdp/scripts");
    fs::create_dir_all(&windows_dir)?;
    for (name, content) in WINDOWS_SCRIPTS {
        let path = windows_dir.join(name);
        if fs::read(&path).ok().as_deref() != Some(content.as_bytes()) {
            atomic_write(&path, content.as_bytes(), 0o700)?;
        }
    }
    let windows_xml = state.root.join("recipes/high-windows-rdp/autounattend.xml");
    let xml = include_str!("../recipes/high-windows-rdp/autounattend.xml");
    if fs::read(&windows_xml).ok().as_deref() != Some(xml.as_bytes()) {
        atomic_write(&windows_xml, xml.as_bytes(), 0o600)?;
    }
    let offline_dir = state.root.join("recipes/high-ubuntu-ssh/offline");
    fs::create_dir_all(&offline_dir)?;
    let offline_script = offline_dir.join("build-package-bundle.sh");
    let offline_content =
        include_str!("../recipes/high-ubuntu-ssh/offline/build-package-bundle.sh");
    if fs::read(&offline_script).ok().as_deref() != Some(offline_content.as_bytes()) {
        atomic_write(&offline_script, offline_content.as_bytes(), 0o700)?;
    }
    Ok(state.root.join("recipes/high-ubuntu-ssh"))
}

fn run_high_script(
    root: &Path,
    high_root: &Path,
    script: &str,
    args: &[&str],
) -> anyhow::Result<()> {
    let path = root.join("scripts").join(script);
    anyhow::ensure!(
        path.is_file(),
        "missing High lifecycle script {}",
        path.display()
    );
    let output = Command::new("sh")
        .arg(&path)
        .args(args)
        .env("HF_HIGH_ROOT", high_root)
        .env("HF_HIGH_NETWORK_SCOPE", "local")
        .env("HF_HIGH_VIRT_TYPE", "kvm")
        .env("HF_HIGH_DHCP_ATTEMPTS", "12")
        .env("LIBVIRT_DEFAULT_URI", "qemu:///system")
        .env("LC_ALL", "C")
        .output()
        .with_context(|| format!("could not run {}", path.display()))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        bail!(
            "{} exited with {}: {}",
            script,
            output.status,
            detail.trim()
        );
    }
    Ok(())
}

fn trap_uuid(id: &str) -> Uuid {
    let digest = Sha256::digest(id.as_bytes());
    let mut bytes: [u8; 16] = digest[..16]
        .try_into()
        .expect("SHA-256 has at least 16 bytes");
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}
