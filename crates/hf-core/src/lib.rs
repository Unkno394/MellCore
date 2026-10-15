//! Stable domain contracts. Network transports and infrastructure live outside this crate.

pub mod host_inventory;
pub mod math;
pub mod security;

/// SSH identification shared by Low and Middle backends behind one Dispatcher listener.
pub const SHARED_SSH_IDENTIFICATION: &str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10";

pub use host_inventory::*;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRegistration {
    pub enrollment_token: String,
    pub hostname: String,
    pub agent_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredAgent {
    pub agent_id: Uuid,
    /// Credentials for the selected transport. Never use `agent_id` as authentication.
    pub transport_credential: String,
    /// Settings issued after enrollment for the optional Hysteria transport service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hysteria: Option<HysteriaConnection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HysteriaConnection {
    /// Public Hysteria endpoint in `host:port` form (IPv6 is bracketed).
    pub server: String,
    /// TLS server name the agent verifies; certificate verification is not disabled.
    pub sni: String,
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("agent is not authorized")]
    Unauthorized,
}

/// The agent core depends on this port, not on Hysteria, HTTP, or a radio implementation.
#[async_trait]
pub trait RegistrationTransport: Send + Sync {
    async fn register(&self, registration: AgentRegistration)
    -> Result<RegisteredAgent, CoreError>;
}

#[derive(Debug, Clone)]
pub struct BootstrapScript {
    pub contents: String,
    /// A root-owned initial command copied to the agent inbox during the one SSH bootstrap.
    /// This is deliberately data, never interpolated into the shell installer.
    pub initial_command_json: Option<Vec<u8>>,
}

/// Ephemeral SSH credentials used only during first installation. Do not persist or log this type.
pub struct SshBootstrapTarget {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: SshAuthentication,
    /// Optional sudo credential, used only during installation and never persisted.
    pub sudo_password: Option<String>,
}

/// Ephemeral SSH authentication material. Never derive Debug/Serialize for this type.
pub enum SshAuthentication {
    Password(String),
    PrivateKey {
        pem: String,
        passphrase: Option<String>,
    },
}

/// Desired honeypot instance. Recipes are supplied by the infrastructure layer, not the core.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrapSpec {
    pub trap_id: Uuid,
    pub tier: TrapTier,
    pub protocol: String,
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrapTier {
    Low,
    Medium,
    High,
}

/// A command is idempotent by `command_id`; the agent persists completed IDs before ACKing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentCommand {
    DeployKozyavka(KozyavkaDeployment),
    DeployPritvoryashka(PritvoryashkaDeployment),
    /// Generic High VM deployment. `DeployHighUbuntu` remains for wire compatibility.
    DeployHighVm(HighVmDeployment),
    DeployHighUbuntu(HighUbuntuDeployment),
    ResetHighVm {
        command_id: Uuid,
        trap_id: Uuid,
    },
    ResetHighUbuntu {
        command_id: Uuid,
        trap_id: Uuid,
    },
    ReconcileTcpPortGroup(TcpPortGroup),
    /// Requests exactly one host reboot through systemd; no command text is caller supplied.
    RebootSystem {
        command_id: Uuid,
    },
    /// Schedules removal of this agent's services and files after its command ACK.
    UninstallAgent {
        command_id: Uuid,
    },
    StopTrap {
        command_id: Uuid,
        trap_id: Uuid,
    },
    RemoveTrap {
        command_id: Uuid,
        trap_id: Uuid,
    },
}

impl AgentCommand {
    pub fn command_id(&self) -> Uuid {
        match self {
            Self::DeployKozyavka(command) => command.command_id,
            Self::DeployPritvoryashka(command) => command.command_id,
            Self::DeployHighVm(command) => command.command_id,
            Self::DeployHighUbuntu(command) => command.command_id,
            Self::ResetHighVm { command_id, .. } => *command_id,
            Self::ResetHighUbuntu { command_id, .. } => *command_id,
            Self::ReconcileTcpPortGroup(command) => command.command_id,
            Self::RebootSystem { command_id } => *command_id,
            Self::UninstallAgent { command_id } => *command_id,
            Self::StopTrap { command_id, .. } | Self::RemoveTrap { command_id, .. } => *command_id,
        }
    }
}

/// Exact deployment data for the existing Low SSH banner honeypot. The central backend builds
/// this from its validated profile snapshot; the agent never accepts arbitrary compose YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KozyavkaDeployment {
    pub command_id: Uuid,
    pub trap_id: Uuid,
    pub host_port: u16,
    pub container_port: u16,
    pub banner: String,
    #[serde(default)]
    pub resources: ContainerResourceLimits,
    /// External direct listener is 0.0.0.0; Dispatcher members are loopback-only.
    pub publish_address: String,
}

/// Exact deployment data for the Middle-interaction SSH trap. The agent fills its own agent ID
/// into the generated runtime configuration rather than trusting it from the control plane.
#[derive(Clone, Serialize, Deserialize)]
pub struct PritvoryashkaDeployment {
    pub command_id: Uuid,
    pub trap_id: Uuid,
    pub server_id: Uuid,
    pub host_port: u16,
    #[serde(default)]
    pub public_ssh_port: u16,
    /// External direct listener is 0.0.0.0; Dispatcher members are loopback-only.
    pub publish_address: String,
    pub hostname: String,
    #[serde(default = "default_middle_username")]
    pub username: String,
    #[serde(default = "default_middle_distribution")]
    pub distribution: String,
    #[serde(default = "default_middle_ssh_auth_mode")]
    pub ssh_auth_mode: String,
    #[serde(default = "default_middle_ssh_credentials")]
    pub ssh_credentials: Vec<MiddleSshCredential>,
    /// Per-trap key used to authenticate Dispatcher PROXY v2 metadata. The agent creates and
    /// persists it when absent, so it is never supplied by an end user.
    #[serde(default)]
    pub dispatcher_proxy_secret: Option<String>,
    #[serde(default = "ContainerResourceLimits::middle_default")]
    pub resources: ContainerResourceLimits,
    #[serde(default = "default_pritvoryashka_connections")]
    pub max_connections: u16,
    #[serde(default)]
    pub baits: Vec<BaitFile>,
    #[serde(default)]
    pub virtual_processes: Vec<VirtualProcess>,
    #[serde(default)]
    pub vulnerability_profiles: Vec<String>,
    /// Additional direct TCP services sharing this trap's virtual state. SSH remains the
    /// primary listener and may be published through the SSH-only Dispatcher.
    #[serde(default)]
    pub endpoints: Vec<PritvoryashkaEndpoint>,
}

impl std::fmt::Debug for PritvoryashkaDeployment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PritvoryashkaDeployment")
            .field("command_id", &self.command_id)
            .field("trap_id", &self.trap_id)
            .field("server_id", &self.server_id)
            .field("host_port", &self.host_port)
            .field("public_ssh_port", &self.public_ssh_port)
            .field("publish_address", &self.publish_address)
            .field("hostname", &self.hostname)
            .field("username", &self.username)
            .field("distribution", &self.distribution)
            .field("ssh_auth_mode", &self.ssh_auth_mode)
            .field("ssh_credentials", &self.ssh_credentials)
            .field("dispatcher_proxy_secret", &"[REDACTED]")
            .field("resources", &self.resources)
            .field("max_connections", &self.max_connections)
            .field("baits", &self.baits)
            .field("virtual_processes", &self.virtual_processes)
            .field("vulnerability_profiles", &self.vulnerability_profiles)
            .field("endpoints", &self.endpoints)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MiddleSshCredential {
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for MiddleSshCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MiddleSshCredential")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

fn default_middle_ssh_auth_mode() -> String {
    "realistic".into()
}

fn default_middle_ssh_credentials() -> Vec<MiddleSshCredential> {
    vec![
        MiddleSshCredential {
            username: "root".into(),
            password: "admin123".into(),
        },
        MiddleSshCredential {
            username: "admin".into(),
            password: "password123".into(),
        },
        MiddleSshCredential {
            username: "test".into(),
            password: "test".into(),
        },
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PritvoryashkaEndpoint {
    pub service_type: String,
    pub host_port: u16,
    pub container_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PritvoryashkaServiceEndpoint {
    pub service_type: &'static str,
    pub container_port: u16,
}

/// Map supported Middle vulnerability profiles to their isolated container listeners.
/// Profiles sharing a protocol endpoint intentionally share one emulator.
pub fn pritvoryashka_service_endpoints(
    profiles: &[String],
) -> Result<Vec<PritvoryashkaServiceEndpoint>, &'static str> {
    let mut selected = BTreeSet::new();
    let mut endpoints = BTreeMap::<u16, &'static str>::new();
    for profile in profiles {
        if !selected.insert(profile.as_str()) {
            return Err("Vulnerability profile IDs must be unique");
        }
        let endpoint = match profile.as_str() {
            "ssh_weak_credentials" | "ssh_root_login_enabled" => None,
            "redis_unauthenticated_access" => Some(("redis", 6379)),
            "docker_api_exposed" => Some(("docker_api", 2375)),
            "http_admin_panel_exposure" | "web_path_traversal" | "web_command_injection" => {
                Some(("http", 8080))
            }
            "sql_database_weak_credentials" => {
                endpoints.insert(13306, "mysql");
                endpoints.insert(15432, "postgres");
                None
            }
            "ftp_anonymous_login" => {
                endpoints.insert(2021, "ftp_data");
                Some(("ftp", 2121))
            }
            "win_autologon_credentials"
            | "win_always_install_elevated"
            | "win_writable_service_binary"
            | "win_guest_share" => None,
            _ => return Err("Unknown Middle vulnerability profile"),
        };
        if let Some((service, port)) = endpoint {
            if let Some(previous) = endpoints.insert(port, service)
                && previous != service
            {
                return Err("Conflicting services use the same endpoint");
            }
        }
    }
    Ok(endpoints
        .into_iter()
        .map(
            |(container_port, service_type)| PritvoryashkaServiceEndpoint {
                service_type,
                container_port,
            },
        )
        .collect())
}

pub fn pritvoryashka_service_endpoints_for_os(
    profiles: &[String],
    windows: bool,
) -> Result<Vec<PritvoryashkaServiceEndpoint>, &'static str> {
    let endpoints = pritvoryashka_service_endpoints(profiles)?;
    if profiles
        .iter()
        .any(|profile| profile != "ssh_weak_credentials" && profile.starts_with("win_") != windows)
    {
        return Err("Vulnerability profiles must match the Middle operating system");
    }
    Ok(endpoints)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BaitFile {
    pub id: Uuid,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default)]
    pub content: String,
    #[serde(default, rename = "category", alias = "kind")]
    pub kind: BaitKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implementation: Option<BaitImplementation>,
    #[serde(default, skip_serializing_if = "BaitConfig::is_empty")]
    pub config: BaitConfig,
}

impl BaitFile {
    pub fn effective_implementation(&self) -> BaitImplementation {
        self.implementation
            .unwrap_or(if self.kind == BaitKind::Account {
                BaitImplementation::VirtualAccount
            } else {
                BaitImplementation::VirtualFile
            })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BaitImplementation {
    VirtualFile,
    VirtualAccount,
    VirtualProcess,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct BaitConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<VirtualAccountConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_format: Option<CredentialFormat>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud_provider: Option<CloudProvider>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windows_artifact: Option<WindowsArtifact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_format: Option<DatabaseFormat>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_format: Option<BackupFormat>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canary_marker: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_config_format: Option<SystemConfigFormat>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history_format: Option<HistoryFormat>,
}

impl BaitConfig {
    fn is_empty(&self) -> bool {
        self.account.is_none()
            && self.credential_format.is_none()
            && self.cloud_provider.is_none()
            && self.windows_artifact.is_none()
            && self.database_format.is_none()
            && self.backup_format.is_none()
            && self.canary_marker.is_none()
            && self.system_config_format.is_none()
            && self.history_format.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VirtualAccountConfig {
    pub login: String,
    #[serde(default)]
    pub uid: Option<u32>,
    #[serde(default)]
    pub home_directory: Option<String>,
    #[serde(default)]
    pub shell: Option<VirtualShell>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VirtualShell {
    #[default]
    Bash,
    Sh,
    Nologin,
}

impl VirtualShell {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bash => "/bin/bash",
            Self::Sh => "/bin/sh",
            Self::Nologin => "/usr/sbin/nologin",
        }
    }
}

macro_rules! bait_config_enum {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($variant),+ }
    };
}

bait_config_enum!(CredentialFormat {
    ApiToken,
    SshKey,
    Password,
    EnvironmentVariables
});
bait_config_enum!(CloudProvider {
    Aws,
    Azure,
    Gcp,
    Kubernetes
});
bait_config_enum!(WindowsArtifact {
    PowershellScript,
    Configuration,
    Document,
    RegistryExport
});
bait_config_enum!(DatabaseFormat {
    SqlDump,
    Sqlite,
    Csv,
    Json
});
bait_config_enum!(BackupFormat {
    SqlDump,
    Manifest,
    TarListing,
    ZipListing
});
bait_config_enum!(SystemConfigFormat {
    SystemdUnit,
    Cron,
    SshConfig,
    ApplicationConfig
});
bait_config_enum!(HistoryFormat {
    BashHistory,
    ApplicationLog,
    SystemLog
});

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum VirtualProtocol {
    #[default]
    Tcp,
    Udp,
}

impl VirtualProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct VirtualProcessConfig {
    pub protocol: VirtualProtocol,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BaitKind {
    Account,
    #[default]
    File,
    Credential,
    Database,
    Backup,
    NetworkService,
    WebInterface,
    Process,
    SystemConfig,
    SourceCode,
    CloudInfrastructure,
    NetworkPivot,
    Windows,
    Canary,
    History,
}

impl BaitKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::File => "file",
            Self::Credential => "credential",
            Self::Database => "database",
            Self::Backup => "backup",
            Self::NetworkService => "network_service",
            Self::WebInterface => "web_interface",
            Self::Process => "process",
            Self::SystemConfig => "system_config",
            Self::SourceCode => "source_code",
            Self::CloudInfrastructure => "cloud_infrastructure",
            Self::NetworkPivot => "network_pivot",
            Self::Windows => "windows",
            Self::Canary => "canary",
            Self::History => "history",
        }
    }
}

/// A process row rendered by Middle's virtual Linux environment. It is never executed on the host.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VirtualProcess {
    pub id: Uuid,
    #[serde(default)]
    pub title: String,
    #[serde(default, rename = "category", alias = "kind")]
    pub kind: BaitKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implementation: Option<BaitImplementation>,
    pub name: String,
    pub user: String,
    pub command: String,
    #[serde(default = "default_virtual_process_running")]
    pub running: bool,
    #[serde(default)]
    pub listen_port: Option<u16>,
    #[serde(default, skip_serializing_if = "VirtualProcessConfig::is_default")]
    pub config: VirtualProcessConfig,
}

impl VirtualProcessConfig {
    fn is_default(&self) -> bool {
        self.protocol == VirtualProtocol::Tcp
    }
}

fn default_virtual_process_running() -> bool {
    true
}

pub fn validate_bait_files(baits: &[BaitFile]) -> Result<(), &'static str> {
    use std::collections::HashSet;
    if baits.len() > 32 {
        return Err("at most 32 bait artifacts are supported");
    }
    let mut ids = HashSet::new();
    let mut paths = HashSet::new();
    let mut account_names = HashSet::new();
    let mut account_uids = HashSet::new();
    for bait in baits {
        if bait.id.is_nil() || !ids.insert(bait.id) {
            return Err("bait IDs must be unique nonzero UUIDs");
        }
        if bait.kind == BaitKind::Process {
            return Err("process baits must be configured as virtual processes");
        }
        if bait.name.trim().is_empty()
            || bait.name.len() > 80
            || bait.name.chars().any(char::is_control)
        {
            return Err("bait name must contain 1..80 printable bytes");
        }
        if bait.content.len() > 4096 || bait.content.contains('\0') {
            return Err("bait content must be text of at most 4096 bytes");
        }
        match bait.kind {
            BaitKind::Account => {
                if bait.implementation.is_some_and(|implementation| {
                    implementation != BaitImplementation::VirtualAccount
                        && implementation != BaitImplementation::VirtualFile
                }) {
                    return Err(
                        "account baits must use virtual_account or virtual_file implementation",
                    );
                }
                let login = bait
                    .config
                    .account
                    .as_ref()
                    .map_or(bait.name.as_str(), |account| account.login.as_str());
                if !valid_linux_login(login) || !account_names.insert(login.to_ascii_lowercase()) {
                    return Err("account bait login must be a unique valid Linux login name");
                }
                if let Some(account) = &bait.config.account {
                    if let Some(uid) = account.uid
                        && (uid < 1001 || uid > 65_535 || !account_uids.insert(uid))
                    {
                        return Err("account bait UIDs must be unique and at least 1001");
                    }
                    if let Some(home) = &account.home_directory
                        && !valid_guest_path(home, &["/home/", "/C/Users/"])
                    {
                        return Err("account home directory must be under /home or /C/Users");
                    }
                }
                if let Some(path) = &bait.path
                    && !valid_bait_path(path, &mut paths)
                {
                    return Err("bait path must be unique and inside an allowed guest directory");
                }
            }
            _ => {
                if bait
                    .implementation
                    .is_some_and(|implementation| implementation != BaitImplementation::VirtualFile)
                {
                    return Err("file baits must use the virtual_file implementation");
                }
                let Some(path) = &bait.path else {
                    return Err("virtual_file baits require a path");
                };
                if !valid_bait_path(path, &mut paths) {
                    return Err("bait path must be unique and inside an allowed guest directory");
                }
            }
        }
        if (bait.config.account.is_some() && bait.kind != BaitKind::Account)
            || (bait.config.credential_format.is_some() && bait.kind != BaitKind::Credential)
            || (bait.config.cloud_provider.is_some() && bait.kind != BaitKind::CloudInfrastructure)
            || (bait.config.windows_artifact.is_some() && bait.kind != BaitKind::Windows)
            || (bait.config.database_format.is_some() && bait.kind != BaitKind::Database)
            || (bait.config.backup_format.is_some() && bait.kind != BaitKind::Backup)
            || (bait.config.canary_marker.is_some() && bait.kind != BaitKind::Canary)
            || (bait.config.system_config_format.is_some() && bait.kind != BaitKind::SystemConfig)
            || (bait.config.history_format.is_some() && bait.kind != BaitKind::History)
        {
            return Err("bait config fields must match the bait category");
        }
        if let Some(marker) = &bait.config.canary_marker
            && (marker.is_empty()
                || marker.len() > 128
                || marker.chars().any(char::is_control)
                || !bait.content.contains(marker))
        {
            return Err("canary marker must be printable and present in the bait content");
        }
    }
    if serde_json::to_vec(baits)
        .map_err(|_| "bait serialization failed")?
        .len()
        > 48 * 1024
    {
        return Err("combined bait configuration exceeds 49152 bytes");
    }
    Ok(())
}

fn valid_linux_login(login: &str) -> bool {
    !login.is_empty()
        && login.len() <= 32
        && login
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}

fn valid_bait_path<'a>(path: &'a str, paths: &mut std::collections::HashSet<&'a str>) -> bool {
    let allowed = [
        "/home/admin/",
        "/root/",
        "/tmp/",
        "/opt/",
        "/srv/",
        "/var/backups/",
        "/var/log/",
        "/etc/",
        "/C/Users/",
        "/C/Windows/",
        "/C/Program Files/",
        "/C/ProgramData/",
    ];
    path.len() <= 256
        && allowed.iter().any(|prefix| path.starts_with(prefix))
        && !path.chars().any(char::is_control)
        && !path
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || part == "." || part == ".." || part.len() > 255)
        && paths.insert(path)
}

fn valid_guest_path(path: &str, allowed_roots: &[&str]) -> bool {
    path.len() <= 256
        && allowed_roots.iter().any(|prefix| path.starts_with(prefix))
        && !path.chars().any(char::is_control)
        && !path
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || part == "." || part == ".." || part.len() > 255)
}

pub fn validate_virtual_processes(processes: &[VirtualProcess]) -> Result<(), &'static str> {
    use std::collections::HashSet;
    if processes.len() > 24 {
        return Err("at most 24 virtual processes are supported");
    }
    let mut ids = HashSet::new();
    let mut names = HashSet::new();
    let mut ports = HashSet::new();
    for process in processes {
        if process.id.is_nil() || !ids.insert(process.id) {
            return Err("virtual process IDs must be unique nonzero UUIDs");
        }
        if process
            .implementation
            .is_some_and(|implementation| implementation != BaitImplementation::VirtualProcess)
        {
            return Err("virtual processes must use the virtual_process implementation");
        }
        if process.kind == BaitKind::WebInterface && process.config.protocol != VirtualProtocol::Tcp
        {
            return Err("virtual web interfaces must use TCP");
        }
        if !matches!(
            process.kind,
            BaitKind::Process
                | BaitKind::Database
                | BaitKind::NetworkService
                | BaitKind::WebInterface
        ) {
            return Err(
                "virtual process category must be process, database, network service or web interface",
            );
        }
        if process.name.is_empty()
            || process.name.len() > 48
            || !process
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.@-".contains(&byte))
            || !names.insert(process.name.to_ascii_lowercase())
        {
            return Err(
                "virtual process names must be unique and contain only letters, numbers, '.', '_' or '-'",
            );
        }
        if process.user.is_empty()
            || process.user.len() > 32
            || !process
                .user
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        {
            return Err("virtual process user is invalid");
        }
        if process.command.trim().is_empty()
            || process.command.len() > 256
            || process.command.chars().any(char::is_control)
        {
            return Err("virtual process command must contain 1..256 printable bytes");
        }
        if process.title.len() > 80 || process.title.chars().any(char::is_control) {
            return Err("virtual process title must be at most 80 printable bytes");
        }
        if let Some(port) = process.listen_port
            && (port == 0 || !ports.insert((process.config.protocol, port)))
        {
            return Err("virtual process ports must be unique nonzero ports per protocol");
        }
    }
    if serde_json::to_vec(processes)
        .map_err(|_| "virtual process serialization failed")?
        .len()
        > 12 * 1024
    {
        return Err("virtual process configuration exceeds 12288 bytes");
    }
    Ok(())
}

fn default_pritvoryashka_connections() -> u16 {
    128
}

/// Bounded Docker resource budget passed as typed deployment data. The agent still enforces
/// tier-specific ceilings and renders its own Compose file; callers never supply YAML.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContainerResourceLimits {
    pub cpu_cores: f64,
    pub memory_mb: u32,
    pub pids: u32,
}

impl Default for ContainerResourceLimits {
    fn default() -> Self {
        Self {
            cpu_cores: 0.5,
            memory_mb: 128,
            pids: 64,
        }
    }
}

impl ContainerResourceLimits {
    pub fn middle_default() -> Self {
        Self {
            cpu_cores: 1.0,
            memory_mb: 512,
            pids: 256,
        }
    }

    pub fn within(&self, max_cpu: f64, max_memory_mb: u32, max_pids: u32) -> bool {
        self.cpu_cores.is_finite()
            && self.cpu_cores >= 0.05
            && self.cpu_cores <= max_cpu
            && (32..=max_memory_mb).contains(&self.memory_mb)
            && (16..=max_pids).contains(&self.pids)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighUbuntuDeployment {
    pub command_id: Uuid,
    pub trap_id: Uuid,
    pub base_image: String,
    pub external_ssh_port: u16,
}

/// Guest operating systems supported by the High VM lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HighGuestOs {
    Ubuntu,
    Debian,
    ArchLinux,
    Windows,
    CustomLinux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HighImageFormat {
    Qcow2,
    Iso,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HighImageArchitecture {
    X86_64,
    Aarch64,
    #[serde(other)]
    Unknown,
}

/// An operator-supplied immutable image. A trusted digest is mandatory: transport TLS alone does
/// not prove that a mutable third-party URL still contains the reviewed artefact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HighImageSource {
    pub url: String,
    pub sha256: String,
    pub format: HighImageFormat,
    pub architecture: HighImageArchitecture,
}

/// The immutable artefact expected before an OS adapter starts a VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HighImageKind {
    CloudImage,
    PreparedQcow2,
    InstallMediaAndDisk,
}

/// Per-instance preparation performed by the OS adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HighImagePreparation {
    CloudInitSeed,
    OfflineGuestPreparation,
    UnattendedInstall,
    Sysprep,
    /// Boots isolated installation media and probes the declared guest service. Success depends
    /// on the media providing its own unattended mechanism; arbitrary installers are not claimed
    /// to be universally automatable.
    BestEffortInstall,
}

/// Durable deployment progress for long-running High VM installation workflows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HighLifecycleState {
    Downloading,
    VmCreated,
    Installing,
    Rebooting,
    Configuring,
    #[default]
    Ready,
    Failed,
}

/// The service published externally by a High guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum HighGuestConnection {
    Ssh { guest_port: u16 },
    Rdp { guest_port: u16 },
}

/// A typed OS profile carried across the control plane and persisted by the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HighOsProfile {
    pub guest_os: HighGuestOs,
    pub image_kind: HighImageKind,
    pub image_preparation: HighImagePreparation,
    pub connection: HighGuestConnection,
}

impl HighOsProfile {
    pub const fn ubuntu_ssh() -> Self {
        Self {
            guest_os: HighGuestOs::Ubuntu,
            image_kind: HighImageKind::CloudImage,
            image_preparation: HighImagePreparation::CloudInitSeed,
            connection: HighGuestConnection::Ssh { guest_port: 22 },
        }
    }

    pub const fn arch_linux_ssh() -> Self {
        Self {
            guest_os: HighGuestOs::ArchLinux,
            image_kind: HighImageKind::CloudImage,
            image_preparation: HighImagePreparation::CloudInitSeed,
            connection: HighGuestConnection::Ssh { guest_port: 22 },
        }
    }

    pub const fn debian_ssh() -> Self {
        Self {
            guest_os: HighGuestOs::Debian,
            image_kind: HighImageKind::CloudImage,
            image_preparation: HighImagePreparation::CloudInitSeed,
            connection: HighGuestConnection::Ssh { guest_port: 22 },
        }
    }

    pub const fn windows_rdp() -> Self {
        Self {
            guest_os: HighGuestOs::Windows,
            image_kind: HighImageKind::PreparedQcow2,
            image_preparation: HighImagePreparation::Sysprep,
            connection: HighGuestConnection::Rdp { guest_port: 3389 },
        }
    }

    /// Compatibility profile for manifests created by the original ISO installer adapter.
    pub const fn windows_rdp_legacy_iso() -> Self {
        Self {
            guest_os: HighGuestOs::Windows,
            image_kind: HighImageKind::InstallMediaAndDisk,
            image_preparation: HighImagePreparation::UnattendedInstall,
            connection: HighGuestConnection::Rdp { guest_port: 3389 },
        }
    }

    pub const fn ubuntu_iso_ssh() -> Self {
        Self {
            guest_os: HighGuestOs::Ubuntu,
            image_kind: HighImageKind::InstallMediaAndDisk,
            image_preparation: HighImagePreparation::UnattendedInstall,
            connection: HighGuestConnection::Ssh { guest_port: 22 },
        }
    }

    pub const fn debian_iso_ssh() -> Self {
        Self {
            guest_os: HighGuestOs::Debian,
            image_kind: HighImageKind::InstallMediaAndDisk,
            image_preparation: HighImagePreparation::UnattendedInstall,
            connection: HighGuestConnection::Ssh { guest_port: 22 },
        }
    }

    pub const fn arch_linux_iso_ssh() -> Self {
        Self {
            guest_os: HighGuestOs::ArchLinux,
            image_kind: HighImageKind::InstallMediaAndDisk,
            image_preparation: HighImagePreparation::UnattendedInstall,
            connection: HighGuestConnection::Ssh { guest_port: 22 },
        }
    }

    pub const fn custom_linux_qcow2_ssh() -> Self {
        Self {
            guest_os: HighGuestOs::CustomLinux,
            image_kind: HighImageKind::CloudImage,
            image_preparation: HighImagePreparation::CloudInitSeed,
            connection: HighGuestConnection::Ssh { guest_port: 22 },
        }
    }

    pub const fn custom_linux_iso_ssh() -> Self {
        Self {
            guest_os: HighGuestOs::CustomLinux,
            image_kind: HighImageKind::InstallMediaAndDisk,
            image_preparation: HighImagePreparation::BestEffortInstall,
            connection: HighGuestConnection::Ssh { guest_port: 22 },
        }
    }
}

/// Common High deployment contract used by all OS adapters.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HighVmDeployment {
    pub command_id: Uuid,
    pub trap_id: Uuid,
    pub base_image: String,
    #[serde(alias = "external_ssh_port")]
    pub external_service_port: u16,
    #[serde(default = "HighOsProfile::ubuntu_ssh")]
    pub profile: HighOsProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_source: Option<HighImageSource>,
}

impl From<HighUbuntuDeployment> for HighVmDeployment {
    fn from(value: HighUbuntuDeployment) -> Self {
        Self {
            command_id: value.command_id,
            trap_id: value.trap_id,
            base_image: value.base_image,
            external_service_port: value.external_ssh_port,
            profile: HighOsProfile::ubuntu_ssh(),
            image_source: None,
        }
    }
}

/// Agent-side transition from one direct trap to a shared external TCP listener.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpPortGroup {
    pub command_id: Uuid,
    pub listener_port: u16,
    pub members: Vec<TcpPortGroupMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpPortGroupMember {
    pub trap_id: Uuid,
    pub backend_port: u16,
    pub weight: u8,
    #[serde(default)]
    pub trap_kind: SharedTcpTrapKind,
}

/// The Dispatcher only sees TCP targets; the agent needs this to recreate the correct recipe on
/// a loopback backend port during a direct-listener → shared-listener transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SharedTcpTrapKind {
    #[default]
    Kozyavka,
    Pritvoryashka,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub command_id: Uuid,
    pub trap_id: Uuid,
    pub success: bool,
    pub detail: String,
}

#[async_trait]
pub trait RemoteBootstrap: Send + Sync {
    /// Execute a prepared, non-interactive installation script on a VPS exactly once.
    async fn install_agent(
        &self,
        target: SshBootstrapTarget,
        script: BootstrapScript,
    ) -> Result<(), CoreError>;
}

/// HFSP stays identical regardless of whether packets travel through Hysteria, TCP, HTTPS or LoRa.
pub const HFSP_MAGIC: [u8; 4] = *b"HFSP";
pub const HFSP_VERSION: u8 = 1;
pub const HFSP_HEADER_LEN: usize = 28;
pub const HFSP_MAX_PAYLOAD_LEN: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum HfspMessageKind {
    Register = 1,
    Command = 2,
    Telemetry = 3,
    Ack = 4,
    Heartbeat = 5,
    Error = 6,
}

impl TryFrom<u8> for HfspMessageKind {
    type Error = HfspCodecError;

    fn try_from(value: u8) -> Result<Self, HfspCodecError> {
        match value {
            1 => Ok(Self::Register),
            2 => Ok(Self::Command),
            3 => Ok(Self::Telemetry),
            4 => Ok(Self::Ack),
            5 => Ok(Self::Heartbeat),
            6 => Ok(Self::Error),
            _ => Err(HfspCodecError::UnknownMessageKind(value)),
        }
    }
}

/// Wire frame: fixed header followed by an opaque serialized payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HfspFrame {
    pub kind: HfspMessageKind,
    pub flags: u16,
    pub sequence: u64,
    pub acknowledgement: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum HfspCodecError {
    #[error("HFSP frame is truncated")]
    Truncated,
    #[error("invalid HFSP magic")]
    InvalidMagic,
    #[error("unsupported HFSP version {0}")]
    UnsupportedVersion(u8),
    #[error("unknown HFSP message kind {0}")]
    UnknownMessageKind(u8),
    #[error("HFSP payload length is invalid")]
    InvalidLength,
    #[error("HFSP payload exceeds the maximum size")]
    PayloadTooLarge,
    #[error("payload serialization failed: {0}")]
    Serialization(String),
}

impl HfspFrame {
    pub fn from_json<T: Serialize>(
        kind: HfspMessageKind,
        sequence: u64,
        acknowledgement: u64,
        payload: &T,
    ) -> Result<Self, HfspCodecError> {
        let payload = serde_json::to_vec(payload)
            .map_err(|error| HfspCodecError::Serialization(error.to_string()))?;
        Ok(Self {
            kind,
            flags: 0,
            sequence,
            acknowledgement,
            payload,
        })
    }

    pub fn payload_json<T: for<'de> Deserialize<'de>>(&self) -> Result<T, HfspCodecError> {
        serde_json::from_slice(&self.payload)
            .map_err(|error| HfspCodecError::Serialization(error.to_string()))
    }

    pub fn encode(&self) -> Result<Vec<u8>, HfspCodecError> {
        if self.payload.len() > HFSP_MAX_PAYLOAD_LEN {
            return Err(HfspCodecError::PayloadTooLarge);
        }
        let payload_len =
            u32::try_from(self.payload.len()).map_err(|_| HfspCodecError::PayloadTooLarge)?;
        let mut bytes = Vec::with_capacity(HFSP_HEADER_LEN + self.payload.len());
        bytes.extend_from_slice(&HFSP_MAGIC);
        bytes.push(HFSP_VERSION);
        bytes.push(self.kind as u8);
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.acknowledgement.to_be_bytes());
        bytes.extend_from_slice(&payload_len.to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, HfspCodecError> {
        if bytes.len() < HFSP_HEADER_LEN {
            return Err(HfspCodecError::Truncated);
        }
        if bytes[0..4] != HFSP_MAGIC {
            return Err(HfspCodecError::InvalidMagic);
        }
        if bytes[4] != HFSP_VERSION {
            return Err(HfspCodecError::UnsupportedVersion(bytes[4]));
        }
        let kind = HfspMessageKind::try_from(bytes[5])?;
        let flags = u16::from_be_bytes(bytes[6..8].try_into().expect("fixed slice"));
        let sequence = u64::from_be_bytes(bytes[8..16].try_into().expect("fixed slice"));
        let acknowledgement = u64::from_be_bytes(bytes[16..24].try_into().expect("fixed slice"));
        let payload_len =
            u32::from_be_bytes(bytes[24..28].try_into().expect("fixed slice")) as usize;
        if payload_len > HFSP_MAX_PAYLOAD_LEN {
            return Err(HfspCodecError::PayloadTooLarge);
        }
        if bytes.len() != HFSP_HEADER_LEN + payload_len {
            return Err(HfspCodecError::InvalidLength);
        }
        Ok(Self {
            kind,
            flags,
            sequence,
            acknowledgement,
            payload: bytes[HFSP_HEADER_LEN..].to_vec(),
        })
    }
}

#[derive(Debug, Error)]
#[error("{transport}: {message}")]
pub struct TransportError {
    pub transport: &'static str,
    pub message: String,
}

/// Replaceable boundary beneath HFSP. Implementations carry complete encoded HFSP packets.
#[async_trait]
pub trait PacketTransport: Send + Sync + fmt::Debug {
    fn name(&self) -> &'static str;
    async fn send(&self, packet: &[u8]) -> Result<(), TransportError>;
    async fn receive(&self) -> Result<Vec<u8>, TransportError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hfsp_round_trip_preserves_header_and_json_payload() {
        let frame = HfspFrame::from_json(
            HfspMessageKind::Telemetry,
            7,
            4,
            &serde_json::json!({"event": "hit"}),
        )
        .unwrap();
        let decoded = HfspFrame::decode(&frame.encode().unwrap()).unwrap();
        assert_eq!(decoded.kind, HfspMessageKind::Telemetry);
        assert_eq!(decoded.sequence, 7);
        assert_eq!(
            decoded.payload_json::<serde_json::Value>().unwrap()["event"],
            "hit"
        );
    }

    #[test]
    fn high_profiles_round_trip_without_losing_adapter_contract() {
        for profile in [
            HighOsProfile::ubuntu_ssh(),
            HighOsProfile::debian_ssh(),
            HighOsProfile::arch_linux_ssh(),
            HighOsProfile::windows_rdp(),
            HighOsProfile::windows_rdp_legacy_iso(),
            HighOsProfile::ubuntu_iso_ssh(),
            HighOsProfile::debian_iso_ssh(),
            HighOsProfile::arch_linux_iso_ssh(),
            HighOsProfile::custom_linux_qcow2_ssh(),
            HighOsProfile::custom_linux_iso_ssh(),
        ] {
            let encoded = serde_json::to_vec(&profile).unwrap();
            assert_eq!(
                serde_json::from_slice::<HighOsProfile>(&encoded).unwrap(),
                profile
            );
        }
    }

    #[test]
    fn high_lifecycle_states_use_backend_facing_names() {
        assert_eq!(
            serde_json::to_string(&HighLifecycleState::Downloading).unwrap(),
            "\"DOWNLOADING\""
        );
        assert_eq!(
            serde_json::to_string(&HighLifecycleState::VmCreated).unwrap(),
            "\"VM_CREATED\""
        );
        assert_eq!(
            serde_json::from_str::<HighLifecycleState>("\"REBOOTING\"").unwrap(),
            HighLifecycleState::Rebooting
        );
    }

    #[test]
    fn legacy_ubuntu_deployment_converts_to_the_generic_contract() {
        let legacy = HighUbuntuDeployment {
            command_id: Uuid::new_v4(),
            trap_id: Uuid::new_v4(),
            base_image: "/images/ubuntu.qcow2".into(),
            external_ssh_port: 2222,
        };
        let generic: HighVmDeployment = legacy.clone().into();
        assert_eq!(generic.command_id, legacy.command_id);
        assert_eq!(generic.trap_id, legacy.trap_id);
        assert_eq!(generic.base_image, legacy.base_image);
        assert_eq!(generic.external_service_port, legacy.external_ssh_port);
        assert_eq!(generic.profile, HighOsProfile::ubuntu_ssh());
        assert!(generic.image_source.is_none());
    }

    #[test]
    fn custom_image_source_round_trip_preserves_integrity_contract() {
        let deployment = HighVmDeployment {
            command_id: Uuid::new_v4(),
            trap_id: Uuid::new_v4(),
            base_image: String::new(),
            external_service_port: 2222,
            profile: HighOsProfile::debian_ssh(),
            image_source: Some(HighImageSource {
                url: "https://images.example.invalid/debian.qcow2".into(),
                sha256: "a".repeat(64),
                format: HighImageFormat::Qcow2,
                architecture: HighImageArchitecture::X86_64,
            }),
        };
        let encoded = serde_json::to_vec(&deployment).unwrap();
        let decoded: HighVmDeployment = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.image_source, deployment.image_source);
        assert_eq!(decoded.profile, HighOsProfile::debian_ssh());

        let unsupported: HighImageArchitecture = serde_json::from_str("\"sparc64\"").unwrap();
        assert_eq!(unsupported, HighImageArchitecture::Unknown);
    }
}

fn default_middle_username() -> String {
    "admin".into()
}

fn default_middle_distribution() -> String {
    "ubuntu".into()
}
