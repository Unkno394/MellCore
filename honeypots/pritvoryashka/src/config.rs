use std::{collections::BTreeSet, net::SocketAddr, path::PathBuf, time::Duration};

use chrono::Utc;
use hf_core::{BaitFile, VirtualProcess};
use serde::Deserialize;
use thiserror::Error;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Default, Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Distribution {
    #[default]
    Ubuntu,
    Debian,
    Arch,
    Windows,
}

/// Immutable defaults for a Linux guest. Mutable facts such as installed
/// package versions belong to the guest's virtual state, not this profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinuxProfile {
    pub distribution: Distribution,
    pub package_manager: PackageManager,
    pub bash_version: &'static str,
    pub kernel_release: &'static str,
    pub proc_version: &'static str,
    pub os_release: &'static str,
    pub issue: &'static str,
    pub systemd_unit_dir: &'static str,
    pub ssh_service: &'static str,
    pub cron_service: &'static str,
    pub postgres_command: &'static str,
    pub sshd_command: &'static str,
    pub cron_command: &'static str,
    pub systemd_version: &'static str,
    pub systemd_package_version: &'static str,
    pub nginx_executable: &'static str,
    pub nginx_version: &'static str,
    pub sshd_executable: &'static str,
    pub openssh_version: &'static str,
    pub redis_command: Option<&'static str>,
    pub redis_process_command: &'static str,
    pub redis_service_name: &'static str,
    pub redis_description: &'static str,
    pub redis_user: &'static str,
    pub redis_pid_file: &'static str,
    pub redis_store_file: &'static str,
    pub services: &'static [LinuxServiceProfile],
    pub mysql_service: &'static str,
    pub mysql_command: &'static str,
    pub nginx_worker_user: &'static str,
    pub apt_suite: &'static str,
    pub apt_mirror: &'static str,
    pub apt_codename: &'static str,
    pub debian_version: &'static str,
    pub redis_config_file: &'static str,
    pub redis_cli_executable: &'static str,
    pub redis_data_dir: &'static str,
    pub containerd_version_output: &'static str,
    pub dockerd_version_output: &'static str,
    pub dbus_version_output: &'static str,
    pub dash_version_output: &'static str,
    pub nano_version_output: &'static str,
    pub apt_version_output: &'static str,
    pub dpkg_version_output: &'static str,
    pub operating_system_name: &'static str,
    pub nginx_master_command: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinuxServiceProfile {
    pub name: &'static str,
    pub description: &'static str,
    pub pid: u32,
    pub user: &'static str,
    pub command: &'static str,
    pub rss_kib: u32,
    pub port: Option<u16>,
    pub address: &'static str,
    pub static_unit: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageManager {
    Apt,
    Pacman,
}

const UBUNTU_SERVICES: &[LinuxServiceProfile] = &[
    LinuxServiceProfile {
        name: "docker",
        description: "Docker Application Container Engine",
        pid: 901,
        user: "root",
        command: "/usr/bin/dockerd -H fd://",
        rss_kib: 74600,
        port: None,
        address: "",
        static_unit: false,
    },
    LinuxServiceProfile {
        name: "postgresql",
        description: "PostgreSQL RDBMS",
        pid: 721,
        user: "postgres",
        command: "/usr/lib/postgresql/14/bin/postgres",
        rss_kib: 42100,
        port: Some(5432),
        address: "127.0.0.1",
        static_unit: false,
    },
    LinuxServiceProfile {
        name: "ssh",
        description: "OpenBSD Secure Shell server",
        pid: 684,
        user: "root",
        command: "/usr/sbin/sshd -D",
        rss_kib: 9260,
        port: Some(22),
        address: "0.0.0.0",
        static_unit: false,
    },
    LinuxServiceProfile {
        name: "cron",
        description: "Regular background program processing daemon",
        pid: 593,
        user: "root",
        command: "/usr/sbin/cron -f",
        rss_kib: 2632,
        port: None,
        address: "",
        static_unit: false,
    },
    LinuxServiceProfile {
        name: "systemd-journald",
        description: "Journal Service",
        pid: 362,
        user: "root",
        command: "/lib/systemd/systemd-journald",
        rss_kib: 8832,
        port: None,
        address: "",
        static_unit: true,
    },
    LinuxServiceProfile {
        name: "systemd-resolved",
        description: "Network Name Resolution",
        pid: 512,
        user: "systemd-resolve",
        command: "/lib/systemd/systemd-resolved",
        rss_kib: 7680,
        port: None,
        address: "",
        static_unit: false,
    },
    LinuxServiceProfile {
        name: "dbus",
        description: "D-Bus System Message Bus",
        pid: 542,
        user: "messagebus",
        command: "/usr/bin/dbus-daemon --system",
        rss_kib: 4120,
        port: None,
        address: "",
        static_unit: false,
    },
];

const DEBIAN_SERVICES: &[LinuxServiceProfile] = &[
    LinuxServiceProfile {
        name: "docker",
        description: "Docker Application Container Engine",
        pid: 901,
        user: "root",
        command: "/usr/bin/dockerd -H fd://",
        rss_kib: 74600,
        port: None,
        address: "",
        static_unit: false,
    },
    LinuxServiceProfile {
        name: "postgresql@17-main",
        description: "PostgreSQL Cluster 17-main",
        pid: 721,
        user: "postgres",
        command: "/usr/lib/postgresql/17/bin/postgres -D /var/lib/postgresql/17/main",
        rss_kib: 42100,
        port: Some(5432),
        address: "127.0.0.1",
        static_unit: false,
    },
    LinuxServiceProfile {
        name: "ssh",
        description: "OpenBSD Secure Shell server",
        pid: 684,
        user: "root",
        command: "/usr/sbin/sshd -D",
        rss_kib: 9260,
        port: Some(22),
        address: "0.0.0.0",
        static_unit: false,
    },
    LinuxServiceProfile {
        name: "cron",
        description: "Regular background program processing daemon",
        pid: 593,
        user: "root",
        command: "/usr/sbin/cron -f",
        rss_kib: 2632,
        port: None,
        address: "",
        static_unit: false,
    },
    LinuxServiceProfile {
        name: "systemd-journald",
        description: "Journal Service",
        pid: 362,
        user: "root",
        command: "/lib/systemd/systemd-journald",
        rss_kib: 8832,
        port: None,
        address: "",
        static_unit: true,
    },
    LinuxServiceProfile {
        name: "systemd-resolved",
        description: "Network Name Resolution",
        pid: 512,
        user: "systemd-resolve",
        command: "/lib/systemd/systemd-resolved",
        rss_kib: 7680,
        port: None,
        address: "",
        static_unit: false,
    },
    LinuxServiceProfile {
        name: "dbus",
        description: "D-Bus System Message Bus",
        pid: 542,
        user: "messagebus",
        command: "/usr/bin/dbus-daemon --system",
        rss_kib: 4120,
        port: None,
        address: "",
        static_unit: false,
    },
];

const ARCH_SERVICES: &[LinuxServiceProfile] = &[
    LinuxServiceProfile {
        name: "docker",
        description: "Docker Application Container Engine",
        pid: 901,
        user: "root",
        command: "/usr/bin/dockerd -H fd://",
        rss_kib: 74600,
        port: None,
        address: "",
        static_unit: false,
    },
    LinuxServiceProfile {
        name: "postgresql",
        description: "PostgreSQL RDBMS",
        pid: 721,
        user: "postgres",
        command: "/usr/bin/postgres -D /var/lib/postgres/data",
        rss_kib: 42100,
        port: Some(5432),
        address: "127.0.0.1",
        static_unit: false,
    },
    LinuxServiceProfile {
        name: "valkey",
        description: "In-memory data structure store",
        pid: 1224,
        user: "valkey",
        command: "/usr/bin/valkey-server /etc/valkey/valkey.conf",
        rss_kib: 13820,
        port: Some(6379),
        address: "127.0.0.1",
        static_unit: false,
    },
    LinuxServiceProfile {
        name: "sshd",
        description: "OpenBSD Secure Shell server",
        pid: 684,
        user: "root",
        command: "/usr/bin/sshd -D",
        rss_kib: 9260,
        port: Some(22),
        address: "0.0.0.0",
        static_unit: false,
    },
    LinuxServiceProfile {
        name: "cronie",
        description: "Command Scheduler",
        pid: 593,
        user: "root",
        command: "/usr/bin/crond -n",
        rss_kib: 2632,
        port: None,
        address: "",
        static_unit: false,
    },
    LinuxServiceProfile {
        name: "systemd-journald",
        description: "Journal Service",
        pid: 362,
        user: "root",
        command: "/usr/lib/systemd/systemd-journald",
        rss_kib: 8832,
        port: None,
        address: "",
        static_unit: true,
    },
    LinuxServiceProfile {
        name: "systemd-resolved",
        description: "Network Name Resolution",
        pid: 512,
        user: "systemd-resolve",
        command: "/usr/lib/systemd/systemd-resolved",
        rss_kib: 7680,
        port: None,
        address: "",
        static_unit: false,
    },
    LinuxServiceProfile {
        name: "dbus-broker",
        description: "D-Bus System Message Bus",
        pid: 542,
        user: "dbus",
        command: "/usr/bin/dbus-broker-launch --scope system --audit",
        rss_kib: 4120,
        port: None,
        address: "",
        static_unit: false,
    },
];

const UBUNTU_PROFILE: LinuxProfile = LinuxProfile {
    distribution: Distribution::Ubuntu,
    package_manager: PackageManager::Apt,
    bash_version: "5.1.16",
    kernel_release: "5.15.0-119-generic",
    proc_version: "Linux version 5.15.0-119-generic (buildd@lcy02-amd64-118) #129-Ubuntu SMP",
    os_release: "NAME=\"Ubuntu\"\nVERSION=\"22.04.4 LTS (Jammy Jellyfish)\"\nID=ubuntu\nVERSION_ID=\"22.04\"\nPRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\n",
    issue: "Ubuntu 22.04.4 LTS \\n \\l\n",
    systemd_unit_dir: "/lib/systemd/system",
    ssh_service: "ssh",
    cron_service: "cron",
    postgres_command: "/usr/lib/postgresql/14/bin/postgres",
    sshd_command: "/usr/sbin/sshd -D",
    cron_command: "/usr/sbin/cron -f",
    systemd_version: "249",
    systemd_package_version: "249.11-0ubuntu3.12",
    nginx_executable: "/usr/sbin/nginx",
    nginx_version: "1.18.0 (Ubuntu)",
    sshd_executable: "/usr/sbin/sshd",
    openssh_version: "OpenSSH_9.6p1, OpenSSL 3.0.13",
    redis_command: Some("/usr/bin/redis-server"),
    redis_process_command: "/usr/bin/redis-server /etc/redis/redis.conf",
    redis_service_name: "redis-server",
    redis_description: "Advanced key-value store",
    redis_user: "redis",
    redis_pid_file: "/run/redis-server.pid",
    redis_store_file: "/var/lib/redis/virtual-store.json",
    services: UBUNTU_SERVICES,
    mysql_service: "mysql",
    mysql_command: "/usr/sbin/mysqld --defaults-file=/etc/mysql/mysql.conf.d/mysqld.cnf",
    nginx_worker_user: "www-data",
    apt_suite: "jammy/main",
    apt_mirror: "http://archive.ubuntu.com/ubuntu",
    apt_codename: "jammy",
    debian_version: "",
    redis_config_file: "/etc/redis/redis.conf",
    redis_cli_executable: "/usr/bin/redis-cli",
    redis_data_dir: "/var/lib/redis",
    containerd_version_output: "containerd github.com/containerd/containerd 1.6.28-0ubuntu1\n",
    dockerd_version_output: "Docker version 24.0.7, build 24.0.7-0ubuntu2~22.04.1\n",
    dbus_version_output: "D-Bus Message Bus Daemon 1.12.20\n",
    dash_version_output: "\nDash 0.5.11\n\n",
    nano_version_output: "GNU nano, version 6.2\n",
    apt_version_output: "apt 2.4.12 (amd64)\n",
    dpkg_version_output: "Debian 'dpkg' package management program version 1.21.1ubuntu2.3 (amd64).\n",
    operating_system_name: "Ubuntu 22.04.4 LTS",
    nginx_master_command: "nginx: master process /usr/sbin/nginx",
};

const DEBIAN_PROFILE: LinuxProfile = LinuxProfile {
    distribution: Distribution::Debian,
    package_manager: PackageManager::Apt,
    bash_version: "5.2.37",
    kernel_release: "6.12.111+deb13-amd64",
    proc_version: "Linux version 6.12.111+deb13-amd64 (debian-kernel@lists.debian.org) #1 SMP PREEMPT_DYNAMIC Debian 6.12.111-1",
    os_release: "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"13\"\nVERSION=\"13 (trixie)\"\nVERSION_CODENAME=trixie\nID=debian\nHOME_URL=\"https://www.debian.org/\"\nSUPPORT_URL=\"https://www.debian.org/support\"\nBUG_REPORT_URL=\"https://bugs.debian.org/\"\n",
    issue: "Debian GNU/Linux 13 \\n \\l\n",
    systemd_unit_dir: "/lib/systemd/system",
    ssh_service: "ssh",
    cron_service: "cron",
    postgres_command: "/usr/lib/postgresql/17/bin/postgres -D /var/lib/postgresql/17/main",
    sshd_command: "/usr/sbin/sshd -D",
    cron_command: "/usr/sbin/cron -f",
    systemd_version: "257",
    systemd_package_version: "257.9-1~deb13u1",
    nginx_executable: "/usr/sbin/nginx",
    nginx_version: "1.26.3",
    sshd_executable: "/usr/sbin/sshd",
    openssh_version: "OpenSSH_9.6p1, OpenSSL 3.0.13",
    redis_command: Some("/usr/bin/redis-server"),
    redis_process_command: "/usr/bin/redis-server /etc/redis/redis.conf",
    redis_service_name: "redis-server",
    redis_description: "Advanced key-value store",
    redis_user: "redis",
    redis_pid_file: "/run/redis-server.pid",
    redis_store_file: "/var/lib/redis/virtual-store.json",
    services: DEBIAN_SERVICES,
    mysql_service: "mysql",
    mysql_command: "/usr/sbin/mysqld --defaults-file=/etc/mysql/mysql.conf.d/mysqld.cnf",
    nginx_worker_user: "www-data",
    apt_suite: "trixie/main",
    apt_mirror: "http://deb.debian.org/debian",
    apt_codename: "trixie",
    debian_version: "13.7",
    redis_config_file: "/etc/redis/redis.conf",
    redis_cli_executable: "/usr/bin/redis-cli",
    redis_data_dir: "/var/lib/redis",
    containerd_version_output: "containerd github.com/containerd/containerd 1.7.24~ds1-6+deb13u1\n",
    dockerd_version_output: "Docker version 26.1.5, build 26.1.5+dfsg1-9+deb13u1\n",
    dbus_version_output: "D-Bus Message Bus Daemon 1.16.2\n",
    dash_version_output: "\nDash 0.5.12-12\n\n",
    nano_version_output: "GNU nano, version 8.4\n",
    apt_version_output: "apt 3.0.3 (amd64)\n",
    dpkg_version_output: "Debian 'dpkg' package management program version 1.22.22 (amd64).\n",
    operating_system_name: "Debian GNU/Linux 13 (trixie)",
    nginx_master_command: "nginx: master process /usr/sbin/nginx",
};

const ARCH_PROFILE: LinuxProfile = LinuxProfile {
    distribution: Distribution::Arch,
    package_manager: PackageManager::Pacman,
    bash_version: "5.3.20",
    kernel_release: "6.17.0-arch1-1",
    proc_version: "Linux version 6.17.0-arch1-1 (linux@archlinux) #1 SMP PREEMPT_DYNAMIC",
    os_release: "NAME=\"Arch Linux\"\nPRETTY_NAME=\"Arch Linux\"\nID=arch\nBUILD_ID=rolling\n",
    issue: "Arch Linux \\r (\\l)\n",
    systemd_unit_dir: "/usr/lib/systemd/system",
    ssh_service: "sshd",
    cron_service: "cronie",
    postgres_command: "/usr/bin/postgres -D /var/lib/postgres/data",
    sshd_command: "/usr/bin/sshd -D",
    cron_command: "/usr/bin/crond -n",
    systemd_version: "262",
    systemd_package_version: "262-1",
    nginx_executable: "/usr/bin/nginx",
    nginx_version: "1.30.5",
    sshd_executable: "/usr/bin/sshd",
    openssh_version: "OpenSSH_10.6p1, OpenSSL 3.5.2",
    redis_command: Some("/usr/bin/valkey-server"),
    redis_process_command: "/usr/bin/valkey-server /etc/valkey/valkey.conf",
    redis_service_name: "valkey",
    redis_description: "In-memory data structure store",
    redis_user: "valkey",
    redis_pid_file: "/run/valkey.pid",
    redis_store_file: "/var/lib/valkey/virtual-store.json",
    services: ARCH_SERVICES,
    mysql_service: "mariadb",
    mysql_command: "/usr/bin/mariadbd --defaults-file=/etc/my.cnf --port=13306",
    nginx_worker_user: "http",
    apt_suite: "",
    apt_mirror: "",
    apt_codename: "",
    debian_version: "",
    redis_config_file: "/etc/valkey/valkey.conf",
    redis_cli_executable: "/usr/bin/valkey-cli",
    redis_data_dir: "/var/lib/valkey",
    containerd_version_output: "",
    dockerd_version_output: "Docker version 28.3.3\n",
    dbus_version_output: "D-Bus Message Bus Daemon 1.16.2\n",
    dash_version_output: "\nDash 0.5.11\n\n",
    nano_version_output: "GNU nano, version 8.4\n",
    apt_version_output: "",
    dpkg_version_output: "",
    operating_system_name: "Arch Linux",
    nginx_master_command: "nginx: master process /usr/bin/nginx",
};

impl Distribution {
    pub fn linux_profile(self) -> Option<&'static LinuxProfile> {
        match self {
            Self::Ubuntu => Some(&UBUNTU_PROFILE),
            Self::Debian => Some(&DEBIAN_PROFILE),
            Self::Arch => Some(&ARCH_PROFILE),
            Self::Windows => None,
        }
    }

    pub fn is_apt(self) -> bool {
        self.linux_profile()
            .is_some_and(|profile| profile.package_manager == PackageManager::Apt)
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ubuntu => "ubuntu",
            Self::Debian => "debian",
            Self::Arch => "arch",
            Self::Windows => "windows",
        }
    }
    pub fn os_release(self) -> &'static str {
        self.linux_profile()
            .map_or("", |profile| profile.os_release)
    }
    pub fn issue(self) -> &'static str {
        self.linux_profile().map_or("", |profile| profile.issue)
    }

    pub fn kernel_release(self) -> &'static str {
        self.linux_profile()
            .map_or("", |profile| profile.kernel_release)
    }

    pub fn proc_version(self) -> &'static str {
        self.linux_profile()
            .map_or("", |profile| profile.proc_version)
    }
}

impl LinuxProfile {
    pub fn service(&self, name: &str) -> Option<&'static LinuxServiceProfile> {
        self.services.iter().find(|service| service.name == name)
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub bind: SocketAddr,
    #[serde(default)]
    pub ssh_public_port: Option<u16>,
    pub health_bind: SocketAddr,
    pub trap_id: Uuid,
    pub server_id: Uuid,
    pub agent_id: Uuid,
    #[serde(default = "default_hostname")]
    pub hostname: String,
    #[serde(default = "default_username")]
    pub username: String,
    #[serde(default)]
    pub distribution: Distribution,
    pub host_key: PathBuf,
    /// A Dispatcher group uses the same SSH identification and host key for every member.
    #[serde(default)]
    pub shared_ssh_identity: bool,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub ssh_auth_mode: SshAuthMode,
    #[serde(default = "default_ssh_credentials")]
    pub ssh_credentials: Vec<SshCredential>,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_idle_seconds")]
    pub idle_timeout_seconds: u64,
    #[serde(default = "default_input_bytes")]
    pub max_input_bytes: usize,
    #[serde(default)]
    pub baits: Vec<BaitFile>,
    #[serde(default)]
    pub virtual_processes: Vec<VirtualProcess>,
    #[serde(default)]
    pub vulnerability_profiles: Vec<String>,
    #[serde(default)]
    pub network_listeners: Vec<NetworkListener>,
    /// Present only on Middle instances behind the host Dispatcher. Raw client-supplied
    /// PROXY headers are ignored unless this per-trap authentication key is configured.
    #[serde(default)]
    pub dispatcher_proxy_secret: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SshAuthMode {
    #[default]
    Realistic,
    Adaptive,
}

#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct SshCredential {
    pub username: String,
    pub password: String,
}

fn default_ssh_credentials() -> Vec<SshCredential> {
    vec![
        SshCredential {
            username: "root".into(),
            password: "admin123".into(),
        },
        SshCredential {
            username: "admin".into(),
            password: "password123".into(),
        },
        SshCredential {
            username: "test".into(),
            password: "test".into(),
        },
    ]
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkListener {
    pub service_type: String,
    pub bind: SocketAddr,
    #[serde(default)]
    pub public_port: Option<u16>,
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    pub policy: AuthPolicy,
    pub username: Option<String>,
    pub password_env: Option<String>,
    pub capture: CredentialCapture,
    pub max_attempts: usize,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthPolicy {
    AcceptAll,
    Configured,
    RejectAll,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialCapture {
    None,
    Username,
    Password,
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    pub endpoint: Option<String>,
    pub token_env: Option<String>,
    pub jsonl_path: Option<PathBuf>,
    pub queue_capacity: usize,
    pub batch_size: usize,
    pub flush_interval_ms: u64,
    pub max_event_bytes: usize,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            policy: AuthPolicy::AcceptAll,
            username: None,
            password_env: None,
            capture: CredentialCapture::Username,
            max_attempts: 6,
        }
    }
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            endpoint: None,
            token_env: None,
            jsonl_path: Some(PathBuf::from("pritvoryashka-events.jsonl")),
            queue_capacity: 1024,
            batch_size: 50,
            flush_interval_ms: 500,
            max_event_bytes: 65_536,
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot read configuration: {0}")]
    Read(#[from] std::io::Error),
    #[error("invalid configuration JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid configuration: {0}")]
    Invalid(&'static str),
}

impl Config {
    pub async fn load(path: impl AsRef<std::path::Path>) -> Result<Self, ConfigError> {
        let bytes = tokio::fs::read(path).await?;
        let config: Self = serde_json::from_slice(&bytes)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.trap_id.is_nil() || self.server_id.is_nil() || self.agent_id.is_nil() {
            return Err(ConfigError::Invalid("identity UUIDs must not be nil"));
        }
        if self.ssh_public_port == Some(0) {
            return Err(ConfigError::Invalid("public SSH port must be nonzero"));
        }
        if self
            .dispatcher_proxy_secret
            .as_deref()
            .is_some_and(|secret| {
                secret.len() != 32 || !secret.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        {
            return Err(ConfigError::Invalid(
                "Dispatcher PROXY protocol key is invalid",
            ));
        }
        if self.hostname.is_empty()
            || self.hostname.len() > 64
            || !self
                .hostname
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
        {
            return Err(ConfigError::Invalid("hostname is invalid"));
        }
        if self.username.len() > 32
            || self.username == "root"
            || !self
                .username
                .as_bytes()
                .first()
                .is_some_and(|b| b.is_ascii_lowercase() || *b == b'_')
            || !self
                .username
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        {
            return Err(ConfigError::Invalid("username is invalid"));
        }
        if self.auth.policy == AuthPolicy::Configured
            && self.auth.username.as_deref() != Some(self.username.as_str())
        {
            return Err(ConfigError::Invalid(
                "configured SSH username must match virtual username",
            ));
        }
        hf_core::validate_bait_files(&self.baits).map_err(ConfigError::Invalid)?;
        if self.distribution == Distribution::Windows {
            if self
                .baits
                .iter()
                .filter_map(|bait| bait.config.account.as_ref())
                .any(|account| {
                    !account
                        .home_directory
                        .as_deref()
                        .is_some_and(|home| home.starts_with("/C/Users/"))
                        || account.uid.is_some()
                        || account.shell.is_some()
                })
            {
                return Err(ConfigError::Invalid(
                    "Windows account baits require a /C/Users/ home directory and no Linux UID or shell",
                ));
            }
            if self
                .baits
                .iter()
                .filter_map(|bait| bait.path.as_deref())
                .any(|path| !path.starts_with("/C/"))
            {
                return Err(ConfigError::Invalid(
                    "Windows bait files must use virtual /C/... paths",
                ));
            }
        } else if self
            .baits
            .iter()
            .filter_map(|bait| bait.config.account.as_ref())
            .any(|account| {
                account
                    .home_directory
                    .as_deref()
                    .is_some_and(|home| !home.starts_with("/home/"))
            })
        {
            return Err(ConfigError::Invalid(
                "Linux account home directories must be under /home/",
            ));
        } else if self
            .baits
            .iter()
            .filter_map(|bait| bait.path.as_deref())
            .any(|path| path.starts_with("/C/"))
        {
            return Err(ConfigError::Invalid(
                "Windows bait paths require a Windows Middle profile",
            ));
        }
        hf_core::validate_virtual_processes(&self.virtual_processes)
            .map_err(ConfigError::Invalid)?;
        if self.ssh_credentials.len() > 32 {
            return Err(ConfigError::Invalid(
                "SSH authentication allows at most 32 credential pairs",
            ));
        }
        if self.ssh_auth_mode == SshAuthMode::Realistic {
            if self.ssh_credentials.is_empty() {
                return Err(ConfigError::Invalid(
                    "realistic SSH authentication requires at least one credential pair",
                ));
            }
            let mut unique_ssh_usernames = BTreeSet::new();
            for credential in &self.ssh_credentials {
                let username = credential.username.as_str();
                let valid_username = username.len() <= 32
                    && username
                        .as_bytes()
                        .first()
                        .is_some_and(|byte| byte.is_ascii_lowercase() || *byte == b'_')
                    && username.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'_' | b'-')
                    });
                if !valid_username
                    || credential.password.trim().is_empty()
                    || credential.password.len() > 128
                    || credential.password.chars().any(char::is_control)
                    || !unique_ssh_usernames.insert(username.to_ascii_lowercase())
                {
                    return Err(ConfigError::Invalid(
                        "SSH credential usernames must be unique",
                    ));
                }
            }
            if !unique_ssh_usernames.contains(self.username.as_str()) {
                return Err(ConfigError::Invalid(
                    "realistic SSH credentials must include the virtual username",
                ));
            }
        }
        let expected_listeners: BTreeSet<_> = hf_core::pritvoryashka_service_endpoints_for_os(
            &self.vulnerability_profiles,
            self.distribution == Distribution::Windows,
        )
        .map_err(ConfigError::Invalid)?
        .into_iter()
        .map(|endpoint| (endpoint.service_type.to_owned(), endpoint.container_port))
        .collect();
        let actual: BTreeSet<_> = self
            .network_listeners
            .iter()
            .map(|listener| {
                if !listener.bind.ip().is_unspecified() && !listener.bind.ip().is_loopback() {
                    return Err(ConfigError::Invalid(
                        "network listeners must bind to the container or loopback interface",
                    ));
                }
                Ok((listener.service_type.clone(), listener.bind.port()))
            })
            .collect::<Result<_, _>>()?;
        if actual.len() != self.network_listeners.len() || actual != expected_listeners {
            return Err(ConfigError::Invalid(
                "network listeners do not match vulnerability profiles",
            ));
        }
        let public_ports: Vec<_> = self
            .network_listeners
            .iter()
            .map(|listener| {
                listener.public_port.ok_or(ConfigError::Invalid(
                    "every network listener requires a public TCP port",
                ))
            })
            .collect::<Result<_, _>>()?;
        if public_ports.contains(&0)
            || public_ports.iter().copied().collect::<BTreeSet<_>>().len() != public_ports.len()
            || self
                .ssh_public_port
                .is_some_and(|port| public_ports.contains(&port))
        {
            return Err(ConfigError::Invalid(
                "public SSH and service ports must be unique and nonzero",
            ));
        }
        if self.network_listeners.iter().any(|listener| {
            if listener.service_type == "ftp_data" {
                listener.public_port.is_none_or(|port| port == 0)
            } else {
                false
            }
        }) {
            return Err(ConfigError::Invalid(
                "FTP passive listener requires a public TCP port",
            ));
        }
        let now = Utc::now();
        let mut fs = if self.distribution == Distribution::Windows {
            crate::filesystem::VirtualFileSystem::windows(&self.hostname, &self.username, now)
        } else {
            crate::filesystem::VirtualFileSystem::linux_with_profile(
                &self.hostname,
                &self.username,
                self.distribution,
                now,
            )
        };
        if self.distribution != Distribution::Windows {
            let _virtual_server = crate::shell::model::VirtualServer::new_with_processes(
                &mut fs,
                now,
                &self.virtual_processes,
            );
        }
        for bait in &self.baits {
            if let Some(path) = bait.path.as_deref() {
                fs.install_bait(bait, path, now).map_err(|_| {
                    ConfigError::Invalid("bait file cannot be placed in the virtual filesystem")
                })?;
            }
        }
        if !(1..=10_000).contains(&self.max_connections)
            || !(1..=20).contains(&self.auth.max_attempts)
            || !(30..=86_400).contains(&self.idle_timeout_seconds)
            || !(256..=65_536).contains(&self.max_input_bytes)
            || !(1..=100_000).contains(&self.telemetry.queue_capacity)
            || !(1..=1000).contains(&self.telemetry.batch_size)
            || !(100..=60_000).contains(&self.telemetry.flush_interval_ms)
            || !(1024..=1_048_576).contains(&self.telemetry.max_event_bytes)
        {
            return Err(ConfigError::Invalid(
                "one or more limits are outside supported ranges",
            ));
        }
        if self.auth.policy == AuthPolicy::Configured
            && (self.auth.username.as_deref().is_none_or(str::is_empty)
                || self.auth.password_env.as_deref().is_none_or(str::is_empty))
        {
            return Err(ConfigError::Invalid(
                "configured authentication requires username and password_env",
            ));
        }
        if self.telemetry.endpoint.is_some()
            && self
                .telemetry
                .token_env
                .as_deref()
                .is_none_or(str::is_empty)
        {
            return Err(ConfigError::Invalid(
                "telemetry endpoint requires token_env",
            ));
        }
        if self.telemetry.endpoint.is_none() && self.telemetry.jsonl_path.is_none() {
            return Err(ConfigError::Invalid(
                "at least one telemetry sink must be configured",
            ));
        }
        if let Some(endpoint) = &self.telemetry.endpoint {
            let url = reqwest::Url::parse(endpoint)
                .map_err(|_| ConfigError::Invalid("telemetry endpoint is invalid"))?;
            let loopback = url.host_str().is_some_and(|host| {
                host == "localhost"
                    || host
                        .trim_matches(['[', ']'])
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            });
            if url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || url.path() != "/internal/v1/telemetry/batches"
                || (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
            {
                return Err(ConfigError::Invalid("telemetry endpoint is unsafe"));
            }
        }
        Ok(())
    }

    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_seconds)
    }
}

fn default_hostname() -> String {
    "srv-app-01".into()
}
fn default_max_connections() -> usize {
    128
}
fn default_idle_seconds() -> u64 {
    600
}
fn default_input_bytes() -> usize {
    8192
}

fn default_username() -> String {
    "admin".into()
}
