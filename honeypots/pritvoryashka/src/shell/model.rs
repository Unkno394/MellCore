use std::collections::BTreeMap;
use std::sync::OnceLock;

use chrono::{DateTime, Duration, Utc};
use hf_core::VirtualProcess;

use crate::{
    config::Distribution,
    filesystem::{FsError, VirtualFileSystem},
    shell::packages,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VirtualInteraction {
    pub bait: &'static str,
    pub action: String,
    pub target: Option<String>,
    pub success: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactAction {
    pub modified: bool,
    pub operation: &'static str,
    pub path: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VirtualCommand {
    pub output: String,
    pub exit_status: u32,
    pub interaction: VirtualInteraction,
    pub artifacts: Vec<ArtifactAction>,
}

impl VirtualCommand {
    fn success(
        bait: &'static str,
        action: impl Into<String>,
        target: Option<String>,
        output: impl Into<String>,
    ) -> Self {
        Self {
            output: output.into(),
            exit_status: 0,
            interaction: VirtualInteraction {
                bait,
                action: action.into(),
                target,
                success: true,
            },
            artifacts: Vec::new(),
        }
    }

    fn failure(
        bait: &'static str,
        action: impl Into<String>,
        target: Option<String>,
        output: impl Into<String>,
    ) -> Self {
        Self {
            output: output.into(),
            exit_status: 1,
            interaction: VirtualInteraction {
                bait,
                action: action.into(),
                target,
                success: false,
            },
            artifacts: Vec::new(),
        }
    }

    fn accessed(mut self, operation: &'static str, path: impl Into<String>) -> Self {
        self.artifacts.push(ArtifactAction {
            modified: false,
            operation,
            path: path.into(),
        });
        self
    }

    fn modified(mut self, operation: &'static str, path: impl Into<String>) -> Self {
        self.artifacts.push(ArtifactAction {
            modified: true,
            operation,
            path: path.into(),
        });
        self
    }

    fn retag(
        mut self,
        bait: &'static str,
        action: impl Into<String>,
        target: Option<String>,
    ) -> Self {
        self.interaction.bait = bait;
        self.interaction.action = action.into();
        self.interaction.target = target;
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProcessState {
    Running,
    Sleeping,
    Stopped,
}

impl ProcessState {
    fn code(self) -> char {
        match self {
            Self::Running => 'R',
            Self::Sleeping => 'S',
            Self::Stopped => 'T',
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::Running => "R (running)",
            Self::Sleeping => "S (sleeping)",
            Self::Stopped => "T (stopped)",
        }
    }
}

fn process_command_name(command: &str) -> &str {
    let first = command.split_whitespace().next().unwrap_or(command);
    let first = first.trim_start_matches('-');
    if first == "nginx:" {
        return "nginx";
    }
    first
        .rsplit('/')
        .next()
        .unwrap_or(first)
        .trim_end_matches(':')
}

fn process_parent(pid: u32) -> u32 {
    match pid {
        1 => 0,
        2 => 0,
        1312 => 684,
        1224 => 901,
        1134 | 1188 => 1,
        30000..=30099 => 901,
        _ => 1,
    }
}

fn process_uid_gid(distribution: Distribution, user: &str) -> (u32, u32) {
    match (distribution, user) {
        (_, "root") => (0, 0),
        (Distribution::Arch, "dbus") => (81, 81),
        (Distribution::Arch, "systemd-resolve") => (975, 975),
        (Distribution::Arch, "http") => (33, 33),
        (Distribution::Arch, "sshd") => (50, 50),
        (Distribution::Arch, "postgres") => (967, 967),
        (Distribution::Arch, "valkey") => (971, 971),
        (_, "mysql") => (106, 112),
        (_, "messagebus") => (100, 104),
        (_, "syslog") => (101, 105),
        (_, "systemd-resolve") => (102, 102),
        (_, "systemd-timesync") => (103, 103),
        (_, "www-data") => (33, 33),
        (_, "postgres") => (114, 120),
        (_, "redis") => (117, 124),
        (_, "app") => (1001, 1001),
        (_, "admin") => (1000, 1000),
        (_, "daemon") => (1, 1),
        (_, "bin") => (2, 2),
        (_, "sys") => (3, 3),
        (_, "adm") => (4, 4),
        _ => (1000, 1000),
    }
}

fn process_cpu_time(pid: u32) -> String {
    let seconds = pid.wrapping_mul(37).wrapping_add(17) % 1_800 + 1;
    format!(
        "{:02}:{:02}:{:02}",
        seconds / 3_600,
        (seconds / 60) % 60,
        seconds % 60
    )
}

fn parse_ps_columns(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|column| !column.is_empty())
        .map(str::to_owned)
        .collect()
}

fn ps_column(
    column: &str,
    pid: u32,
    ppid: u32,
    user: &str,
    state: char,
    command: &str,
    rss: u32,
    distribution: Distribution,
) -> String {
    match column.trim_end_matches('=') {
        "pid" => pid.to_string(),
        "ppid" => ppid.to_string(),
        "user" | "uname" | "euser" => user.to_owned(),
        "uid" | "euid" => process_uid_gid(distribution, user).0.to_string(),
        "gid" | "egid" => process_uid_gid(distribution, user).1.to_string(),
        "stat" | "state" => state.to_string(),
        "comm" => command
            .split_whitespace()
            .next()
            .unwrap_or(command)
            .rsplit('/')
            .next()
            .unwrap_or(command)
            .to_owned(),
        "args" | "command" | "cmd" => command.to_owned(),
        "%cpu" | "pcpu" => "0.0".into(),
        "%mem" | "pmem" => format!("{:.1}", f64::from(rss) / 8_000.0),
        "rss" => rss.to_string(),
        "vsz" => rss.saturating_mul(4).to_string(),
        "tty" => {
            if pid == 1312 {
                "pts/0".into()
            } else {
                "?".into()
            }
        }
        "etime" => "17-00:12:00".into(),
        "time" | "cputime" => process_cpu_time(pid),
        "start" | "lstart" => "Oct12".into(),
        _ => "?".into(),
    }
}

#[derive(Clone, Debug)]
struct Process {
    pid: u32,
    user: &'static str,
    command: &'static str,
    state: ProcessState,
    rss_kib: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProcessSignal {
    Stop,
    Continue,
    Exit,
}

#[derive(Clone, Debug)]
struct Service {
    description: &'static str,
    pid: u32,
    port: Option<u16>,
    address: &'static str,
    active: bool,
    started_at: Option<DateTime<Utc>>,
    stopped_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
struct Container {
    id: &'static str,
    name: &'static str,
    image: &'static str,
    pid: Option<u32>,
    port: Option<u16>,
    running: bool,
    logs: &'static str,
}

#[derive(Clone, Debug)]
struct DbUser {
    id: u32,
    email: String,
    role: String,
}

#[derive(Clone, Debug)]
struct Backup {
    path: &'static str,
    entries: Vec<(&'static str, &'static str)>,
}

#[derive(Clone)]
pub struct VirtualServer {
    distribution: Distribution,
    vulnerability_profiles: std::collections::BTreeSet<String>,
    processes: BTreeMap<u32, Process>,
    virtual_processes: Vec<VirtualProcess>,
    services: BTreeMap<&'static str, Service>,
    containers: BTreeMap<&'static str, Container>,
    cron: Vec<String>,
    authorized_keys: Vec<String>,
    git_baseline: BTreeMap<&'static str, &'static str>,
    db_users: Vec<DbUser>,
    db_audit: Vec<String>,
    backups: Vec<Backup>,
    booted_at: DateTime<Utc>,
    username: String,
    home: String,
}

impl VirtualServer {
    pub fn new(fs: &mut VirtualFileSystem, now: DateTime<Utc>) -> Self {
        Self::new_with_processes(fs, now, &[])
    }

    pub fn new_with_processes(
        fs: &mut VirtualFileSystem,
        now: DateTime<Utc>,
        virtual_processes: &[VirtualProcess],
    ) -> Self {
        Self::new_with_identity(fs, now, virtual_processes, "admin")
    }

    pub fn new_with_identity(
        fs: &mut VirtualFileSystem,
        now: DateTime<Utc>,
        virtual_processes: &[VirtualProcess],
        username: &str,
    ) -> Self {
        static BOOTED_AT: OnceLock<DateTime<Utc>> = OnceLock::new();
        let booted_at = BOOTED_AT
            .get_or_init(|| now - Duration::days(17))
            .to_owned();
        // Existing persisted sessions may predate the Debian profile files.
        // Add missing release metadata without overwriting operator changes.
        if let Some(profile) = fs.distribution().linux_profile()
            && !profile.debian_version.is_empty()
            && !fs.exists("/etc/debian_version")
        {
            fs.put_file(
                "/etc/debian_version",
                format!("{}\n", profile.debian_version),
                now,
            );
        }
        let mut processes: BTreeMap<u32, Process> = [
            Process {
                pid: 1,
                user: "root",
                command: "/sbin/init",
                state: ProcessState::Sleeping,
                rss_kib: 11840,
            },
            Process {
                pid: 2,
                user: "root",
                command: "[kthreadd]",
                state: ProcessState::Sleeping,
                rss_kib: 0,
            },
            Process {
                pid: 362,
                user: "root",
                command: "/lib/systemd/systemd-journald",
                state: ProcessState::Sleeping,
                rss_kib: 8832,
            },
            Process {
                pid: 408,
                user: "root",
                command: "/lib/systemd/systemd-udevd",
                state: ProcessState::Sleeping,
                rss_kib: 6216,
            },
            Process {
                pid: 512,
                user: "systemd-resolve",
                command: "/lib/systemd/systemd-resolved",
                state: ProcessState::Sleeping,
                rss_kib: 7680,
            },
            Process {
                pid: 542,
                user: "messagebus",
                command: "/usr/bin/dbus-daemon --system",
                state: ProcessState::Sleeping,
                rss_kib: 4120,
            },
            Process {
                pid: 593,
                user: "root",
                command: "/usr/sbin/cron -f",
                state: ProcessState::Sleeping,
                rss_kib: 2632,
            },
            Process {
                pid: 772,
                user: "root",
                command: "/usr/bin/containerd",
                state: ProcessState::Sleeping,
                rss_kib: 40216,
            },
            Process {
                pid: 684,
                user: "root",
                command: "/usr/sbin/sshd -D",
                state: ProcessState::Sleeping,
                rss_kib: 9260,
            },
            Process {
                pid: 721,
                user: "postgres",
                command: "/usr/lib/postgresql/14/bin/postgres",
                state: ProcessState::Sleeping,
                rss_kib: 42100,
            },
            Process {
                pid: 1224,
                user: "redis",
                command: "redis-server *:6379",
                state: ProcessState::Sleeping,
                rss_kib: 13820,
            },
            Process {
                pid: 901,
                user: "root",
                command: "/usr/bin/dockerd -H fd://",
                state: ProcessState::Sleeping,
                rss_kib: 74600,
            },
            Process {
                pid: 1134,
                user: "app",
                command: "/app/billing-api --config /app/config.toml",
                state: ProcessState::Sleeping,
                rss_kib: 81320,
            },
            Process {
                pid: 1188,
                user: "app",
                command: "/app/billing-worker --queue invoices",
                state: ProcessState::Sleeping,
                rss_kib: 47640,
            },
            Process {
                pid: 1312,
                user: "admin",
                command: "-bash",
                state: ProcessState::Sleeping,
                rss_kib: 5360,
            },
        ]
        .into_iter()
        .map(|process| (process.pid, process))
        .collect();

        if let Some(profile) = fs.distribution().linux_profile() {
            for service in profile.services {
                if let Some(process) = processes.get_mut(&service.pid) {
                    process.user = service.user;
                    process.command = service.command;
                    process.rss_kib = service.rss_kib;
                }
            }
        }

        let services = fs
            .distribution()
            .linux_profile()
            .map(|profile| {
                profile
                    .services
                    .iter()
                    .map(|spec| {
                        (
                            spec.name,
                            Service {
                                description: spec.description,
                                pid: spec.pid,
                                port: spec.port,
                                address: spec.address,
                                active: true,
                                started_at: Some(booted_at + Duration::minutes(12)),
                                stopped_at: None,
                            },
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();

        let mut containers = BTreeMap::from([
            (
                "billing-api",
                Container {
                    id: "9d42ab41cd73",
                    name: "billing-api",
                    image: "registry.internal/billing-api:2.8.4",
                    pid: Some(1134),
                    port: Some(8080),
                    running: true,
                    logs: "2026-10-12T07:41:12Z INFO billing_api: listening on 0.0.0.0:8080\n2026-10-12T07:42:03Z INFO billing_api: health check passed\n",
                },
            ),
            (
                "billing-worker",
                Container {
                    id: "5a7c091efc20",
                    name: "billing-worker",
                    image: "registry.internal/billing-api:2.8.4",
                    pid: Some(1188),
                    port: None,
                    running: true,
                    logs: "2026-10-12T07:41:15Z INFO worker: connected to redis\n2026-10-12T07:42:01Z INFO worker: invoice queue idle\n",
                },
            ),
            (
                "redis",
                Container {
                    id: "a82f4c0d19e7",
                    name: "redis",
                    image: "redis:7.2-alpine",
                    pid: Some(1224),
                    port: None,
                    running: true,
                    logs: "1:C 27 Sep 2026 07:40:58.011 # Redis is starting\n1:M 27 Sep 2026 07:40:58.012 * Ready to accept connections\n",
                },
            ),
            (
                "payments-migrate",
                Container {
                    id: "c31277a9b813",
                    name: "payments-migrate",
                    image: "registry.internal/billing-api:2.8.4",
                    pid: None,
                    port: None,
                    running: false,
                    logs: "2026-10-12T07:40:51Z INFO migrate: schema is current\n",
                },
            ),
        ]);
        if fs.distribution() == Distribution::Arch
            && let Some(container) = containers.get_mut("redis")
        {
            container.image = "valkey/valkey:9.1-alpine";
            container.logs = "1:C 15 Oct 2026 07:40:58.011 # Valkey is starting\n1:M 15 Oct 2026 07:40:58.012 * Ready to accept connections\n";
        }

        let cron = vec![
            "17 2 * * * /usr/local/bin/companyctl backups create billing >> /var/log/backup.log 2>&1".into(),
            "*/5 * * * * /usr/local/bin/companyctl services health --quiet".into(),
        ];
        let authorized_keys = vec![
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDecoyDeployKeyMaterialOnly deploy@ci.internal"
                .into(),
        ];
        let git_baseline = BTreeMap::from([
            (
                "Cargo.toml",
                "[package]\nname = \"billing-api\"\nversion = \"2.8.4\"\nedition = \"2021\"\n\n[dependencies]\naxum = \"0.7\"\ntokio = { version = \"1\", features = [\"full\"] }\n",
            ),
            (
                "src/main.rs",
                "mod config;\nmod payments;\n\n#[tokio::main]\nasync fn main() {\n    billing_api::serve().await;\n}\n",
            ),
            (
                "config/production.toml",
                "listen = \"0.0.0.0:8080\"\nredis_url = \"redis://redis:6379/0\"\ndatabase_url = \"postgres://billing_app:decoy-db-pass@db-internal:5432/billing\"\n",
            ),
        ]);
        let db_users = vec![
            DbUser {
                id: 1,
                email: "alice@example.test".into(),
                role: "admin".into(),
            },
            DbUser {
                id: 2,
                email: "ops@example.test".into(),
                role: "operator".into(),
            },
            DbUser {
                id: 3,
                email: "demo@example.test".into(),
                role: "viewer".into(),
            },
        ];
        let backups = vec![
            Backup {
                path: "/var/backups/billing-2026-10-11.tar.gz",
                entries: vec![
                    (
                        "billing/.env",
                        "APP_ENV=production\nDATABASE_URL=postgres://billing_app:decoy-db-pass@db-internal:5432/billing\nREDIS_URL=redis://redis:6379/0\n",
                    ),
                    (
                        "billing/config/production.toml",
                        "listen = \"0.0.0.0:8080\"\nfeature_refunds = true\n",
                    ),
                    (
                        "billing/README.restore",
                        "Restore with companyctl backups restore billing-2026-10-11\n",
                    ),
                ],
            },
            Backup {
                path: "/var/backups/customers-2026-10-11.sql",
                entries: vec![(
                    "customers.sql",
                    "-- synthetic decoy dump\nINSERT INTO customers VALUES (1001, 'Acme Test LLC');\n",
                )],
            },
            Backup {
                path: "/var/backups/ops-config-2026-10-10.zip",
                entries: vec![
                    (
                        "ops/hosts.ini",
                        "[production]\napp-01 ansible_host=10.20.4.21\ndb-01 ansible_host=10.20.4.12\n",
                    ),
                    (
                        "ops/group_vars/vault.yml",
                        "vault_token: decoy-vault-token-7f91b2\n",
                    ),
                ],
            },
        ];

        let mut model = Self {
            distribution: fs.distribution(),
            vulnerability_profiles: std::collections::BTreeSet::new(),
            processes,
            virtual_processes: virtual_processes.to_vec(),
            services,
            containers,
            cron,
            authorized_keys,
            git_baseline,
            db_users,
            db_audit: vec!["deploy completed for billing-api:2.8.4".into()],
            backups,
            booted_at,
            username: username.to_owned(),
            home: format!("/home/{username}"),
        };
        model.sync_container_proxies(fs);
        model.seed_filesystem(fs, now);
        model
    }

    pub(crate) fn initialize_vulnerability_scenarios(
        profiles: &std::collections::BTreeSet<String>,
        fs: &mut VirtualFileSystem,
        now: DateTime<Utc>,
    ) {
        if profiles.contains("redis_unauthenticated_access") {
            if let Some(package) = packages::lookup("redis-server")
                && let Err(error) = packages::install(fs, package, now)
            {
                tracing::warn!(%error, "could not install virtual Redis package for selected scenario");
            }
            let profile = fs.distribution().linux_profile();
            let config_path = profile.map_or("/etc/redis/redis.conf", |p| p.redis_config_file);
            let pid_path = profile.map_or("/run/redis-server.pid", |p| p.redis_pid_file);
            let cli_path = profile.map_or("/usr/bin/redis-cli", |p| p.redis_cli_executable);
            let data_dir = profile.map_or("/var/lib/redis", |p| p.redis_data_dir);
            ensure_dir(fs, data_dir, now);
            let _ = fs.put_file(
                config_path,
                "bind 0.0.0.0\nprotected-mode no\nport 6379\n",
                now,
            );
            let _ = fs.put_file(
                cli_path,
                "ELF virtual Redis-compatible command-line client\n",
                now,
            );
            if let Ok(node) = fs.node_mut(cli_path) {
                node.permissions = crate::filesystem::permissions::Permissions(0o755);
            }
            let _ = fs.put_file(pid_path, "2101\n", now);
            let store_path =
                profile.map_or("/var/lib/redis/virtual-store.json", |p| p.redis_store_file);
            if !fs.exists(store_path) {
                let _ = fs.put_file(
                    store_path,
                    r#"{"service:mode":"production","app:environment":"production","cache:health":"ok"}"#,
                    now,
                );
            }
        }

        if profiles.iter().any(|profile| {
            matches!(
                profile.as_str(),
                "http_admin_panel_exposure" | "web_path_traversal" | "web_command_injection"
            )
        }) && let Some(package) = packages::lookup("curl")
            && let Err(error) = packages::install(fs, package, now)
        {
            tracing::warn!(%error, "could not install virtual curl client for selected HTTP scenario");
        }

        let unit_dir = fs
            .distribution()
            .linux_profile()
            .map_or("/etc/systemd/system", |profile| profile.systemd_unit_dir);
        if profiles.contains("docker_api_exposed") {
            let _ = fs.put_file(
                &format!("{unit_dir}/docker.service"),
                "[Unit]\nDescription=Docker Application Container Engine\n[Service]\nExecStart=/usr/bin/dockerd -H fd:// -H tcp://0.0.0.0:2375\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n",
                now,
            );
        }

        if profiles.contains("sql_database_weak_credentials") {
            if let Some(package) = packages::lookup("mysql-server")
                && let Err(error) = packages::install(fs, package, now)
            {
                tracing::warn!(%error, "could not install virtual MySQL package for selected scenario");
            }
            ensure_dir(fs, "/var/lib/mysql", now);
            let passwd =
                String::from_utf8_lossy(fs.read("/etc/passwd").unwrap_or_default()).into_owned();
            if !passwd.lines().any(|line| line.starts_with("mysql:")) {
                fs.put_file(
                    "/etc/passwd",
                    format!(
                        "{passwd}mysql:x:106:112:MySQL Server:/nonexistent:/usr/sbin/nologin\n"
                    ),
                    now,
                );
            }
            let group =
                String::from_utf8_lossy(fs.read("/etc/group").unwrap_or_default()).into_owned();
            if !group.lines().any(|line| line.starts_with("mysql:")) {
                fs.put_file("/etc/group", format!("{group}mysql:x:112:\n"), now);
            }
            ensure_dir(fs, unit_dir, now);
            let profile = fs.distribution().linux_profile();
            let mysql_unit_name = profile.map_or("mysql", |profile| profile.mysql_service);
            let mysql_exec = profile.map_or(
                "/usr/sbin/mysqld --defaults-file=/etc/mysql/mysql.conf.d/mysqld.cnf",
                |profile| profile.mysql_command,
            );
            let _ = fs.put_file(
                &format!("{unit_dir}/{mysql_unit_name}.service"),
                format!("[Unit]\nDescription=MySQL compatible database server\nAfter=network.target\n[Service]\nExecStart={mysql_exec}\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n"),
                now,
            );
            let _ = fs.put_file(
                &format!("{unit_dir}/postgresql-public.service"),
                format!("[Unit]\nDescription=PostgreSQL virtual weak-credential listener\nAfter=network.target\n[Service]\nExecStart={}\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n", profile.map_or("/usr/lib/postgresql/14/bin/postgres", |profile| profile.postgres_command)),
                now,
            );
        }

        if profiles.contains("ftp_anonymous_login") {
            ensure_executable(fs, "/usr/sbin/vsftpd", now);
            ensure_executable(fs, "/usr/bin/ftp", now);
            let unit_dir = fs
                .distribution()
                .linux_profile()
                .map_or("/etc/systemd/system", |profile| profile.systemd_unit_dir);
            ensure_dir(fs, unit_dir, now);
            let _ = fs.put_file(
                &format!("{unit_dir}/vsftpd.service"),
                "[Unit]\nDescription=vsftpd FTP server\nAfter=network.target\n[Service]\nExecStart=/usr/sbin/vsftpd /etc/vsftpd.conf\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n",
                now,
            );
            let _ = fs.put_file(
                &format!("{unit_dir}/vsftpd-data.service"),
                "[Unit]\nDescription=vsftpd passive data listener\nAfter=network.target\n[Service]\nExecStart=/usr/sbin/vsftpd /etc/vsftpd.conf\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n",
                now,
            );
            let _ = fs.put_file(
                "/etc/vsftpd.conf",
                "listen=YES\nlisten_port=2121\nanonymous_enable=YES\nlocal_enable=YES\nwrite_enable=YES\npasv_min_port=2021\npasv_max_port=2021\n",
                now,
            );
        }
    }

    pub(crate) fn sync_vulnerability_scenarios(
        &mut self,
        profiles: &std::collections::BTreeSet<String>,
        fs: &mut VirtualFileSystem,
        now: DateTime<Utc>,
    ) {
        self.vulnerability_profiles.clone_from(profiles);
        let http_enabled = profiles.iter().any(|profile| {
            matches!(
                profile.as_str(),
                "http_admin_panel_exposure" | "web_path_traversal" | "web_command_injection"
            )
        });
        if !http_enabled {
            self.services.remove("billing-api-http");
        }
        if !profiles.contains("sql_database_weak_credentials") {
            for name in ["mysql", "mariadb", "postgresql-public"] {
                self.services.remove(name);
            }
            self.processes.remove(&2202);
        }
        if !profiles.contains("ftp_anonymous_login") {
            self.services.remove("vsftpd");
            self.services.remove("vsftpd-data");
            self.processes.remove(&2203);
        }

        if profiles.contains("docker_api_exposed") {
            if let Some(service) = self.services.get_mut("docker") {
                service.port = Some(2375);
                service.address = "0.0.0.0";
            }
            if let Some(process) = self.processes.get_mut(&901) {
                process.command = "/usr/bin/dockerd -H fd:// -H tcp://0.0.0.0:2375";
            }
        } else if let Some(service) = self.services.get_mut("docker") {
            service.port = None;
            service.address = "";
            if let Some(process) = self.processes.get_mut(&901) {
                process.command = "/usr/bin/dockerd -H fd://";
            }
        }

        if profiles.contains("redis_unauthenticated_access") {
            let service_name = self
                .distribution
                .linux_profile()
                .map_or("redis-server", |profile| profile.redis_service_name);
            if let Some(service) = self.services.get_mut(service_name) {
                service.address = "0.0.0.0";
            }
        }

        if http_enabled {
            self.services.entry("billing-api-http").or_insert(Service {
                description: "MellCore virtual vulnerable HTTP application",
                pid: 1134,
                port: Some(8080),
                address: "0.0.0.0",
                active: true,
                started_at: Some(self.booted_at + Duration::minutes(12)),
                stopped_at: None,
            });
        }

        if profiles.contains("sql_database_weak_credentials") {
            let profile = self.distribution.linux_profile();
            let mysql_service_name = profile.map_or("mysql", |profile| profile.mysql_service);
            self.services.entry(mysql_service_name).or_insert(Service {
                description: "MySQL compatible virtual database",
                pid: 2202,
                port: Some(13306),
                address: "0.0.0.0",
                active: true,
                started_at: Some(self.booted_at + Duration::minutes(12)),
                stopped_at: None,
            });
            if self
                .services
                .get(mysql_service_name)
                .is_some_and(|service| service.active)
            {
                self.processes.entry(2202).or_insert(Process {
                    pid: 2202,
                    user: "mysql",
                    command: profile.map_or("/usr/sbin/mysqld --port=13306", |profile| {
                        profile.mysql_command
                    }),
                    state: ProcessState::Sleeping,
                    rss_kib: 32100,
                });
            } else {
                self.processes.remove(&2202);
            }
            self.services.entry("postgresql-public").or_insert(Service {
                description: "PostgreSQL virtual weak-credential endpoint",
                pid: 721,
                port: Some(15432),
                address: "0.0.0.0",
                active: true,
                started_at: Some(self.booted_at + Duration::minutes(12)),
                stopped_at: None,
            });
        }

        if profiles.contains("ftp_anonymous_login") {
            self.services.entry("vsftpd").or_insert(Service {
                description: "vsftpd anonymous FTP control listener",
                pid: 2203,
                port: Some(2121),
                address: "0.0.0.0",
                active: true,
                started_at: Some(self.booted_at + Duration::minutes(12)),
                stopped_at: None,
            });
            self.services.entry("vsftpd-data").or_insert(Service {
                description: "vsftpd passive data listener",
                pid: 2203,
                port: Some(2021),
                address: "0.0.0.0",
                active: true,
                started_at: Some(self.booted_at + Duration::minutes(12)),
                stopped_at: None,
            });
            if self
                .services
                .get("vsftpd")
                .is_some_and(|service| service.active)
            {
                self.processes.entry(2203).or_insert(Process {
                    pid: 2203,
                    user: "root",
                    command: "/usr/sbin/vsftpd /etc/vsftpd.conf",
                    state: ProcessState::Sleeping,
                    rss_kib: 5120,
                });
            } else {
                self.processes.remove(&2203);
            }
        }

        self.sync_proc(fs, now);
    }

    pub fn booted_at(&self) -> DateTime<Utc> {
        self.booted_at.to_owned()
    }

    pub fn initial_history() -> Vec<String> {
        [
            "systemctl status billing-api",
            "docker compose -f /srv/billing-api/compose.yml ps",
            "psql -h db-internal -U billing_ro -d billing -c 'select count(*) from users;'",
            "tar -tzf /var/backups/billing-2026-10-11.tar.gz",
            "cd /srv/billing-api",
            "git log --oneline -5",
            "companyctl services list",
            "cat /srv/billing-api/.env",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    pub fn sync_history(&self, fs: &mut VirtualFileSystem, history: &[String], now: DateTime<Utc>) {
        fs.put_file(
            &format!("{}/.bash_history", self.home),
            format!("{}\n", history.join("\n")),
            now,
        );
        if let Ok(node) = fs.node_mut(&format!("{}/.bash_history", self.home)) {
            node.permissions = crate::filesystem::permissions::Permissions(0o600);
        }
    }

    pub fn refresh_packages(&mut self, fs: &mut VirtualFileSystem, now: DateTime<Utc>) {
        let Some(profile) = fs.distribution().linux_profile() else {
            self.sync_proc(fs, now);
            return;
        };

        // Core service availability is derived from profile metadata and the
        // same virtual executable files inspected by `which` and `ls`.
        for definition in profile.services {
            let executable = definition
                .command
                .split_whitespace()
                .next()
                .filter(|path| path.starts_with('/'));
            let mut available = executable.is_some_and(|path| fs.exists(path));
            if definition.name.starts_with("postgresql") {
                available &= packages::installed(fs, "postgresql") && fs.exists("/usr/bin/psql");
            }
            if !available {
                if let Some(service) = self.services.remove(definition.name) {
                    self.processes.remove(&service.pid);
                }
                self.processes.remove(&definition.pid);
            } else {
                self.services
                    .entry(definition.name)
                    .or_insert_with(|| Service {
                        description: definition.description,
                        pid: definition.pid,
                        port: definition.port,
                        address: definition.address,
                        active: false,
                        started_at: None,
                        stopped_at: Some(now),
                    });
            }
        }

        let nginx_bin = profile.nginx_executable;
        if fs.exists(nginx_bin)
            && let Ok(node) = fs.node_mut(nginx_bin)
        {
            node.reported_size = Some(1_217_920);
        }
        if !fs.exists(nginx_bin) {
            if let Some(service) = self.services.remove("nginx") {
                self.processes.remove(&service.pid);
                self.processes.remove(&(service.pid + 1));
                self.processes.remove(&(service.pid + 2));
            }
        }
        let key_value_bin = profile.redis_command.unwrap_or("/usr/bin/redis-server");
        let key_value_service = profile.redis_service_name;
        if fs.exists(key_value_bin) {
            let pid_path = profile.redis_pid_file;
            let active = fs.exists(pid_path);
            let pid = fs
                .read(pid_path)
                .ok()
                .and_then(|value| String::from_utf8_lossy(value).trim().parse::<u32>().ok())
                .unwrap_or(2101);
            let existing = self.services.get(key_value_service).cloned();
            self.services.insert(
                key_value_service,
                Service {
                    description: profile.redis_description,
                    pid,
                    port: Some(6379),
                    address: "127.0.0.1",
                    active,
                    started_at: active.then(|| {
                        existing
                            .as_ref()
                            .and_then(|service| service.started_at.clone())
                            .unwrap_or(now)
                    }),
                    stopped_at: (!active).then(|| {
                        existing
                            .as_ref()
                            .and_then(|service| service.stopped_at.clone())
                            .unwrap_or(now)
                    }),
                },
            );
            if active {
                self.processes.insert(
                    pid,
                    Process {
                        pid,
                        user: profile.redis_user,
                        command: service_command_for_profile(Some(profile), key_value_service),
                        state: ProcessState::Sleeping,
                        rss_kib: 13820,
                    },
                );
            } else if let Some(existing) = existing {
                self.processes.remove(&existing.pid);
            }
        } else {
            if let Some(service) = self.services.remove(key_value_service) {
                self.processes.remove(&service.pid);
            }
        }
        if fs.exists(nginx_bin) {
            let active = fs.exists("/run/nginx.pid");
            let pid = fs
                .read("/run/nginx.pid")
                .ok()
                .and_then(|value| String::from_utf8_lossy(value).trim().parse::<u32>().ok())
                .unwrap_or(2100);
            let existing = self.services.get("nginx").cloned();
            self.services.insert(
                "nginx",
                Service {
                    description: "A high performance web server and a reverse proxy server",
                    pid,
                    port: Some(80),
                    address: "0.0.0.0",
                    active,
                    started_at: active.then(|| {
                        existing
                            .as_ref()
                            .and_then(|service| service.started_at.clone())
                            .unwrap_or(now)
                    }),
                    stopped_at: (!active).then(|| {
                        existing
                            .as_ref()
                            .and_then(|service| service.stopped_at.clone())
                            .unwrap_or(now)
                    }),
                },
            );
            if active {
                let worker = profile.nginx_worker_user;
                self.processes.insert(
                    pid,
                    Process {
                        pid,
                        user: "root",
                        command: profile.nginx_master_command,
                        state: ProcessState::Sleeping,
                        rss_kib: 4152,
                    },
                );
                self.processes.insert(
                    pid + 1,
                    Process {
                        pid: pid + 1,
                        user: worker,
                        command: "nginx: worker process",
                        state: ProcessState::Sleeping,
                        rss_kib: 2160,
                    },
                );
                self.processes.insert(
                    pid + 2,
                    Process {
                        pid: pid + 2,
                        user: worker,
                        command: "nginx: worker process",
                        state: ProcessState::Sleeping,
                        rss_kib: 2184,
                    },
                );
            }
        }
        self.sync_proc(fs, now);
    }

    pub fn execute(
        &mut self,
        command: &str,
        args: &[String],
        cwd: &str,
        fs: &mut VirtualFileSystem,
        now: DateTime<Utc>,
    ) -> Option<VirtualCommand> {
        let result = match command {
            "ps" => self.ps(args),
            "pgrep" => self.pgrep(args),
            "pidof" => self.pidof(args),
            "top" => self.top(now),
            "kill" => self.kill(args, fs, now),
            "ip" => self.ip(args),
            "ss" => self.sockets("ss", args),
            "netstat" => self.sockets("netstat", args),
            "crontab" => self.crontab(args, cwd, fs, now),
            "systemctl" => self.systemctl(args, fs, now),
            "authorized_keys" => self.authorized_keys(args, fs, now),
            "docker" => self.docker(args, fs, now),
            "docker-compose" => self.docker_compose(args, fs, now),
            "git" => self.git(args, cwd, fs),
            "psql" => self.psql(args),
            "tar" => self.archive("tar", args, cwd, fs, now),
            "unzip" => self.archive("unzip", args, cwd, fs, now),
            "zipinfo" => self.archive("zipinfo", args, cwd, fs, now),
            "companyctl" => self.companyctl(args, cwd, fs, now),
            _ => return None,
        };
        Some(result)
    }

    fn seed_filesystem(&self, fs: &mut VirtualFileSystem, now: DateTime<Utc>) {
        for path in [
            "/proc",
            "/srv",
            "/srv/billing-api",
            "/srv/billing-api/src",
            "/srv/billing-api/config",
            &format!("{}/.ssh", self.home),
            "/root/.ssh",
            "/root/.aws",
            "/etc/billing",
            "/etc/systemd",
            "/etc/systemd/system",
            "/var/lib",
            "/var/lib/docker",
            "/var/lib/docker/volumes",
            "/usr/bin",
            "/opt",
            "/opt/companyctl",
        ] {
            ensure_dir(fs, path, now);
        }
        match fs.distribution() {
            Distribution::Ubuntu => {
                ensure_dir(fs, "/var/lib/dpkg", now);
                let mut status = fs.read("/var/lib/dpkg/status").unwrap_or_default().to_vec();
                if !String::from_utf8_lossy(&status)
                    .lines()
                    .any(|line| line == "Package: postgresql")
                {
                    status.extend_from_slice(b"Package: postgresql\nStatus: install ok installed\nVersion: 14+238\nArchitecture: amd64\nDescription: object-relational SQL database\n\n");
                    fs.put_file("/var/lib/dpkg/status", status, now);
                }
                fs.put_file("/usr/bin/psql", "ELF virtual PostgreSQL client\n", now);
                if let Ok(node) = fs.node_mut("/usr/bin/psql") {
                    node.permissions = crate::filesystem::permissions::Permissions(0o755);
                }
            }
            Distribution::Debian => {
                ensure_dir(fs, "/var/lib/dpkg", now);
                if !fs.exists("/var/lib/dpkg/status") {
                    fs.put_file("/var/lib/dpkg/status", "", now);
                }
            }
            Distribution::Arch => {
                ensure_dir(fs, "/var/lib/pacman/local", now);
            }
            Distribution::Windows => {}
        }
        for path in [
            "/srv/billing-api",
            "/srv/billing-api/src",
            "/srv/billing-api/config",
        ] {
            if let Ok(node) = fs.node_mut(path) {
                node.owner = self.username.clone();
            }
        }
        fs.put_file("/srv/billing-api/.env", "APP_ENV=production\nDATABASE_URL=postgres://billing_app:decoy-db-pass@db-internal:5432/billing\nREDIS_URL=redis://redis:6379/0\nJWT_SIGNING_KEY=decoy-jwt-signing-key-never-valid\n", now);
        fs.put_file("/srv/billing-api/.env.production", "SENTRY_DSN=https://decoy-public-key@errors.internal/42\nPAYMENTS_TOKEN=hf_decoy_payments_01J9Z8F2\n", now);
        fs.put_file(&format!("{}/.ssh/id_deploy", self.home), "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA-DECOY-KEY-NOT-VALID-AAAA\n-----END OPENSSH PRIVATE KEY-----\n", now);
        fs.put_file(
            &format!("{}/.ssh/authorized_keys", self.home),
            format!("{}\n", self.authorized_keys.join("\n")),
            now,
        );
        if let Ok(node) = fs.node_mut(&format!("{}/.ssh/authorized_keys", self.home)) {
            node.permissions = crate::filesystem::permissions::Permissions(0o600);
        }
        if let Ok(node) = fs.node_mut(&format!("{}/.ssh", self.home)) {
            node.permissions = crate::filesystem::permissions::Permissions(0o700);
        }
        if let Ok(node) = fs.node_mut(&format!("{}/.ssh/id_deploy", self.home)) {
            node.permissions = crate::filesystem::permissions::Permissions(0o600);
        }
        if let Ok(node) = fs.node_mut(&format!("{}/.ssh/authorized_keys", self.home)) {
            node.permissions = crate::filesystem::permissions::Permissions(0o600);
        }
        fs.put_file(&format!("{}/.ssh/config", self.home), "Host db-internal\n    HostName 10.20.4.12\n    User deploy\n    IdentityFile ~/.ssh/id_deploy\n", now);
        fs.put_file("/root/.aws/credentials", "[production-readonly]\naws_access_key_id = AKIADECOY00000000000\naws_secret_access_key = decoySecretKeyMaterialNeverAccepted\n", now);
        fs.put_file("/etc/billing/config.toml", "environment = \"production\"\nregistry = \"registry.internal\"\nops_token = \"decoy-companyctl-token-4d18\"\n", now);
        for (name, service) in &self.services {
            let profile = fs.distribution().linux_profile();
            let service_profile = profile.and_then(|profile| profile.service(name));
            let exec_start = service_profile.map_or_else(
                || service_command_for_profile(profile, name),
                |definition| definition.command,
            );
            let unit_file = systemd_unit_file(fs.distribution(), name);
            if service_profile.is_some_and(|definition| definition.static_unit) {
                fs.put_file(
                    &unit_file,
                    format!("[Unit]\nDescription={}\nDocumentation=man:{}.service(8)\nDefaultDependencies=no\nBefore=sysinit.target\n\n[Service]\nExecStart={exec_start}\nRestart=always\n", service.description, name),
                    now,
                );
                continue;
            }
            fs.put_file(
                &unit_file,
                format!(
                    "[Unit]\nDescription={}\nAfter=network.target\n\n[Service]\nExecStart={exec_start}\nRestart=on-failure\n\n[Install]\nWantedBy=multi-user.target\n",
                    service.description,
                ),
                now,
            );
            if service.active {
                ensure_dir(fs, "/etc/systemd/system/multi-user.target.wants", now);
                fs.put_symlink(
                    &format!("/etc/systemd/system/multi-user.target.wants/{name}.service"),
                    &unit_file,
                    now,
                );
            }
        }
        if self.distribution == Distribution::Debian {
            let aggregate_unit = systemd_unit_file(self.distribution, "postgresql");
            fs.put_file(
                &aggregate_unit,
                "[Unit]\nDescription=PostgreSQL RDBMS\nAfter=network.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/true\nExecStop=/usr/bin/true\n\n[Install]\nWantedBy=multi-user.target\n",
                now,
            );
            let template_unit = systemd_unit_file(self.distribution, "postgresql@17-main");
            fs.put_file(
                &template_unit,
                "[Unit]\nDescription=PostgreSQL Cluster %i\nAfter=network.target\n\n[Service]\nType=forking\nUser=postgres\nExecStart=/usr/bin/pg_ctlcluster --skip-systemctl-redirect %i start\nExecStop=/usr/bin/pg_ctlcluster --skip-systemctl-redirect %i stop\nPIDFile=/run/postgresql/%i.pid\n\n[Install]\nWantedBy=multi-user.target\n",
                now,
            );
            if self.service_running("postgresql@17-main") {
                ensure_dir(fs, "/etc/systemd/system/multi-user.target.wants", now);
                fs.put_symlink(&systemd_enabled_link("postgresql"), &aggregate_unit, now);
            }
        }
        if let Some(profile) = fs.distribution().linux_profile() {
            let command = profile
                .cron_command
                .split_whitespace()
                .next()
                .unwrap_or("/usr/sbin/cron");
            ensure_executable(fs, command, now);
        }
        let redis_image = if self.distribution == Distribution::Arch {
            "valkey/valkey:9.1-alpine"
        } else {
            "redis:7.2-alpine"
        };
        fs.put_file(
            "/srv/billing-api/compose.yml",
            format!("services:\n  api:\n    container_name: billing-api\n    image: registry.internal/billing-api:2.8.4\n    ports: [\"8080:8080\"]\n    depends_on: [redis]\n  worker:\n    container_name: billing-worker\n    image: registry.internal/billing-api:2.8.4\n    depends_on: [redis]\n  redis:\n    container_name: redis\n    image: {redis_image}\n    restart: unless-stopped\n"),
            now,
        );
        fs.put_file("/srv/billing-api/.gitignore", "/target\n.env.local\n", now);
        for (relative, content) in &self.git_baseline {
            fs.put_file(&format!("/srv/billing-api/{relative}"), *content, now);
        }
        for backup in &self.backups {
            let manifest = backup
                .entries
                .iter()
                .map(|(path, _)| *path)
                .collect::<Vec<_>>()
                .join("\n");
            fs.put_file(
                backup.path,
                format!("PRITVORYASHKA VIRTUAL ARCHIVE\n{manifest}\n"),
                now,
            );
        }
        if fs.distribution() == Distribution::Arch {
            for path in [
                "/var/lib/postgres/data",
                "/var/lib/postgres/data/base",
                "/var/lib/postgres/data/global",
                "/var/lib/postgres/data/pg_wal",
                "/var/lib/postgres/data/pg_xact",
            ] {
                ensure_dir(fs, path, now);
                if let Ok(node) = fs.node_mut(path) {
                    node.owner = "postgres".into();
                    node.group = "postgres".into();
                    node.permissions = crate::filesystem::permissions::Permissions(0o700);
                }
            }
            fs.put_file("/var/lib/postgres/data/PG_VERSION", "18\n", now);
            fs.put_file(
                "/var/lib/postgres/data/global/pg_control",
                "virtual PostgreSQL 18 cluster control data\n",
                now,
            );
            for path in [
                "/var/lib/postgres/data/PG_VERSION",
                "/var/lib/postgres/data/global/pg_control",
            ] {
                if let Ok(node) = fs.node_mut(path) {
                    node.owner = "postgres".into();
                    node.group = "postgres".into();
                    node.permissions = crate::filesystem::permissions::Permissions(0o600);
                }
            }
            if let Err(error) = packages::seed_arch_base(fs, now) {
                tracing::warn!(%error, "could not seed Arch package database");
            }
            if let Some(service) = self.services.get("valkey")
                && self.service_running("valkey")
            {
                fs.put_file("/run/valkey.pid", format!("{}\n", service.pid), now);
            }
        }
        self.sync_cron(fs, now);
        self.sync_authorized_keys(fs, now);
        self.sync_proc(fs, now);
        packages::sync_dpkg_file_lists(fs, now);
    }

    fn pgrep(&self, args: &[String]) -> VirtualCommand {
        let exact = args.iter().any(|arg| arg == "-x" || arg == "--exact");
        let full_command = args.iter().any(|arg| arg == "-f" || arg == "--full");
        let show_command = args.iter().any(|arg| arg == "-a" || arg == "--list-full");
        let pattern = args.iter().enumerate().find_map(|(index, arg)| {
            if matches!(
                arg.as_str(),
                "-u" | "--euid" | "-U" | "--uid" | "-P" | "--parent"
            ) {
                None
            } else if arg.starts_with('-') {
                None
            } else if index > 0
                && matches!(
                    args[index - 1].as_str(),
                    "-u" | "--euid" | "-U" | "--uid" | "-P" | "--parent"
                )
            {
                None
            } else {
                Some(arg.as_str())
            }
        });
        let Some(pattern) = pattern else {
            return VirtualCommand::failure(
                "processes",
                "pgrep",
                None,
                "usage: pgrep [-aflx] pattern\n",
            );
        };
        let mut rows = self
            .processes
            .values()
            .map(|process| (process.pid, process.command))
            .chain(
                self.virtual_processes
                    .iter()
                    .enumerate()
                    .filter(|(_, process)| process.running)
                    .map(|(index, process)| (4000 + index as u32, process.command.as_str())),
            )
            .filter(|(_, command)| {
                let haystack = if full_command {
                    *command
                } else {
                    process_command_name(command)
                };
                if exact {
                    haystack == pattern
                } else {
                    haystack.contains(pattern)
                }
            })
            .collect::<Vec<_>>();
        rows.sort_by_key(|(pid, _)| *pid);
        let output = rows
            .into_iter()
            .map(|(pid, command)| {
                if show_command {
                    format!("{pid} {command}\n")
                } else {
                    format!("{pid}\n")
                }
            })
            .collect::<String>();
        if output.is_empty() {
            VirtualCommand::failure("processes", "pgrep", Some(pattern.into()), "")
        } else {
            VirtualCommand::success("processes", "pgrep", Some(pattern.into()), output)
        }
    }

    fn pidof(&self, args: &[String]) -> VirtualCommand {
        let single = args.iter().any(|arg| arg == "-s" || arg == "--single-shot");
        let names = args
            .iter()
            .filter(|arg| !arg.starts_with('-'))
            .map(|name| name.rsplit('/').next().unwrap_or(name.as_str()))
            .collect::<Vec<_>>();
        if names.is_empty() {
            return VirtualCommand::failure(
                "processes",
                "pidof",
                None,
                "pidof: missing program name\n",
            );
        }
        let mut pids = self
            .processes
            .values()
            .map(|process| (process.pid, process.command))
            .chain(
                self.virtual_processes
                    .iter()
                    .enumerate()
                    .filter(|(_, process)| process.running)
                    .map(|(index, process)| (4000 + index as u32, process.command.as_str())),
            )
            .filter(|(_, command)| names.contains(&process_command_name(command)))
            .map(|(pid, _)| pid)
            .collect::<Vec<_>>();
        pids.sort_unstable_by(|left, right| right.cmp(left));
        pids.dedup();
        if single {
            pids.truncate(1);
        }
        if pids.is_empty() {
            VirtualCommand::failure("processes", "pidof", Some(names.join(" ")), "")
        } else {
            VirtualCommand::success(
                "processes",
                "pidof",
                Some(names.join(" ")),
                format!(
                    "{}\n",
                    pids.iter()
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(" ")
                ),
            )
        }
    }

    fn ps(&self, args: &[String]) -> VirtualCommand {
        let mut all = false;
        let mut aux = false;
        let mut ef = false;
        let mut pid_filter = None::<std::collections::BTreeSet<u32>>;
        let mut columns = None::<Vec<String>>;
        let mut no_headers = false;
        let mut index = 0;
        while index < args.len() {
            let arg = args[index].as_str();
            match arg {
                "aux" | "-aux" => {
                    all = true;
                    aux = true;
                }
                "-ef" | "-eF" => {
                    all = true;
                    ef = true;
                }
                "-eo" => {
                    all = true;
                    index += 1;
                    let Some(value) = args.get(index) else {
                        return VirtualCommand::failure(
                            "processes",
                            "list",
                            None,
                            "ps: option requires an argument -- 'o'\n",
                        );
                    };
                    columns = Some(parse_ps_columns(value));
                }
                "-e" | "-A" | "--everyone" => all = true,
                "-f" => ef = true,
                "--no-headers" => no_headers = true,
                "-p" | "--pid" => {
                    index += 1;
                    let Some(value) = args.get(index) else {
                        return VirtualCommand::failure(
                            "processes",
                            "list",
                            None,
                            "ps: option requires an argument -- 'p'\n",
                        );
                    };
                    let parsed = value
                        .split(',')
                        .filter_map(|pid| pid.parse::<u32>().ok())
                        .collect::<std::collections::BTreeSet<_>>();
                    if parsed.is_empty() {
                        return VirtualCommand::failure(
                            "processes",
                            "list",
                            None,
                            "ps: invalid process id\n",
                        );
                    }
                    pid_filter = Some(parsed);
                    all = true;
                }
                "-o" | "--format" => {
                    index += 1;
                    let Some(value) = args.get(index) else {
                        return VirtualCommand::failure(
                            "processes",
                            "list",
                            None,
                            "ps: option requires an argument -- 'o'\n",
                        );
                    };
                    columns = Some(parse_ps_columns(value));
                }
                _ if arg.starts_with("--pid=") => {
                    let parsed = arg[6..]
                        .split(',')
                        .filter_map(|pid| pid.parse::<u32>().ok())
                        .collect::<std::collections::BTreeSet<_>>();
                    if parsed.is_empty() {
                        return VirtualCommand::failure(
                            "processes",
                            "list",
                            None,
                            "ps: invalid process id\n",
                        );
                    }
                    pid_filter = Some(parsed);
                    all = true;
                }
                _ if arg.starts_with("-eo") && arg.len() > 3 => {
                    all = true;
                    columns = Some(parse_ps_columns(&arg[3..]));
                }
                _ if arg.starts_with("-o") && arg.len() > 2 => {
                    columns = Some(parse_ps_columns(&arg[2..]))
                }
                _ if arg.starts_with('-') => {
                    return VirtualCommand::failure(
                        "processes",
                        "list",
                        None,
                        "error: unsupported ps option or argument\n",
                    );
                }
                _ => {
                    return VirtualCommand::failure(
                        "processes",
                        "list",
                        None,
                        "error: unsupported ps argument\n",
                    );
                }
            }
            index += 1;
        }
        let mut rows = Vec::<(u32, u32, String, char, String, u32)>::new();
        for process in self.processes.values() {
            let user = if process.pid == 1312 {
                self.username.as_str()
            } else {
                process.user
            };
            rows.push((
                process.pid,
                process_parent(process.pid),
                user.to_owned(),
                process.state.code(),
                process.command.to_owned(),
                process.rss_kib,
            ));
        }
        for (index, process) in self.virtual_processes.iter().enumerate() {
            let pid = 4000 + index as u32;
            rows.push((
                pid,
                1,
                process.user.clone(),
                if process.running { 'S' } else { 'T' },
                process.command.clone(),
                2048,
            ));
        }
        rows.retain(|(pid, _ppid, user, _state, _command, _rss)| {
            pid_filter.as_ref().is_none_or(|pids| pids.contains(pid))
                && (all || user == &self.username || *pid == 1312)
        });
        let mut output = String::new();
        if let Some(columns) = columns {
            if !no_headers && !columns.iter().all(|column| column.ends_with('=')) {
                output.push_str(
                    &columns
                        .iter()
                        .map(|column| column.trim_end_matches('=').to_ascii_uppercase())
                        .collect::<Vec<_>>()
                        .join(" "),
                );
                output.push('\n');
            }
            for (pid, ppid, user, state, command, rss) in rows {
                output.push_str(
                    &columns
                        .iter()
                        .map(|column| {
                            ps_column(
                                column,
                                pid,
                                ppid,
                                &user,
                                state,
                                &command,
                                rss,
                                self.distribution,
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" "),
                );
                output.push('\n');
            }
        } else if aux {
            if !no_headers {
                output.push_str(
                    "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n",
                );
            }
            for (pid, _ppid, user, state, command, rss) in rows {
                output.push_str(&format!("{user:<9} {pid:>5}  0.1  {:>3.1} {:>6} {:>5} ?        {state}    {}  {} {command}\n", f64::from(rss) / 8_000.0, rss.saturating_mul(4), rss, (self.booted_at + Duration::minutes(12)).format("%b%d"), process_cpu_time(pid)));
            }
        } else if ef {
            if !no_headers {
                output.push_str("UID          PID    PPID  C STIME TTY          TIME CMD\n");
            }
            for (pid, ppid, user, _state, command, _rss) in rows {
                output.push_str(&format!(
                    "{user:<12} {pid:>5} {ppid:>7}  0 {} ?        {} {command}\n",
                    (self.booted_at + Duration::minutes(12)).format("%b%d"),
                    process_cpu_time(pid)
                ));
            }
        } else {
            if !no_headers {
                output.push_str("  PID TTY          TIME CMD\n");
            }
            for (pid, _ppid, _user, _state, command, _rss) in rows {
                output.push_str(&format!(
                    "{pid:>5} pts/0    {} {}\n",
                    process_cpu_time(pid),
                    command.trim_start_matches('-')
                ));
            }
        }
        VirtualCommand::success("processes", "list", None, output)
    }

    fn top(&self, now: DateTime<Utc>) -> VirtualCommand {
        let running = self
            .processes
            .values()
            .filter(|p| p.state == ProcessState::Running)
            .count();
        let sleeping = self
            .processes
            .values()
            .filter(|p| p.state == ProcessState::Sleeping)
            .count();
        let stopped = self
            .processes
            .values()
            .filter(|p| p.state == ProcessState::Stopped)
            .count();
        let custom_running = self
            .virtual_processes
            .iter()
            .filter(|process| process.running)
            .count();
        let custom_stopped = self.virtual_processes.len() - custom_running;
        let mut output = format!(
            "top - {} up {},  1 user,  load average: 0.08, 0.04, 0.01\nTasks: {:>3} total, {:>3} running, {:>3} sleeping, {:>3} stopped, {:>3} zombie\n%Cpu(s):  1.0 us,  0.3 sy, 98.7 id\nMiB Mem :   3930.0 total,   1124.2 free,    842.1 used,   1963.7 buff/cache\n\n  PID USER      S    RES TIME+     COMMAND\n",
            now.format("%H:%M:%S"),
            format!("{} days", (now - self.booted_at).num_days().max(0)),
            self.processes.len() + self.virtual_processes.len(),
            running + custom_running,
            sleeping,
            stopped + custom_stopped,
            0
        );
        for process in self.processes.values() {
            output.push_str(&format!(
                "{:>5} {:<9} {} {:>6} {:>8} {}\n",
                process.pid,
                if process.pid == 1312 {
                    self.username.as_str()
                } else {
                    process.user
                },
                process.state.code(),
                process.rss_kib,
                process_cpu_time(process.pid),
                process.command
            ));
        }
        for (index, process) in self.virtual_processes.iter().enumerate() {
            output.push_str(&format!(
                "{:>5} {:<9} {} {:>6} {:>8} {}\n",
                4000 + index as u32,
                process.user,
                if process.running { 'S' } else { 'T' },
                2048,
                process_cpu_time(4000 + index as u32),
                process.command
            ));
        }
        VirtualCommand::success("processes", "monitor", None, output)
    }

    fn kill(
        &mut self,
        args: &[String],
        fs: &mut VirtualFileSystem,
        now: DateTime<Utc>,
    ) -> VirtualCommand {
        let Some(raw_pid) = args.last() else {
            return VirtualCommand::failure(
                "processes",
                "signal",
                None,
                "kill: usage: kill [-SIGNAL] pid\n",
            );
        };
        let Ok(pid) = raw_pid.parse::<u32>() else {
            return VirtualCommand::failure(
                "processes",
                "signal",
                Some(raw_pid.clone()),
                format!("kill: {raw_pid}: arguments must be process or job IDs\n"),
            );
        };
        if pid == 1 {
            return VirtualCommand::failure(
                "processes",
                "signal",
                Some(pid.to_string()),
                "kill: (1) - Operation not permitted\n",
            );
        }
        let signal = args
            .iter()
            .find(|arg| arg.starts_with('-'))
            .map(|arg| arg.trim_start_matches('-'))
            .unwrap_or("TERM")
            .to_ascii_uppercase();
        if pid >= 4000 {
            let index = (pid - 4000) as usize;
            let Some(process) = self.virtual_processes.get_mut(index) else {
                return VirtualCommand::failure(
                    "processes",
                    "signal",
                    Some(pid.to_string()),
                    format!("kill: ({pid}) - No such process\n"),
                );
            };
            match signal.as_str() {
                "STOP" | "19" => process.running = false,
                "CONT" | "18" => process.running = true,
                "TERM" | "15" | "KILL" | "9" | "INT" | "2" | "HUP" | "1" => process.running = false,
                _ => {
                    return VirtualCommand::failure(
                        "processes",
                        "signal",
                        Some(pid.to_string()),
                        format!("kill: {signal}: invalid signal specification\n"),
                    );
                }
            }
            self.sync_proc(fs, now);
            return VirtualCommand::success(
                "processes",
                format!("signal_{signal}"),
                Some(pid.to_string()),
                "",
            )
            .modified("signal", format!("/proc/{pid}"));
        }
        if !self.processes.contains_key(&pid) {
            return VirtualCommand::failure(
                "processes",
                "signal",
                Some(pid.to_string()),
                format!("kill: ({pid}) - No such process\n"),
            );
        }
        let effect = match signal.as_str() {
            "STOP" | "19" => ProcessSignal::Stop,
            "CONT" | "18" => ProcessSignal::Continue,
            "TERM" | "15" | "KILL" | "9" | "INT" | "2" | "HUP" | "1" => ProcessSignal::Exit,
            _ => {
                return VirtualCommand::failure(
                    "processes",
                    "signal",
                    Some(pid.to_string()),
                    format!("kill: {signal}: invalid signal specification\n"),
                );
            }
        };
        apply_process_signal(
            &mut self.processes,
            &mut self.services,
            &mut self.containers,
            pid,
            effect,
            now,
        );
        if effect == ProcessSignal::Exit {
            let _ = fs.remove(&format!("/proc/{pid}"), true);
        }
        self.sync_proc(fs, now);
        VirtualCommand::success(
            "processes",
            format!("signal_{signal}"),
            Some(pid.to_string()),
            "",
        )
        .modified("signal", format!("/proc/{pid}"))
    }

    fn ip(&self, args: &[String]) -> VirtualCommand {
        let subcommand = args.first().map(String::as_str).unwrap_or("address");
        let output = match subcommand {
            "a" | "addr" | "address" => {
                "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n    inet 10.20.4.21/24 brd 10.20.4.255 scope global eth0\n3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 state DOWN\n    inet 172.17.0.1/16 scope global docker0\n"
            }
            "r" | "route" => {
                "default via 10.20.4.1 dev eth0 proto dhcp src 10.20.4.21 metric 100\n10.20.4.0/24 dev eth0 proto kernel scope link src 10.20.4.21\n172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown\n"
            }
            "link" => {
                "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 state DOWN\n"
            }
            "neigh" | "neighbor" => {
                "10.20.4.1 dev eth0 lladdr 02:42:0a:14:04:01 REACHABLE\n172.17.0.1 dev docker0 lladdr 02:42:ac:11:00:01 STALE\n"
            }
            _ => {
                return VirtualCommand::failure(
                    "network",
                    "inspect",
                    Some(subcommand.into()),
                    format!("Object \"{subcommand}\" is unknown, try \"ip help\".\n"),
                );
            }
        };
        VirtualCommand::success("network", "inspect", Some(subcommand.into()), output)
    }

    fn sockets(&self, command: &str, args: &[String]) -> VirtualCommand {
        let show_process = args.iter().any(|arg| {
            arg == "--processes"
                || (arg.starts_with('-') && arg.chars().skip(1).any(|flag| flag == 'p'))
        });
        let listen_only = args
            .iter()
            .any(|arg| arg.starts_with('-') && arg.chars().skip(1).any(|flag| flag == 'l'));
        let mut rows = Vec::new();
        for (name, service) in &self.services {
            if service.active
                && let Some(port) = service.port
            {
                let owner = self
                    .processes
                    .get(&service.pid)
                    .map_or("root", |process| process.user);
                rows.push(("tcp", service.address, port, service.pid, *name, owner));
            }
        }
        for process in self
            .processes
            .values()
            .filter(|process| process.command.contains("redis-server"))
        {
            if !rows.iter().any(|(_, _, port, _, _, _)| *port == 6379) {
                rows.push((
                    "tcp",
                    if process.command.contains("127.0.0.1:6379") {
                        "127.0.0.1"
                    } else {
                        "0.0.0.0"
                    },
                    6379,
                    process.pid,
                    "redis-server",
                    process.user,
                ));
            }
        }
        for (index, container) in self.containers.values().enumerate() {
            if container.running
                && let Some(port) = container.port
            {
                if container.name == "redis"
                    || rows
                        .iter()
                        .any(|(_, _, existing_port, _, _, _)| *existing_port == port)
                {
                    continue;
                }
                rows.push((
                    "tcp",
                    "0.0.0.0",
                    port,
                    30000 + index as u32,
                    "docker-proxy",
                    "root",
                ));
            }
        }
        for (index, process) in self.virtual_processes.iter().enumerate() {
            if process.running
                && let Some(port) = process.listen_port
            {
                rows.push((
                    process.config.protocol.as_str(),
                    "0.0.0.0",
                    port,
                    4000 + index as u32,
                    process.name.as_str(),
                    process.user.as_str(),
                ));
            }
        }
        let output = if command == "ss" {
            let mut text = if show_process {
                "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
                    .to_owned()
            } else {
                "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n".to_owned()
            };
            for (protocol, address, port, pid, name, owner) in rows {
                let state = if protocol == "udp" {
                    "UNCONN"
                } else {
                    "LISTEN"
                };
                if show_process && (self.username == "root" || owner == self.username.as_str()) {
                    text.push_str(&format!("{protocol:<5} {state:<6} 0      128    {address}:{port:<5}     0.0.0.0:*    users:((\"{name}\",pid={pid},fd=3))\n"));
                } else {
                    text.push_str(&format!(
                        "{protocol:<5} {state:<6} 0      128    {address}:{port:<5}     0.0.0.0:*\n"
                    ));
                }
            }
            if !listen_only {
                if show_process && self.username == "root" {
                    text.push_str("tcp   ESTAB  0      0      10.20.4.21:22       203.0.113.42:51432 users:((\"sshd\",pid=684,fd=4))\n");
                } else {
                    text.push_str(
                        "tcp   ESTAB  0      0      10.20.4.21:22       203.0.113.42:51432\n",
                    );
                }
            }
            text
        } else {
            let mut text = if show_process {
                "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n".to_owned()
            } else {
                "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
                    .to_owned()
            };
            for (protocol, address, port, pid, name, owner) in rows {
                let state = if protocol == "udp" {
                    "UNCONN"
                } else {
                    "LISTEN"
                };
                if show_process && (self.username == "root" || owner == self.username.as_str()) {
                    text.push_str(&format!("{protocol:<10} 0      0 {address}:{port:<5}          0.0.0.0:*               {state:<11} {pid}/{name}\n"));
                } else {
                    text.push_str(&format!("{protocol:<10} 0      0 {address}:{port:<5}          0.0.0.0:*               {state}\n"));
                }
            }
            if !listen_only {
                if show_process && self.username == "root" {
                    text.push_str("tcp        0      0 10.20.4.21:22            203.0.113.42:51432       ESTABLISHED 684/sshd\n");
                } else {
                    text.push_str("tcp        0      0 10.20.4.21:22            203.0.113.42:51432       ESTABLISHED\n");
                }
            }
            text
        };
        VirtualCommand::success("network", "list_sockets", None, output)
    }

    fn crontab(
        &mut self,
        args: &[String],
        cwd: &str,
        fs: &mut VirtualFileSystem,
        now: DateTime<Utc>,
    ) -> VirtualCommand {
        match args {
            [flag] if flag == "-l" => VirtualCommand::success(
                "persistence",
                "cron_list",
                Some("admin".into()),
                format!("{}\n", self.cron.join("\n")),
            )
            .accessed("read", "/var/spool/cron/admin"),
            [flag] if flag == "-r" => {
                self.cron.clear();
                self.sync_cron(fs, now);
                VirtualCommand::success("persistence", "cron_remove_all", Some("admin".into()), "")
                    .modified("write", "/var/spool/cron/admin")
            }
            [subcommand, entry @ ..] if subcommand == "add" && !entry.is_empty() => {
                if self.cron.len() >= 64 {
                    return VirtualCommand::failure(
                        "persistence",
                        "cron_add",
                        None,
                        "crontab: too many entries\n",
                    );
                }
                self.cron.push(entry.join(" "));
                self.sync_cron(fs, now);
                VirtualCommand::success("persistence", "cron_add", Some(entry.join(" ")), "")
                    .modified("write", "/var/spool/cron/admin")
            }
            [subcommand, index] if subcommand == "remove" => {
                let Ok(index) = index.parse::<usize>() else {
                    return VirtualCommand::failure(
                        "persistence",
                        "cron_remove",
                        Some(index.clone()),
                        "crontab: invalid entry number\n",
                    );
                };
                if index == 0 || index > self.cron.len() {
                    return VirtualCommand::failure(
                        "persistence",
                        "cron_remove",
                        Some(index.to_string()),
                        "crontab: entry not found\n",
                    );
                }
                self.cron.remove(index - 1);
                self.sync_cron(fs, now);
                VirtualCommand::success("persistence", "cron_remove", Some(index.to_string()), "")
                    .modified("write", "/var/spool/cron/admin")
            }
            [file] if !file.starts_with('-') => {
                let path = match VirtualFileSystem::normalize(cwd, file) {
                    Ok(path) => path,
                    Err(error) => {
                        return virtual_fs_failure("persistence", "cron_install", file, error);
                    }
                };
                let data = match fs.read(&path) {
                    Ok(data) => String::from_utf8_lossy(data),
                    Err(error) => {
                        return virtual_fs_failure("persistence", "cron_install", file, error);
                    }
                };
                self.cron = data
                    .lines()
                    .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
                    .map(str::to_owned)
                    .take(64)
                    .collect();
                self.sync_cron(fs, now);
                VirtualCommand::success("persistence", "cron_install", Some(path.clone()), "")
                    .accessed("read", path)
                    .modified("write", "/var/spool/cron/admin")
            }
            [flag] if flag == "-e" => VirtualCommand::failure(
                "persistence",
                "cron_edit",
                Some("admin".into()),
                "crontab: interactive editor is unavailable; use 'crontab add <entry>' or 'crontab <file>'\n",
            ),
            _ => VirtualCommand::failure(
                "persistence",
                "cron",
                None,
                "usage: crontab [-l|-r] | crontab add <entry> | crontab remove <number> | crontab <file>\n",
            ),
        }
    }

    fn systemctl(
        &mut self,
        args: &[String],
        fs: &mut VirtualFileSystem,
        now: DateTime<Utc>,
    ) -> VirtualCommand {
        let Some(action) = args.first().map(String::as_str) else {
            return VirtualCommand::failure(
                "persistence",
                "systemctl",
                None,
                "systemctl: missing command\n",
            );
        };
        if action == "--version" {
            let Some(profile) = self.distribution.linux_profile() else {
                return VirtualCommand::failure(
                    "persistence",
                    "systemctl_version",
                    None,
                    "systemctl: command not found\n",
                );
            };
            return VirtualCommand::success(
                "persistence",
                "systemctl_version",
                None,
                format!(
                    "systemd {} ({})\n+PAM +AUDIT +SELINUX +APPARMOR +IMA +SMACK +SECCOMP +GCRYPT -GNUTLS +OPENSSL +ACL +BLKID +CURL +ELFUTILS +FIDO2 +IDN2 -IDN +IPTC +KMOD +LIBCRYPTSETUP +LIBFDISK +PCRE2 -PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD\n",
                    profile.systemd_version, profile.systemd_package_version,
                ),
            );
        }
        if action == "list-units" || action == "list-unit-files" {
            let requested_type = args
                .iter()
                .find_map(|arg| arg.strip_prefix("--type="))
                .or_else(|| {
                    args.windows(2)
                        .find(|pair| pair[0] == "--type")
                        .map(|pair| pair[1].as_str())
                });
            let wants_timer = requested_type == Some("timer");
            let wants_services = requested_type.is_none() || requested_type == Some("service");
            let mut output = if action == "list-unit-files" {
                "UNIT FILE                              STATE           PRESET\n".to_owned()
            } else {
                "UNIT                 LOAD   ACTIVE   SUB     DESCRIPTION\n".to_owned()
            };
            if wants_services {
                for (name, service) in &self.services {
                    let active = if self.service_running(name) {
                        "active   running"
                    } else {
                        "inactive dead   "
                    };
                    if action == "list-unit-files" {
                        let unit_name = *name;
                        let static_unit = self
                            .distribution
                            .linux_profile()
                            .and_then(|profile| profile.service(name))
                            .is_some_and(|profile| profile.static_unit);
                        let enabled = if static_unit {
                            "static"
                        } else if systemd_unit_enabled(fs, name) {
                            "enabled"
                        } else {
                            "disabled"
                        };
                        output.push_str(&format!(
                            "{unit_name}.service{:width$} {enabled:<15} enabled\n",
                            "",
                            width = 38_usize.saturating_sub(unit_name.len())
                        ));
                    } else {
                        output.push_str(&format!(
                            "{name}.service{:width$} loaded {active} {}\n",
                            "",
                            service.description,
                            width = 21_usize.saturating_sub(name.len())
                        ));
                    }
                }
                if self.distribution == Distribution::Debian {
                    let enabled = if systemd_unit_enabled(fs, "postgresql") {
                        "enabled"
                    } else {
                        "disabled"
                    };
                    if action == "list-unit-files" {
                        output.push_str(&format!(
                            "postgresql.service{:width$} {enabled:<15} enabled\n",
                            "",
                            width = 38_usize.saturating_sub("postgresql".len())
                        ));
                    } else {
                        let (active, state) = if self.service_running("postgresql") {
                            ("active", "exited")
                        } else {
                            ("inactive", "dead")
                        };
                        output.push_str(&format!(
                            "postgresql.service{:width$} loaded {active:<8} {state:<7} PostgreSQL RDBMS\n",
                            "",
                            width = 21_usize.saturating_sub("postgresql".len())
                        ));
                    }
                }
                for process in &self.virtual_processes {
                    let active = if process.running {
                        "active   running"
                    } else {
                        "inactive dead   "
                    };
                    if action == "list-unit-files" {
                        let enabled = if systemd_unit_enabled(fs, &process.name) {
                            "enabled"
                        } else {
                            "disabled"
                        };
                        output.push_str(&format!(
                            "{}.service{:width$} {enabled:<15} enabled\n",
                            process.name,
                            "",
                            width = 38_usize.saturating_sub(process.name.len())
                        ));
                    } else {
                        output.push_str(&format!(
                            "{}.service{:width$} loaded {active} User configured virtual process\n",
                            process.name,
                            "",
                            width = 21_usize.saturating_sub(process.name.len())
                        ));
                    }
                }
            }
            if wants_timer {
                output.push_str(if action == "list-unit-files" {
                    "billing-backup.timer                     enabled         enabled\n"
                } else {
                    "billing-backup.timer loaded active   waiting Daily billing backup\n"
                });
            }
            return VirtualCommand::success("persistence", "systemd_list", None, output);
        }
        let Some(raw_name) = args.get(1) else {
            return VirtualCommand::failure(
                "persistence",
                format!("systemd_{action}"),
                None,
                "systemctl: unit name required\n",
            );
        };
        let name = raw_name.trim_end_matches(".service");
        if self.distribution == Distribution::Debian && name == "postgresql" {
            let cluster_name = "postgresql@17-main";
            let active = self.service_running(cluster_name);
            let enabled = systemd_unit_enabled(fs, "postgresql");
            match action {
                "status" => {
                    let service = self.services.get(cluster_name);
                    let timestamp = if active {
                        service.and_then(|service| service.started_at.as_ref())
                    } else {
                        service.and_then(|service| service.stopped_at.as_ref())
                    }
                    .cloned()
                    .unwrap_or(self.booted_at + Duration::minutes(12));
                    let output = if active {
                        format!(
                            "● postgresql.service - PostgreSQL RDBMS\n     Loaded: loaded ({}/postgresql.service; {})\n     Active: active (exited) since {} UTC\n",
                            self.distribution
                                .linux_profile()
                                .map_or("/lib/systemd/system", |profile| profile.systemd_unit_dir),
                            if enabled { "enabled" } else { "disabled" },
                            timestamp.format("%a %Y-%m-%d %H:%M:%S")
                        )
                    } else {
                        format!(
                            "○ postgresql.service - PostgreSQL RDBMS\n     Loaded: loaded ({}/postgresql.service; {})\n     Active: inactive (dead) since {} UTC\n",
                            self.distribution
                                .linux_profile()
                                .map_or("/lib/systemd/system", |profile| profile.systemd_unit_dir),
                            if enabled { "enabled" } else { "disabled" },
                            timestamp.format("%a %Y-%m-%d %H:%M:%S")
                        )
                    };
                    let mut result = VirtualCommand::success(
                        "persistence",
                        "systemd_status",
                        Some(name.into()),
                        output,
                    );
                    if !active {
                        result.exit_status = 3;
                        result.interaction.success = false;
                    }
                    return result;
                }
                "is-active" => {
                    let mut result = VirtualCommand::success(
                        "persistence",
                        "systemd_is-active",
                        Some(name.into()),
                        format!("{}\n", if active { "active" } else { "inactive" }),
                    );
                    if !active {
                        result.exit_status = 3;
                        result.interaction.success = false;
                    }
                    return result;
                }
                "is-enabled" => {
                    let mut result = VirtualCommand::success(
                        "persistence",
                        "systemd_is-enabled",
                        Some(name.into()),
                        format!("{}\n", if enabled { "enabled" } else { "disabled" }),
                    );
                    if !enabled {
                        result.exit_status = 1;
                        result.interaction.success = false;
                    }
                    return result;
                }
                "enable" | "disable" => {
                    let enable = action == "enable";
                    set_systemd_unit_enabled(fs, self.distribution, name, enable, now);
                    return VirtualCommand::success(
                        "persistence",
                        format!("systemd_{action}"),
                        Some(name.into()),
                        "",
                    )
                    .modified("systemd", systemd_enabled_link(name));
                }
                "start" | "stop" | "restart" => {
                    let mut result = self.systemctl(
                        &[action.to_owned(), format!("{cluster_name}.service")],
                        fs,
                        now,
                    );
                    result.interaction.target = Some(name.into());
                    return result;
                }
                _ => {
                    return VirtualCommand::failure(
                        "persistence",
                        format!("systemd_{action}"),
                        Some(name.into()),
                        format!("Unknown command verb {action}.\n"),
                    );
                }
            }
        }
        if action == "is-enabled" {
            if !self.services.contains_key(name)
                && !self
                    .virtual_processes
                    .iter()
                    .any(|process| process.name == name)
                && !fs.exists(&systemd_unit_file(self.distribution, name))
            {
                return VirtualCommand::failure(
                    "persistence",
                    "systemd_is-enabled",
                    Some(name.into()),
                    format!("Unit {name}.service could not be found.\n"),
                );
            }
            let enabled = systemd_unit_enabled(fs, name);
            let mut result = VirtualCommand::success(
                "persistence",
                "systemd_is-enabled",
                Some(name.into()),
                format!("{}\n", if enabled { "enabled" } else { "disabled" }),
            );
            if !enabled {
                result.exit_status = 1;
                result.interaction.success = false;
            }
            return result;
        }
        if let Some(index) = self
            .virtual_processes
            .iter()
            .position(|process| process.name == name)
        {
            let pid = 4000 + index as u32;
            let process = &self.virtual_processes[index];
            if action == "is-active" {
                let active = process.running;
                let mut result = VirtualCommand::success(
                    "processes",
                    "systemd_is-active",
                    Some(name.into()),
                    format!("{}\n", if active { "active" } else { "inactive" }),
                );
                if !active {
                    result.exit_status = 3;
                    result.interaction.success = false;
                }
                return result;
            }
            let output = match action {
                "status" => format!(
                    "{} {}.service - User configured virtual process\n     Loaded: loaded (/etc/systemd/system/{}.service; {})\n     Active: {} ({}) since {} UTC\n   Main PID: {} ({})\n",
                    if process.running { "●" } else { "○" },
                    name,
                    name,
                    if systemd_unit_enabled(fs, name) {
                        "enabled"
                    } else {
                        "disabled"
                    },
                    if process.running {
                        "active"
                    } else {
                        "inactive"
                    },
                    if process.running { "running" } else { "dead" },
                    (self.booted_at + Duration::minutes(12)).format("%a %Y-%m-%d %H:%M:%S"),
                    pid,
                    name
                ),
                "start" | "restart" => {
                    self.virtual_processes[index].running = true;
                    String::new()
                }
                "stop" => {
                    self.virtual_processes[index].running = false;
                    String::new()
                }
                "enable" => {
                    set_systemd_unit_enabled(fs, self.distribution, name, true, now);
                    String::new()
                }
                "disable" => {
                    set_systemd_unit_enabled(fs, self.distribution, name, false, now);
                    String::new()
                }
                _ => {
                    return VirtualCommand::failure(
                        "processes",
                        format!("systemd_{action}"),
                        Some(name.into()),
                        format!("Unknown command verb {action}.\n"),
                    );
                }
            };
            self.sync_proc(fs, now);
            let mut result = VirtualCommand::success(
                "processes",
                format!("systemd_{action}"),
                Some(name.into()),
                output,
            );
            if matches!(action, "start" | "stop" | "restart" | "enable" | "disable") {
                result = result.modified("systemd", format!("/etc/systemd/system/{name}.service"));
            }
            return result;
        }
        let effective_active = self.service_running(name);
        let Some(service) = self.services.get_mut(name) else {
            return VirtualCommand::failure(
                "persistence",
                format!("systemd_{action}"),
                Some(name.into()),
                format!("Unit {name}.service could not be found.\n"),
            );
        };
        let process_name = self
            .processes
            .get(&service.pid)
            .map(|process| process_command_name(process.command))
            .unwrap_or(name);
        let static_unit = self
            .distribution
            .linux_profile()
            .and_then(|profile| profile.service(name))
            .is_some_and(|profile| profile.static_unit);
        if static_unit {
            if action == "is-enabled" {
                return VirtualCommand::success(
                    "persistence",
                    "systemd_is-enabled",
                    Some(name.into()),
                    "static\n",
                );
            }
            if matches!(action, "enable" | "disable" | "start" | "stop" | "restart") {
                return VirtualCommand::failure(
                    "persistence",
                    format!("systemd_{action}"),
                    Some(name.into()),
                    format!(
                        "Failed to {action} {name}.service: Operation refused, unit may be requested by dependency only.\n"
                    ),
                );
            }
        }
        if matches!(name, "redis-server" | "valkey")
            && matches!(action, "start" | "restart")
            && self
                .containers
                .get("redis")
                .is_some_and(|container| container.running)
        {
            return VirtualCommand::failure(
                "persistence",
                "systemd_start",
                Some(name.into()),
                format!("Job for {name}.service failed: Address already in use (port 6379).\n"),
            );
        }
        if action == "is-active" {
            let mut result = VirtualCommand::success(
                "persistence",
                "systemd_is-active",
                Some(name.into()),
                format!(
                    "{}\n",
                    if effective_active {
                        "active"
                    } else {
                        "inactive"
                    }
                ),
            );
            if !effective_active {
                result.exit_status = 3;
                result.interaction.success = false;
            }
            return result;
        }
        let enabled = systemd_unit_enabled(fs, name);
        let unit_file = systemd_unit_file(self.distribution, name);
        let output = match action {
            "status" => {
                if effective_active {
                    format!(
                        "● {name}.service - {}\n     Loaded: loaded ({unit_file}; {})\n     Active: active (running) since {} UTC\n   Main PID: {} ({process_name})\n",
                        service.description,
                        if enabled { "enabled" } else { "disabled" },
                        service
                            .started_at
                            .as_ref()
                            .unwrap_or(&(self.booted_at + Duration::minutes(12)))
                            .format("%a %Y-%m-%d %H:%M:%S"),
                        service.pid
                    )
                } else {
                    format!(
                        "○ {name}.service - {}\n     Loaded: loaded ({unit_file}; {})\n     Active: inactive (dead) since {} UTC\n",
                        service.description,
                        if enabled { "enabled" } else { "disabled" },
                        service
                            .stopped_at
                            .as_ref()
                            .unwrap_or(&(self.booted_at + Duration::minutes(12)))
                            .format("%a %Y-%m-%d %H:%M:%S")
                    )
                }
            }
            "start" | "restart" => {
                if action == "restart" {
                    let old_pid = service.pid;
                    transition_service_process(
                        &mut self.processes,
                        service,
                        old_pid,
                        ProcessSignal::Exit,
                        now,
                    );
                    let _ = fs.remove(&format!("/proc/{old_pid}"), true);
                    if name == "nginx" {
                        self.processes.remove(&(old_pid + 1));
                        self.processes.remove(&(old_pid + 2));
                        let _ = fs.remove(&format!("/proc/{}", old_pid + 1), true);
                        let _ = fs.remove(&format!("/proc/{}", old_pid + 2), true);
                    }
                    service.pid = self
                        .processes
                        .keys()
                        .filter(|pid| !(30000..=30099).contains(*pid))
                        .next_back()
                        .copied()
                        .unwrap_or(1300)
                        .saturating_add(1);
                }
                service.active = true;
                service.started_at = Some(now);
                service.stopped_at = None;
                let pid = service.pid;
                let process = if let Some(definition) = self
                    .distribution
                    .linux_profile()
                    .and_then(|profile| profile.service(name))
                {
                    Process {
                        pid,
                        user: definition.user,
                        command: definition.command,
                        state: ProcessState::Sleeping,
                        rss_kib: definition.rss_kib,
                    }
                } else {
                    match name {
                        "redis-server" | "valkey" => Process {
                            pid,
                            user: self
                                .distribution
                                .linux_profile()
                                .map_or("redis", |profile| profile.redis_user),
                            command: service_command_for_profile(
                                self.distribution.linux_profile(),
                                name,
                            ),
                            state: ProcessState::Sleeping,
                            rss_kib: 3500,
                        },
                        "mysql" | "mariadb" => Process {
                            pid,
                            user: "mysql",
                            command: self
                                .distribution
                                .linux_profile()
                                .map_or("/usr/sbin/mysqld --port=13306", |profile| {
                                    profile.mysql_command
                                }),
                            state: ProcessState::Sleeping,
                            rss_kib: 32100,
                        },
                        "vsftpd" | "vsftpd-data" => Process {
                            pid,
                            user: "root",
                            command: service_command_for_profile(
                                self.distribution.linux_profile(),
                                name,
                            ),
                            state: ProcessState::Sleeping,
                            rss_kib: 5120,
                        },
                        "billing-api-http" => Process {
                            pid,
                            user: "app",
                            command: service_command_for_profile(
                                self.distribution.linux_profile(),
                                name,
                            ),
                            state: ProcessState::Sleeping,
                            rss_kib: 81320,
                        },
                        "postgresql-public" => Process {
                            pid,
                            user: "postgres",
                            command: service_command_for_profile(
                                self.distribution.linux_profile(),
                                name,
                            ),
                            state: ProcessState::Sleeping,
                            rss_kib: 42100,
                        },
                        "nginx" => Process {
                            pid,
                            user: "root",
                            command: service_command_for_profile(
                                self.distribution.linux_profile(),
                                name,
                            ),
                            state: ProcessState::Sleeping,
                            rss_kib: 4152,
                        },
                        _ => unreachable!("service profile or virtual service must exist"),
                    }
                };
                register_process(&mut self.processes, process);
                if name == "nginx" {
                    let worker = self
                        .distribution
                        .linux_profile()
                        .map_or("www-data", |profile| profile.nginx_worker_user);
                    self.processes.insert(
                        pid + 1,
                        Process {
                            pid: pid + 1,
                            user: worker,
                            command: "nginx: worker process",
                            state: ProcessState::Sleeping,
                            rss_kib: 2160,
                        },
                    );
                    self.processes.insert(
                        pid + 2,
                        Process {
                            pid: pid + 2,
                            user: worker,
                            command: "nginx: worker process",
                            state: ProcessState::Sleeping,
                            rss_kib: 2184,
                        },
                    );
                    fs.put_file("/run/nginx.pid", format!("{pid}\n"), now);
                }
                if let Some(profile) = self.distribution.linux_profile()
                    && name == profile.redis_service_name
                {
                    fs.put_file(profile.redis_pid_file, format!("{pid}\n"), now);
                }
                String::new()
            }
            "stop" => {
                transition_service_process(
                    &mut self.processes,
                    service,
                    service.pid,
                    ProcessSignal::Exit,
                    now,
                );
                if name == "nginx" {
                    self.processes.remove(&(service.pid + 1));
                    self.processes.remove(&(service.pid + 2));
                    let _ = fs.remove("/run/nginx.pid", false);
                }
                if let Some(profile) = self.distribution.linux_profile()
                    && name == profile.redis_service_name
                {
                    let _ = fs.remove(profile.redis_pid_file, false);
                }
                let _ = fs.remove(&format!("/proc/{}", service.pid), true);
                if name == "docker" {
                    let container_pids = self
                        .containers
                        .values()
                        .filter_map(|container| container.pid)
                        .collect::<Vec<_>>();
                    for container in self.containers.values_mut() {
                        container.running = false;
                    }
                    for pid in container_pids {
                        self.processes.remove(&pid);
                        let _ = fs.remove(&format!("/proc/{pid}"), true);
                    }
                }
                String::new()
            }
            "enable" => {
                set_systemd_unit_enabled(fs, self.distribution, name, true, now);
                String::new()
            }
            "disable" => {
                set_systemd_unit_enabled(fs, self.distribution, name, false, now);
                String::new()
            }
            _ => {
                return VirtualCommand::failure(
                    "persistence",
                    format!("systemd_{action}"),
                    Some(name.into()),
                    format!("Unknown command verb {action}.\n"),
                );
            }
        };
        self.sync_container_proxies(fs);
        self.sync_proc(fs, now);
        let mut result = VirtualCommand::success(
            "persistence",
            format!("systemd_{action}"),
            Some(name.into()),
            output,
        );
        if matches!(action, "start" | "stop" | "restart" | "enable" | "disable") {
            result = result.modified("systemd", format!("/etc/systemd/system/{name}.service"));
        }
        result
    }

    fn authorized_keys(
        &mut self,
        args: &[String],
        fs: &mut VirtualFileSystem,
        now: DateTime<Utc>,
    ) -> VirtualCommand {
        match args {
            [] => VirtualCommand::success(
                "persistence",
                "authorized_keys_list",
                Some(self.username.clone()),
                format!("{}\n", self.authorized_keys.join("\n")),
            )
            .accessed("read", format!("{}/.ssh/authorized_keys", self.home)),
            [single] if single == "list" => VirtualCommand::success(
                "persistence",
                "authorized_keys_list",
                Some(self.username.clone()),
                format!("{}\n", self.authorized_keys.join("\n")),
            )
            .accessed("read", format!("{}/.ssh/authorized_keys", self.home)),
            [action, key @ ..] if action == "add" && !key.is_empty() => {
                let joined = key.join(" ");
                if !joined.starts_with("ssh-") || joined.len() > 8192 {
                    return VirtualCommand::failure(
                        "persistence",
                        "authorized_keys_add",
                        None,
                        "authorized_keys: invalid public key\n",
                    );
                }
                if self.authorized_keys.len() >= 64 {
                    return VirtualCommand::failure(
                        "persistence",
                        "authorized_keys_add",
                        None,
                        "authorized_keys: too many keys\n",
                    );
                }
                self.authorized_keys.push(joined.clone());
                self.sync_authorized_keys(fs, now);
                VirtualCommand::success(
                    "persistence",
                    "authorized_keys_add",
                    Some(key_fingerprint(&joined)),
                    "key added\n",
                )
                .modified("write", format!("{}/.ssh/authorized_keys", self.home))
            }
            [action, index] if action == "remove" => {
                let Ok(index) = index.parse::<usize>() else {
                    return VirtualCommand::failure(
                        "persistence",
                        "authorized_keys_remove",
                        Some(index.clone()),
                        "authorized_keys: invalid key number\n",
                    );
                };
                if index == 0 || index > self.authorized_keys.len() {
                    return VirtualCommand::failure(
                        "persistence",
                        "authorized_keys_remove",
                        Some(index.to_string()),
                        "authorized_keys: key not found\n",
                    );
                }
                self.authorized_keys.remove(index - 1);
                self.sync_authorized_keys(fs, now);
                VirtualCommand::success(
                    "persistence",
                    "authorized_keys_remove",
                    Some(index.to_string()),
                    "key removed\n",
                )
                .modified("write", format!("{}/.ssh/authorized_keys", self.home))
            }
            _ => VirtualCommand::failure(
                "persistence",
                "authorized_keys",
                None,
                "usage: authorized_keys [list|add <public-key>|remove <number>]\n",
            ),
        }
    }

    fn docker(
        &mut self,
        args: &[String],
        fs: &mut VirtualFileSystem,
        now: DateTime<Utc>,
    ) -> VirtualCommand {
        let api_host = docker_api_host(args);
        if let Some(api_host) = api_host
            && !self.vulnerability_profiles.contains("docker_api_exposed")
        {
            return VirtualCommand::failure(
                "docker",
                "api_connect",
                Some(api_host.to_owned()),
                format!(
                    "error during connect: Get \"http://{api_host}/_ping\": dial tcp: connect: connection refused\n"
                ),
            );
        }
        let normalized_args = if api_host.is_some() {
            args.iter()
                .enumerate()
                .filter_map(|(index, arg)| {
                    let is_host_value =
                        index > 0 && matches!(args[index - 1].as_str(), "-H" | "--host");
                    (!is_host_value
                        && arg != "-H"
                        && arg != "--host"
                        && !arg.starts_with("--host=")
                        && !arg.starts_with("-H="))
                    .then_some(arg.clone())
                })
                .collect::<Vec<_>>()
        } else {
            args.to_vec()
        };
        let args = normalized_args.as_slice();
        if !self
            .services
            .get("docker")
            .is_some_and(|service| service.active)
        {
            return VirtualCommand::failure(
                "docker",
                "daemon_connect",
                None,
                "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?\n",
            );
        }
        if args.first().is_some_and(|arg| arg == "compose") {
            return self.docker_compose(&args[1..], fs, now);
        }
        let Some(action) = args.first().map(String::as_str) else {
            return VirtualCommand::failure("docker", "help", None, "docker: command required\n");
        };
        match action {
            "ps" => {
                let all = args.iter().any(|arg| arg == "-a" || arg == "--all");
                let mut output = "CONTAINER ID   IMAGE                                      COMMAND                  STATUS          PORTS                    NAMES\n".to_owned();
                for container in self
                    .containers
                    .values()
                    .filter(|container| all || container.running)
                {
                    let status = if container.running {
                        format!("Up {} days", (now - self.booted_at).num_days().max(0))
                    } else {
                        "Exited (0)".to_owned()
                    };
                    let ports = if container.running && container.name == "redis" {
                        "6379/tcp".to_owned()
                    } else if container.running {
                        container
                            .port
                            .map(|port| format!("0.0.0.0:{port}->{port}/tcp"))
                            .unwrap_or_default()
                    } else {
                        String::new()
                    };
                    output.push_str(&format!(
                        "{}   {:<42} {:<24} {:<15} {:<24} {}\n",
                        container.id,
                        container.image,
                        container.name,
                        status,
                        ports,
                        container.name
                    ));
                }
                VirtualCommand::success("docker", "container_list", None, output)
            }
            "images" => self.docker_images(),
            "image" if args.get(1).is_some_and(|value| value == "ls") => self.docker_images(),
            "info" => VirtualCommand::success(
                "docker",
                "daemon_info",
                None,
                format!(
                    "Client: Docker Engine - Community\n Version: 27.3.1\n Context: default\n\nServer:\n Containers: {}\n  Running: {}\n  Paused: 0\n  Stopped: {}\n Images: {}\n Server Version: 27.3.1\n Storage Driver: overlay2\n Cgroup Driver: systemd\n Cgroup Version: 2\n Operating System: Ubuntu 22.04.4 LTS\n Architecture: x86_64\n CPUs: 2\n Total Memory: 3.84GiB\n Docker Root Dir: /var/lib/docker\n",
                    self.containers.len(),
                    self.containers
                        .values()
                        .filter(|container| container.running)
                        .count(),
                    self.containers
                        .values()
                        .filter(|container| !container.running)
                        .count(),
                    self.containers
                        .values()
                        .map(|container| container.image)
                        .collect::<std::collections::BTreeSet<_>>()
                        .len()
                ),
            ),
            "inspect" => {
                let Some(name) = args.get(1) else {
                    return VirtualCommand::failure(
                        "docker",
                        "container_inspect",
                        None,
                        "docker inspect requires at least 1 argument\n",
                    );
                };
                let Some(container) = self.find_container(name) else {
                    return docker_not_found("inspect", name);
                };
                let pid = if container.running {
                    container.pid.unwrap_or(0)
                } else {
                    0
                };
                let ip_address = if container.running {
                    match container.name {
                        "billing-api" => "172.18.0.3",
                        "billing-worker" => "172.18.0.4",
                        "redis" => "172.18.0.5",
                        _ => "",
                    }
                } else {
                    ""
                };
                let ports = if container.running && container.name == "redis" {
                    "\"6379/tcp\": null".to_owned()
                } else if container.running {
                    container.port.map_or_else(String::new, |port| {
                        format!("\"{port}/tcp\": [{{\"HostPort\": \"{port}\"}}]")
                    })
                } else {
                    String::new()
                };
                VirtualCommand::success(
                    "docker",
                    "container_inspect",
                    Some(container.name.into()),
                    format!(
                        "[{{\n  \"Id\": \"{}\",\n  \"Name\": \"/{}\",\n  \"Config\": {{\"Image\": \"{}\", \"Env\": [\"APP_ENV=production\",\"DATABASE_URL=postgres://billing_app:decoy-db-pass@db-internal:5432/billing\",\"REDIS_URL=redis://redis:6379/0\"]}},\n  \"State\": {{\"Running\": {}, \"Pid\": {pid}}},\n  \"NetworkSettings\": {{\"IPAddress\": \"{ip_address}\", \"Ports\": {{{ports}}}}}\n}}]\n",
                        container.id, container.name, container.image, container.running
                    ),
                )
            }
            "logs" => {
                let Some(name) = args.iter().skip(1).find(|arg| !arg.starts_with('-')) else {
                    return VirtualCommand::failure(
                        "docker",
                        "container_logs",
                        None,
                        "docker logs requires exactly 1 argument\n",
                    );
                };
                let Some(container) = self.find_container(name) else {
                    return docker_not_found("logs", name);
                };
                VirtualCommand::success(
                    "docker",
                    "container_logs",
                    Some(container.name.into()),
                    container.logs,
                )
            }
            "start" | "stop" | "restart" => {
                let Some(name) = args.get(1) else {
                    return VirtualCommand::failure(
                        "docker",
                        format!("container_{action}"),
                        None,
                        format!("docker {action} requires at least 1 argument\n"),
                    );
                };
                self.set_container(name, action != "stop", fs, now)
            }
            "exec" => self.docker_exec(&args[1..]),
            "volume" => self.docker_objects("volume", &args[1..]),
            "network" => self.docker_objects("network", &args[1..]),
            _ => VirtualCommand::failure(
                "docker",
                action,
                None,
                format!("docker: '{action}' is not a docker command.\n"),
            ),
        }
    }

    fn docker_exec(&self, args: &[String]) -> VirtualCommand {
        let mut index = 0;
        let mut requested_user = None;
        while index < args.len() {
            match args[index].as_str() {
                "-i" | "-t" | "-it" | "-ti" | "--interactive" | "--tty" => index += 1,
                "-u" | "--user" => {
                    let Some(user) = args.get(index + 1) else {
                        return VirtualCommand::failure(
                            "docker",
                            "container_exec",
                            None,
                            "docker exec: option requires an argument -- 'u'\n",
                        );
                    };
                    requested_user = Some(user.as_str());
                    index += 2;
                }
                "-w" | "--workdir" | "-e" | "--env" => index += 2,
                value if value.starts_with('-') => index += 1,
                _ => break,
            }
        }
        let Some(name) = args.get(index) else {
            return VirtualCommand::failure(
                "docker",
                "container_exec",
                None,
                "docker exec requires a container and command\n",
            );
        };
        let command_args = &args[index + 1..];
        if command_args.is_empty() {
            return VirtualCommand::failure(
                "docker",
                "container_exec",
                Some(name.clone()),
                "docker exec requires a container and command\n",
            );
        }
        let Some(container) = self.find_container(name) else {
            return docker_not_found("exec", name);
        };
        if !container.running {
            return VirtualCommand::failure(
                "docker",
                "container_exec",
                Some(container.name.into()),
                format!(
                    "Error response from daemon: container {} is not running\n",
                    container.id
                ),
            );
        }
        let command = command_args
            .iter()
            .map(|value| value.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let user = requested_user.unwrap_or(match container.name {
            "redis" if self.distribution == Distribution::Arch => "valkey",
            "redis" => "redis",
            "billing-api" | "billing-worker" => "app",
            _ => "root",
        });
        let output = match command.as_str() {
            "whoami" => format!("{user}\n"),
            "id" => match user {
                "root" | "0" => "uid=0(root) gid=0(root) groups=0(root)\n".into(),
                "valkey" | "971" => "uid=971(valkey) gid=971(valkey) groups=971(valkey)\n".into(),
                "redis" | "999" => "uid=999(redis) gid=999(redis) groups=999(redis)\n".into(),
                "app" | "1001" => "uid=1001(app) gid=1001(app) groups=1001(app)\n".into(),
                _ => format!("uid=1000({user}) gid=1000({user}) groups=1000({user})\n"),
            },
            "pwd" if container.name == "redis" => "/data\n".into(),
            "pwd" => "/app\n".into(),
            "ls /app" | "ls -la /app" | "ls -l /app" if container.name != "redis" => {
                "total 17420\ndrwxr-xr-x 1 root root     4096 Oct 12 07:40 .\ndrwxr-xr-x 1 root root     4096 Oct 12 07:40 ..\n-rwxr-xr-x 1 app  app  12492800 Oct 11 19:12 billing-api\n-rwxr-xr-x 1 app  app   5144576 Oct 11 19:12 billing-worker\n-rw-r--r-- 1 app  app      1024 Oct 12 07:39 config.toml\n".into()
            }
            "cat /app/config.toml" if container.name != "redis" => {
                "listen = \"0.0.0.0:8080\"\nredis_url = \"redis://redis:6379/0\"\nlog_level = \"info\"\n".into()
            }
            "env" | "printenv" if container.name == "redis" => {
                if self.distribution == Distribution::Arch {
                    "VALKEY_VERSION=9.1.2\nVALKEY_PORT=6379\nHOME=/data\n".into()
                } else {
                    "REDIS_VERSION=7.2\nREDIS_PORT=6379\nHOME=/data\n".into()
                }
            }
            "env" | "printenv" => {
                format!("APP_ENV=production\nHOSTNAME={}\nDATABASE_URL=postgres://billing_app:decoy-db-pass@db-internal:5432/billing\nREDIS_URL=redis://redis:6379/0\n", container.id)
            }
            "ps" | "ps aux" => {
                let process = if container.name == "billing-worker" {
                    "/app/billing-worker --queue invoices"
                } else if container.name == "redis" {
                    if self.distribution == Distribution::Arch {
                        "valkey-server *:6379"
                    } else {
                        "redis-server *:6379"
                    }
                } else {
                    "/app/billing-api --config /app/config.toml"
                };
                let user = if container.name == "redis" {
                    if self.distribution == Distribution::Arch {
                        "valkey"
                    } else {
                        "redis"
                    }
                } else {
                    "app"
                };
                format!("PID USER     STAT COMMAND\n  1 {user:<8} S    {process}\n")
            }
            "cat /app/.env" => {
                "APP_ENV=production\nDATABASE_URL=postgres://billing_app:decoy-db-pass@db-internal:5432/billing\nREDIS_URL=redis://redis:6379/0\n".into()
            }
            "hostname" => container.id.into(),
            _ => {
                return VirtualCommand::failure(
                    "docker",
                    "container_exec",
                    Some(container.name.into()),
                    format!("exec: {command}: not found\n"),
                );
            }
        };
        VirtualCommand::success(
            "docker",
            "container_exec",
            Some(container.name.into()),
            format!("{output}{}", if output.ends_with('\n') { "" } else { "\n" }),
        )
    }

    fn docker_images(&self) -> VirtualCommand {
        let mut output =
            "REPOSITORY                         TAG       IMAGE ID       CREATED        SIZE\n"
                .to_owned();
        let mut seen = std::collections::BTreeSet::new();
        for container in self.containers.values() {
            if seen.insert(container.image) {
                let (repository, tag) = container
                    .image
                    .rsplit_once(':')
                    .unwrap_or((container.image, "latest"));
                let image_id = if container.image == "redis:7.2-alpine" {
                    "6d3a92bc1e0f"
                } else if container.image == "valkey/valkey:9.1-alpine" {
                    "a9fc6d3f4201"
                } else {
                    "be84c73a1590"
                };
                output.push_str(&format!(
                    "{repository:<35} {tag:<9} {image_id:<14} 3 weeks ago    142MB\n"
                ));
            }
        }
        VirtualCommand::success("docker", "image_list", None, output)
    }

    fn docker_objects(&self, kind: &'static str, args: &[String]) -> VirtualCommand {
        let action = args.first().map(String::as_str).unwrap_or("ls");
        let target = args.get(1).cloned();
        let output = match (kind, action) {
            ("volume", "ls") => "DRIVER    VOLUME NAME\nlocal     billing_uploads\n",
            ("volume", "inspect")
                if target
                    .as_deref()
                    .is_some_and(|name| name == "billing_uploads") =>
            {
                "[{\"Driver\":\"local\",\"Mountpoint\":\"/var/lib/docker/volumes/decoy/_data\",\"Scope\":\"local\"}]\n"
            }
            ("network", "ls") => {
                "NETWORK ID     NAME               DRIVER    SCOPE\n31d2dec0a001   bridge             bridge    local\n8891dec0b002   billing_internal   bridge    local\n"
            }
            ("network", "inspect")
                if target
                    .as_deref()
                    .is_some_and(|name| matches!(name, "bridge" | "billing_internal")) =>
            {
                "[{\"Name\":\"billing_internal\",\"Driver\":\"bridge\",\"IPAM\":{\"Config\":[{\"Subnet\":\"172.18.0.0/16\",\"Gateway\":\"172.18.0.1\"}]}}]\n"
            }
            _ => {
                return VirtualCommand::failure(
                    "docker",
                    format!("{kind}_{action}"),
                    target,
                    format!("Error: No such {kind}\n"),
                );
            }
        };
        VirtualCommand::success("docker", format!("{kind}_{action}"), target, output)
    }

    fn docker_compose(
        &mut self,
        args: &[String],
        fs: &mut VirtualFileSystem,
        now: DateTime<Utc>,
    ) -> VirtualCommand {
        let filtered: Vec<_> = args
            .iter()
            .filter(|arg| {
                !arg.starts_with('-') && !arg.ends_with(".yml") && !arg.ends_with(".yaml")
            })
            .cloned()
            .collect();
        let Some(action) = filtered.first().map(String::as_str) else {
            return VirtualCommand::failure(
                "docker",
                "compose",
                None,
                "docker compose requires a command\n",
            );
        };
        match action {
            "ps" => {
                let mut output = "NAME             IMAGE                                      SERVICE   STATUS        PORTS\n".to_owned();
                for container in self
                    .containers
                    .values()
                    .filter(|container| container.name != "payments-migrate")
                {
                    output.push_str(&format!(
                        "{:<16} {:<42} {:<9} {:<13} {}\n",
                        container.name,
                        container.image,
                        container.name.trim_start_matches("billing-"),
                        if container.running {
                            "running"
                        } else {
                            "exited"
                        },
                        if container.running {
                            if container.name == "redis" {
                                "6379/tcp".to_owned()
                            } else {
                                container
                                    .port
                                    .map(|p| format!("0.0.0.0:{p}->{p}/tcp"))
                                    .unwrap_or_default()
                            }
                        } else {
                            String::new()
                        }
                    ));
                }
                VirtualCommand::success("docker", "compose_ps", Some("billing".into()), output)
            }
            "up" | "start" => {
                for name in ["billing-api", "billing-worker", "redis"] {
                    let _ = self.set_container(name, true, fs, now);
                }
                VirtualCommand::success(
                    "docker",
                    format!("compose_{action}"),
                    Some("billing".into()),
                    "[+] Running 3/3\n ✔ Container billing-api     Started\n ✔ Container billing-worker  Started\n ✔ Container redis           Started\n",
                )
            }
            "down" | "stop" => {
                for name in ["billing-api", "billing-worker", "redis"] {
                    let _ = self.set_container(name, false, fs, now);
                }
                VirtualCommand::success(
                    "docker",
                    format!("compose_{action}"),
                    Some("billing".into()),
                    "[+] Stopping 3/3\n ✔ Container redis           Stopped\n ✔ Container billing-worker  Stopped\n ✔ Container billing-api     Stopped\n",
                )
            }
            "logs" => VirtualCommand::success(
                "docker",
                "compose_logs",
                Some("billing".into()),
                format!(
                    "billing-api-1  | {}billing-worker-1 | {}redis-1        | {}",
                    self.containers["billing-api"].logs,
                    self.containers["billing-worker"].logs,
                    self.containers["redis"].logs
                ),
            ),
            "config" => VirtualCommand::success(
                "docker",
                "compose_config",
                Some("billing".into()),
                format!(
                    "name: billing\nservices:\n  api:\n    container_name: billing-api\n    image: registry.internal/billing-api:2.8.4\n    depends_on:\n      - redis\n  worker:\n    container_name: billing-worker\n    image: registry.internal/billing-api:2.8.4\n    depends_on:\n      - redis\n  redis:\n    container_name: redis\n    image: {}\n    restart: unless-stopped\n",
                    self.containers["redis"].image
                ),
            ),
            _ => VirtualCommand::failure(
                "docker",
                format!("compose_{action}"),
                Some("billing".into()),
                format!("no such command: {action}\n"),
            ),
        }
    }

    fn find_container(&self, name_or_id: &str) -> Option<&Container> {
        self.containers
            .values()
            .find(|container| container.name == name_or_id || container.id.starts_with(name_or_id))
    }

    fn sync_container_proxies(&mut self, fs: &mut VirtualFileSystem) {
        let old_proxy_pids = self
            .processes
            .keys()
            .copied()
            .filter(|pid| (30000..=30099).contains(pid))
            .collect::<Vec<_>>();
        for pid in old_proxy_pids {
            self.processes.remove(&pid);
            let _ = fs.remove(&format!("/proc/{pid}"), true);
        }
        let proxies = self
            .containers
            .values()
            .enumerate()
            .filter_map(|(index, container)| {
                (container.running && container.port.is_some()).then_some(30000 + index as u32)
            })
            .collect::<Vec<_>>();
        for pid in proxies {
            self.processes.insert(
                pid,
                Process {
                    pid,
                    user: "root",
                    command: "/usr/bin/docker-proxy",
                    state: ProcessState::Sleeping,
                    rss_kib: 2480,
                },
            );
        }
    }

    fn set_container(
        &mut self,
        name_or_id: &str,
        running: bool,
        fs: &mut VirtualFileSystem,
        now: DateTime<Utc>,
    ) -> VirtualCommand {
        let Some(name) = self
            .containers
            .values()
            .find(|container| container.name == name_or_id || container.id.starts_with(name_or_id))
            .map(|container| container.name)
        else {
            return docker_not_found(if running { "start" } else { "stop" }, name_or_id);
        };
        if running
            && !self
                .services
                .get("docker")
                .is_some_and(|service| service.active)
        {
            return VirtualCommand::failure(
                "docker",
                "container_start",
                Some(name.into()),
                "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?\n",
            );
        }
        let distribution = self.distribution;
        let container = self
            .containers
            .get_mut(name)
            .expect("container name came from map");
        let pid = container.pid;
        // One-shot containers without a steady PID finish immediately after start.
        container.running = running && pid.is_some();
        if let Some(pid) = pid {
            if running {
                let process = match name {
                    "billing-api" => Process {
                        pid,
                        user: "app",
                        command: "/app/billing-api --config /app/config.toml",
                        state: ProcessState::Sleeping,
                        rss_kib: 81320,
                    },
                    "billing-worker" => Process {
                        pid,
                        user: "app",
                        command: "/app/billing-worker --queue invoices",
                        state: ProcessState::Sleeping,
                        rss_kib: 47640,
                    },
                    "redis" => Process {
                        pid,
                        user: if distribution == Distribution::Arch {
                            "valkey"
                        } else {
                            "redis"
                        },
                        command: if distribution == Distribution::Arch {
                            "/usr/bin/valkey-server *:6379"
                        } else {
                            "redis-server *:6379"
                        },
                        state: ProcessState::Sleeping,
                        rss_kib: 13820,
                    },
                    _ => unreachable!("only running containers have a configured PID"),
                };
                self.processes.insert(pid, process);
            } else {
                self.processes.remove(&pid);
                let _ = fs.remove(&format!("/proc/{pid}"), true);
            }
        }
        self.sync_container_proxies(fs);
        self.sync_proc(fs, now);
        let mut result = VirtualCommand::success(
            "docker",
            if running {
                "container_start"
            } else {
                "container_stop"
            },
            Some(name.into()),
            format!("{name}\n"),
        )
        .modified("container_state", format!("docker://{name}"));
        if let Some(pid) = pid {
            result = result.modified(
                if running { "create" } else { "remove" },
                format!("/proc/{pid}"),
            );
        }
        result
    }

    fn git(&self, args: &[String], cwd: &str, fs: &VirtualFileSystem) -> VirtualCommand {
        let repo = if cwd.starts_with("/srv/billing-api") {
            "/srv/billing-api"
        } else {
            return VirtualCommand::failure(
                "git",
                "repository",
                Some(cwd.into()),
                "fatal: not a git repository (or any of the parent directories): .git\n",
            );
        };
        let action = args.first().map(String::as_str).unwrap_or("status");
        match action {
            "log" => {
                let oneline = args.iter().any(|arg| {
                    arg == "--oneline"
                        || arg.starts_with('-') && arg.chars().skip(1).all(|c| c.is_ascii_digit())
                });
                let output = if oneline {
                    "a8147d2 (HEAD -> main, tag: v2.8.4) fix retry accounting for invoice worker\n74d09b1 add refund feature flag\n21c3ee8 rotate production database credentials\n9a40d15 add docker healthcheck\n34cb127 initial billing service\n"
                } else {
                    "commit a8147d2ea41b59af027c64ef21dec0dec0dec001 (HEAD -> main, tag: v2.8.4)\nAuthor: Elena Volkova <elena@example.test>\nDate:   Sat Oct 11 19:22:04 2026 +0000\n\n    fix retry accounting for invoice worker\n\ncommit 74d09b13f9a0dec0dec0dec0dec0dec0dec00002\nAuthor: Pavel Morozov <pavel@example.test>\nDate:   Fri Oct 10 14:08:51 2026 +0000\n\n    add refund feature flag\n"
                };
                VirtualCommand::success("git", "log", Some(repo.into()), output)
            }
            "status" => {
                let changes = self.git_changes(fs);
                let mut output =
                    "On branch main\nYour branch is up to date with 'origin/main'.\n\n".to_owned();
                if changes.is_empty() {
                    output.push_str("nothing to commit, working tree clean\n");
                } else {
                    output.push_str("Changes not staged for commit:\n");
                    for (path, deleted) in changes {
                        output.push_str(&format!(
                            "\t{}:   {path}\n",
                            if deleted { "deleted" } else { "modified" }
                        ));
                    }
                    output.push_str("\nno changes added to commit\n");
                }
                VirtualCommand::success("git", "status", Some(repo.into()), output)
            }
            "show" => {
                let reference = args.get(1).map(String::as_str).unwrap_or("HEAD");
                let Some(output) = git_show(reference) else {
                    return VirtualCommand::failure(
                        "git",
                        "show",
                        Some(reference.into()),
                        format!(
                            "fatal: ambiguous argument '{reference}': unknown revision or path not in the working tree.\n"
                        ),
                    );
                };
                VirtualCommand::success("git", "show", Some(reference.into()), output)
            }
            "branch" => VirtualCommand::success(
                "git",
                "branch",
                Some(repo.into()),
                "* main\n  release/2.8\n",
            ),
            "remote" if args.iter().any(|arg| arg == "-v") => VirtualCommand::success(
                "git",
                "remote",
                Some(repo.into()),
                "origin\tssh://git@git.internal/platform/billing-api.git (fetch)\norigin\tssh://git@git.internal/platform/billing-api.git (push)\n",
            ),
            _ => VirtualCommand::failure(
                "git",
                action,
                Some(repo.into()),
                format!("git: '{action}' is not supported by this repository mirror\n"),
            ),
        }
    }

    fn git_changes(&self, fs: &VirtualFileSystem) -> Vec<(String, bool)> {
        self.git_baseline
            .iter()
            .filter_map(|(path, expected)| {
                let absolute = format!("/srv/billing-api/{path}");
                match fs.read(&absolute) {
                    Ok(data) if data == expected.as_bytes() => None,
                    Ok(_) => Some(((*path).into(), false)),
                    Err(_) => Some(((*path).into(), true)),
                }
            })
            .collect()
    }

    fn psql(&mut self, args: &[String]) -> VirtualCommand {
        let connection_string = args
            .iter()
            .find(|arg| arg.starts_with("postgres://") || arg.starts_with("postgresql://"))
            .map(String::as_str);
        let requested_host = args
            .windows(2)
            .find(|pair| pair[0] == "-h" || pair[0] == "--host")
            .map(|pair| pair[1].as_str())
            .or_else(|| {
                connection_string
                    .and_then(|url| url.split_once("@"))
                    .and_then(|(_, rest)| rest.split('/').next())
                    .map(|authority| authority.rsplit_once(':').map_or(authority, |(host, _)| host))
            });
        if requested_host.is_some_and(|host| {
            host.parse::<std::net::IpAddr>()
                .is_ok_and(|address| !address.is_loopback())
        }) {
            return VirtualCommand::failure(
                "postgresql",
                "connect",
                requested_host.map(str::to_owned),
                "psql: outbound network access is disabled in the virtual SSH shell; test the public listener from an external client\n",
            );
        }
        let public_port_requested = args
            .windows(2)
            .any(|pair| matches!(pair[0].as_str(), "-p" | "--port") && pair[1] == "15432")
            || args
                .iter()
                .any(|arg| arg == "-p15432" || arg == "--port=15432")
            || connection_string.is_some_and(|value| value.contains(":15432/"));
        if public_port_requested {
            if !self
                .vulnerability_profiles
                .contains("sql_database_weak_credentials")
            {
                return VirtualCommand::failure(
                    "postgresql",
                    "connect",
                    Some("127.0.0.1:15432".into()),
                    "psql: error: connection to server at \"127.0.0.1\", port 15432 failed: Connection refused\n",
                );
            }
            let mut username = args
                .windows(2)
                .find(|pair| pair[0] == "-U" || pair[0] == "--username")
                .map(|pair| pair[1].as_str())
                .unwrap_or("postgres");
            let mut password = "";
            if let Some(connection_string) = connection_string
                && let Some(credentials) = connection_string
                    .split_once("://")
                    .and_then(|(_, rest)| rest.split_once('@').map(|(credentials, _)| credentials))
                && let Some((connection_user, connection_password)) = credentials.split_once(':')
            {
                username = connection_user;
                password = connection_password;
            }
            let valid_user = matches!(
                username.to_ascii_lowercase().as_str(),
                "app" | "admin" | "deploy" | "root" | "postgres" | "mysql" | "dbadmin"
            );
            let weak_password = matches!(
                password.to_ascii_lowercase().as_str(),
                "admin"
                    | "admin123"
                    | "password"
                    | "password1"
                    | "123456"
                    | "12345678"
                    | "qwerty"
                    | "letmein"
                    | "welcome"
                    | "ubuntu"
                    | "toor"
            );
            if !valid_user || !weak_password {
                return VirtualCommand::failure(
                    "postgresql",
                    "auth_failed",
                    Some(username.into()),
                    format!(
                        "psql: error: connection to server at \"127.0.0.1\", port 15432 failed: FATAL:  password authentication failed for user \"{username}\"\n"
                    ),
                );
            }
        }
        let query = args
            .iter()
            .position(|arg| arg == "-c" || arg == "--command")
            .and_then(|index| args.get(index + 1))
            .cloned();
        let Some(query) = query else {
            return VirtualCommand::success(
                "postgresql",
                "connect",
                Some("billing@db-internal".into()),
                "psql (14.13 (Ubuntu 14.13-0ubuntu0.22.04.1))\nSSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384)\nType \"help\" for help. Use psql -c <query> in this shell.\n\nbilling=> ",
            );
        };
        let normalized = query.trim().trim_end_matches(';').to_ascii_lowercase();
        let target = Some("billing@db-internal".into());
        if normalized == "\\dt" {
            return VirtualCommand::success(
                "postgresql",
                "schema_list",
                target,
                "             List of relations\n Schema |   Name    | Type  |   Owner\n--------+-----------+-------+-------------\n public | users     | table | billing_app\n public | api_keys  | table | billing_app\n public | audit_log | table | billing_app\n(3 rows)\n",
            );
        }
        if normalized.starts_with("\\d users") {
            return VirtualCommand::success(
                "postgresql",
                "schema_describe",
                target,
                "                 Table \"public.users\"\n Column |  Type   | Nullable\n--------+---------+----------\n id     | bigint  | not null\n email  | text    | not null\n role   | text    | not null\n",
            );
        }
        if normalized.starts_with("select count(*) from users") {
            return VirtualCommand::success(
                "postgresql",
                "select",
                target,
                format!(" count\n-------\n {:>5}\n(1 row)\n", self.db_users.len()),
            );
        }
        if normalized.starts_with("select") && normalized.contains("from users") {
            let mut output =
                " id |         email          |   role\n----+------------------------+----------\n"
                    .to_owned();
            for user in &self.db_users {
                output.push_str(&format!(
                    "{:>3} | {:<22} | {}\n",
                    user.id, user.email, user.role
                ));
            }
            output.push_str(&format!("({} rows)\n", self.db_users.len()));
            return VirtualCommand::success("postgresql", "select", target, output);
        }
        if normalized.starts_with("select") && normalized.contains("from api_keys") {
            return VirtualCommand::success(
                "postgresql",
                "select",
                target,
                " id | service |      token_prefix      | revoked\n----+---------+------------------------+---------\n  7 | deploy  | hf_decoy_deploy_7f91  | f\n 11 | reports | hf_decoy_reports_b812 | f\n(2 rows)\n",
            );
        }
        if normalized.starts_with("select") && normalized.contains("from audit_log") {
            let mut output =
                " id | event\n----+-----------------------------------------\n".to_owned();
            for (index, event) in self.db_audit.iter().enumerate() {
                output.push_str(&format!("{:>3} | {event}\n", index + 1));
            }
            output.push_str(&format!("({} rows)\n", self.db_audit.len()));
            return VirtualCommand::success("postgresql", "select", target, output);
        }
        if normalized.starts_with("insert into audit_log") {
            if self.db_audit.len() >= 256 {
                return VirtualCommand::failure(
                    "postgresql",
                    "insert",
                    target,
                    "ERROR: audit_log quota exceeded\n",
                );
            }
            let event = first_quoted_value(&query)
                .unwrap_or("manual audit event")
                .chars()
                .take(256)
                .collect::<String>();
            self.db_audit.push(event);
            return VirtualCommand::success("postgresql", "insert", target, "INSERT 0 1\n");
        }
        if normalized.starts_with("delete from audit_log") {
            let count = self.db_audit.len();
            self.db_audit.clear();
            return VirtualCommand::success(
                "postgresql",
                "delete",
                target,
                format!("DELETE {count}\n"),
            );
        }
        if normalized.starts_with("update users set role") {
            let Some(id) =
                value_after(&normalized, "where id").and_then(|value| value.parse::<u32>().ok())
            else {
                return VirtualCommand::failure(
                    "postgresql",
                    "update",
                    target,
                    "ERROR: invalid UPDATE predicate\n",
                );
            };
            let Some(role) = first_quoted_value(&query).map(str::to_owned) else {
                return VirtualCommand::failure(
                    "postgresql",
                    "update",
                    target,
                    "ERROR: invalid role value\n",
                );
            };
            let count = self
                .db_users
                .iter_mut()
                .filter(|user| user.id == id)
                .map(|user| {
                    user.role = role.clone();
                    1_u8
                })
                .sum::<u8>();
            return VirtualCommand::success(
                "postgresql",
                "update",
                target,
                format!("UPDATE {count}\n"),
            );
        }
        VirtualCommand::failure(
            "postgresql",
            "query",
            target,
            "ERROR: syntax or feature not supported by the read-only compatibility console\n",
        )
    }

    fn archive(
        &self,
        command: &str,
        args: &[String],
        cwd: &str,
        fs: &mut VirtualFileSystem,
        now: DateTime<Utc>,
    ) -> VirtualCommand {
        let archive_arg = args.iter().find(|arg| {
            self.backups
                .iter()
                .any(|backup| backup.path.ends_with(arg.as_str()) || backup.path == arg.as_str())
        });
        let Some(raw_archive) = archive_arg else {
            return VirtualCommand::failure(
                "backups",
                format!("{command}_inspect"),
                None,
                format!("{command}: archive not found\n"),
            );
        };
        let Some(backup) = self.backups.iter().find(|backup| {
            backup.path == raw_archive || backup.path.ends_with(raw_archive.as_str())
        }) else {
            return VirtualCommand::failure(
                "backups",
                format!("{command}_inspect"),
                Some(raw_archive.clone()),
                format!("{command}: cannot find or open {raw_archive}\n"),
            );
        };
        let listing = command == "zipinfo"
            || args.iter().any(|arg| arg == "-l")
            || (command == "tar"
                && args
                    .iter()
                    .any(|arg| arg.starts_with('-') && arg.contains('t')));
        if listing {
            let mut output = if command == "unzip" {
                format!("Archive:  {}\n", backup.path)
            } else {
                String::new()
            };
            for (path, content) in &backup.entries {
                if command == "unzip" || command == "zipinfo" {
                    output.push_str(&format!(
                        "{:>9}  2026-10-11 02:17   {path}\n",
                        content.len()
                    ));
                } else {
                    output.push_str(&format!("{path}\n"));
                }
            }
            return VirtualCommand::success(
                "backups",
                "archive_list",
                Some(backup.path.into()),
                output,
            )
            .accessed("read", backup.path);
        }
        let target_raw = args
            .iter()
            .position(|arg| arg == "-C" || arg == "-d")
            .and_then(|index| args.get(index + 1))
            .map(String::as_str)
            .unwrap_or(cwd);
        let target = match VirtualFileSystem::normalize(cwd, target_raw) {
            Ok(path) => path,
            Err(error) => {
                return virtual_fs_failure("backups", "archive_extract", target_raw, error);
            }
        };
        if !fs.is_dir(&target) {
            return virtual_fs_failure(
                "backups",
                "archive_extract",
                target_raw,
                FsError::NotDirectory,
            );
        }
        let entries = backup.entries.clone();
        let backup_path = backup.path;
        let mut result =
            VirtualCommand::success("backups", "archive_extract", Some(backup_path.into()), "")
                .accessed("read", backup_path);
        for (relative, content) in entries {
            let path = match VirtualFileSystem::normalize(&target, relative) {
                Ok(path) => path,
                Err(error) => {
                    return virtual_fs_failure("backups", "archive_extract", relative, error);
                }
            };
            if let Some(parent) = path
                .rsplit_once('/')
                .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
            {
                ensure_dir(fs, parent, now);
            }
            if let Err(error) = fs.write(&path, content.as_bytes().to_vec(), now) {
                return virtual_fs_failure("backups", "archive_extract", &path, error);
            }
            result = result.modified("extract", path);
        }
        result
    }

    fn companyctl(
        &mut self,
        args: &[String],
        cwd: &str,
        fs: &mut VirtualFileSystem,
        now: DateTime<Utc>,
    ) -> VirtualCommand {
        let help = "companyctl 1.7.3\nUsage: companyctl <command> [options]\n\nCommands:\n  services  List, inspect and control services\n  config    List and read service configuration\n  backups   List, inspect and restore backups\n\nRun 'companyctl <command> --help' for command help.\n";
        if args.is_empty()
            || args
                .first()
                .is_some_and(|arg| matches!(arg.as_str(), "--help" | "-h" | "help"))
        {
            return VirtualCommand::success("companyctl", "help", None, help);
        }
        let area = args
            .first()
            .expect("empty arguments handled above")
            .as_str();
        let action = args.get(1).map(String::as_str).unwrap_or("list");
        if matches!(action, "--help" | "-h" | "help") {
            let output = match area {
                "services" => {
                    "Usage: companyctl services <list|health|status|start|stop|restart> [service]\n"
                }
                "config" => "Usage: companyctl config <list|get> [name]\n",
                "backups" => "Usage: companyctl backups <list|show|restore> [name]\n",
                _ => help,
            };
            return VirtualCommand::success(
                "companyctl",
                format!("{area}_help"),
                Some(area.into()),
                output,
            );
        }
        match (area, action) {
            ("services", "list" | "health") => {
                let api = self.containers["billing-api"].running;
                let worker = self.containers["billing-worker"].running;
                let postgres_service = if self.distribution == Distribution::Debian {
                    "postgresql@17-main"
                } else {
                    "postgresql"
                };
                let postgres = self.service_running(postgres_service);
                let redis = self.containers["redis"].running;
                let api_endpoint = if api { "http://10.20.4.21:8080" } else { "-" };
                let worker_endpoint = if worker { "redis://redis:6379/0" } else { "-" };
                let postgres_endpoint = if postgres {
                    "postgres://10.20.4.12:5432/billing"
                } else {
                    "-"
                };
                let redis_endpoint = if redis { "redis://redis:6379/0" } else { "-" };
                let output = format!(
                    "SERVICE          STATE     ENDPOINT\nbilling-api      {:<9} {api_endpoint}\nbilling-worker   {:<9} {worker_endpoint}\npostgresql       {:<9} {postgres_endpoint}\nredis            {:<9} {redis_endpoint}\n",
                    state_word(api),
                    state_word(worker),
                    state_word(postgres),
                    state_word(redis)
                );
                VirtualCommand::success("companyctl", format!("services_{action}"), None, output)
            }
            ("services", "status") => {
                let Some(name) = args.get(2) else {
                    return VirtualCommand::failure(
                        "companyctl",
                        "services_status",
                        None,
                        "companyctl: service name required\n",
                    );
                };
                let running = self.virtual_service_running(name);
                match running {
                    Some(running) => VirtualCommand::success(
                        "companyctl",
                        "services_status",
                        Some(name.clone()),
                        format!(
                            "name: {name}\nenvironment: production\nstate: {}\nowner: platform-team\n",
                            state_word(running)
                        ),
                    ),
                    None => VirtualCommand::failure(
                        "companyctl",
                        "services_status",
                        Some(name.clone()),
                        "companyctl: service not found\n",
                    ),
                }
            }
            ("services", "restart" | "start" | "stop") => {
                let Some(name) = args.get(2) else {
                    return VirtualCommand::failure(
                        "companyctl",
                        format!("services_{action}"),
                        None,
                        "companyctl: service name required\n",
                    );
                };
                if self.containers.contains_key(name.as_str()) {
                    self.set_container(name, action != "stop", fs, now).retag(
                        "companyctl",
                        format!("services_{action}"),
                        Some(name.clone()),
                    )
                } else if self.services.contains_key(name.as_str()) {
                    self.systemctl(&[action.into(), name.clone()], fs, now)
                        .retag(
                            "companyctl",
                            format!("services_{action}"),
                            Some(name.clone()),
                        )
                } else {
                    VirtualCommand::failure(
                        "companyctl",
                        format!("services_{action}"),
                        Some(name.clone()),
                        "companyctl: service not found\n",
                    )
                }
            }
            ("config", "list") => VirtualCommand::success(
                "companyctl",
                "config_list",
                None,
                "billing-api\t/etc/billing/config.toml\nproduction-env\t/srv/billing-api/.env\nssh-deploy\t/home/admin/.ssh/config\n",
            ),
            ("config", "get") => {
                let Some(name) = args.get(2) else {
                    return VirtualCommand::failure(
                        "companyctl",
                        "config_get",
                        None,
                        "companyctl: config name required\n",
                    );
                };
                let path = match name.as_str() {
                    "billing-api" => "/etc/billing/config.toml",
                    "production-env" => "/srv/billing-api/.env",
                    "ssh-deploy" => "/home/admin/.ssh/config",
                    _ => {
                        return VirtualCommand::failure(
                            "companyctl",
                            "config_get",
                            Some(name.clone()),
                            "companyctl: config not found\n",
                        );
                    }
                };
                match fs.read(path) {
                    Ok(data) => VirtualCommand::success(
                        "companyctl",
                        "config_get",
                        Some(name.clone()),
                        String::from_utf8_lossy(data),
                    )
                    .accessed("read", path),
                    Err(error) => virtual_fs_failure("companyctl", "config_get", path, error),
                }
            }
            ("backups", "list") => {
                let mut output =
                    "NAME                        CREATED               SIZE     STATUS\n"
                        .to_owned();
                for backup in &self.backups {
                    output.push_str(&format!(
                        "{:<27} 2026-10-11 02:17:04   {:>5} KiB ready\n",
                        backup.path.rsplit('/').next().unwrap_or(backup.path),
                        backup
                            .entries
                            .iter()
                            .map(|(_, content)| content.len())
                            .sum::<usize>()
                    ));
                }
                VirtualCommand::success("companyctl", "backups_list", None, output)
            }
            ("backups", "show") => {
                let Some(name) = args.get(2) else {
                    return VirtualCommand::failure(
                        "companyctl",
                        "backups_show",
                        None,
                        "companyctl: backup name required\n",
                    );
                };
                let Some(backup) = self
                    .backups
                    .iter()
                    .find(|backup| backup.path.contains(name.as_str()))
                else {
                    return VirtualCommand::failure(
                        "companyctl",
                        "backups_show",
                        Some(name.clone()),
                        "companyctl: backup not found\n",
                    );
                };
                VirtualCommand::success(
                    "companyctl",
                    "backups_show",
                    Some(name.clone()),
                    format!(
                        "name: {name}\npath: {}\nfiles: {}\nstatus: verified\n",
                        backup.path,
                        backup.entries.len()
                    ),
                )
                .accessed("read", backup.path)
            }
            ("backups", "restore") => {
                let Some(name) = args.get(2) else {
                    return VirtualCommand::failure(
                        "companyctl",
                        "backups_restore",
                        None,
                        "companyctl: backup name required\n",
                    );
                };
                let Some(path) = self
                    .backups
                    .iter()
                    .find(|backup| backup.path.contains(name.as_str()))
                    .map(|backup| backup.path.to_owned())
                else {
                    return VirtualCommand::failure(
                        "companyctl",
                        "backups_restore",
                        Some(name.clone()),
                        "companyctl: backup not found\n",
                    );
                };
                let archive_command = if path.ends_with(".zip") {
                    "unzip"
                } else {
                    "tar"
                };
                self.archive(
                    archive_command,
                    &[path, "-C".into(), cwd.into()],
                    cwd,
                    fs,
                    now,
                )
                .retag("companyctl", "backups_restore", Some(name.clone()))
            }
            _ => VirtualCommand::failure(
                "companyctl",
                format!("{area}_{action}"),
                None,
                format!(
                    "companyctl: unknown command '{area} {action}'\nRun 'companyctl --help' for usage.\n"
                ),
            ),
        }
    }

    fn virtual_service_running(&self, name: &str) -> Option<bool> {
        if self.distribution == Distribution::Debian && name == "postgresql" {
            return Some(self.service_running("postgresql@17-main"));
        }
        self.containers
            .get(name)
            .map(|container| container.running)
            .or_else(|| {
                self.services
                    .contains_key(name)
                    .then(|| self.service_running(name))
            })
    }

    /// A stopped (SIGSTOP) process still exists and keeps its unit active.
    /// A unit is no longer running once its main PID has exited or vanished.
    fn service_running(&self, name: &str) -> bool {
        if self.distribution == Distribution::Debian && name == "postgresql" {
            return self.service_running("postgresql@17-main");
        }
        self.services
            .get(name)
            .is_some_and(|service| service.active && self.processes.contains_key(&service.pid))
    }

    fn sync_cron(&self, fs: &mut VirtualFileSystem, now: DateTime<Utc>) {
        ensure_dir(fs, "/var/spool", now);
        ensure_dir(fs, "/var/spool/cron", now);
        fs.put_file(
            &format!("/var/spool/cron/{}", self.username),
            format!("{}\n", self.cron.join("\n")),
            now,
        );
    }

    fn sync_authorized_keys(&self, fs: &mut VirtualFileSystem, now: DateTime<Utc>) {
        fs.put_file(
            &format!("{}/.ssh/authorized_keys", self.home),
            format!("{}\n", self.authorized_keys.join("\n")),
            now,
        );
    }

    pub(crate) fn sync_proc(&self, fs: &mut VirtualFileSystem, now: DateTime<Utc>) {
        ensure_dir(fs, "/proc/net", now);
        ensure_dir(fs, "/proc/sys/kernel", now);
        fs.put_file("/proc/sys/kernel/ostype", "Linux\n", now);
        fs.put_file(
            "/proc/sys/kernel/osrelease",
            format!("{}\n", fs.distribution().kernel_release()),
            now,
        );
        fs.put_file("/proc/meminfo", "MemTotal:        4024320 kB\nMemFree:         1151181 kB\nMemAvailable:    3162010 kB\nBuffers:          188416 kB\nCached:          1822413 kB\nSwapCached:            0 kB\nActive:          2941012 kB\nInactive:        1024400 kB\nSwapTotal:       2097148 kB\nSwapFree:        2097148 kB\n", now);
        let cpu_flags = "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx lm constant_tsc rep_good nopl xtopology cpuid tsc_known_freq pni ssse3 fma cx16 sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch invpcid_single pti ssbd ibrs ibpb stibp fsgsbase bmi1 avx2 smep bmi2 erms invpcid rdseed adx smap clflushopt xsaveopt xsavec xgetbv1 xsaves";
        let cpuinfo = (0..4)
            .map(|processor| {
                format!(
                    "processor : {processor}\nvendor_id : GenuineIntel\ncpu family : 6\nmodel : 106\nmodel name : Intel(R) Xeon(R) Platinum 8370C CPU @ 2.80GHz\nstepping : 6\nmicrocode : 0xffffffff\ncpu MHz : 2800.000\ncache size : 49152 KB\nphysical id : 0\ncore id : {processor}\ncpu cores : 4\nflags : {cpu_flags}\n"
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let cpu_count = cpuinfo
            .lines()
            .filter(|line| line.starts_with("processor : "))
            .count()
            .max(1);
        fs.put_file("/proc/cpuinfo", cpuinfo, now);
        fs.put_file(
            "/proc/mounts",
            "/dev/sda1 / ext4 rw,relatime 0 0\ntmpfs /dev tmpfs rw,nosuid,relatime,size=2048000k,nr_inodes=512000 0 0\ntmpfs /run tmpfs rw,nosuid,nodev,size=819200k,nr_inodes=512000 0 0\ntmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n",
            now,
        );
        fs.put_file(
            "/proc/net/route",
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t00000000\t0104140A\t0003\t0\t0\t100\t00000000\t0\t0\t0\neth0\t0004140A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\ndocker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n",
            now,
        );
        fs.put_file(
            "/proc/net/dev",
            "Inter-| Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo:  843200     820    0    0    0     0          0         0   843200     820    0    0    0     0       0          0\n  eth0: 45821904  68421    0    1    0     0          0         0 28741902   52108    0    0    0     0       0          0\ndocker0:        0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n",
            now,
        );
        let active_pids = self
            .processes
            .keys()
            .copied()
            .chain(
                self.virtual_processes
                    .iter()
                    .enumerate()
                    .filter(|(_, process)| process.running)
                    .map(|(index, _)| 4000 + index as u32),
            )
            .collect::<std::collections::BTreeSet<_>>();
        let stale_pids = fs
            .list("/proc")
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(name, node)| {
                (node.is_dir()
                    && name
                        .parse::<u32>()
                        .ok()
                        .is_some_and(|pid| !active_pids.contains(&pid)))
                .then_some(name)
            })
            .collect::<Vec<_>>();
        for pid in stale_pids {
            let _ = fs.remove(&format!("/proc/{pid}"), true);
        }
        for process in self.processes.values() {
            let dir = format!("/proc/{}", process.pid);
            ensure_dir(fs, &dir, now);
            let parent_pid = process_parent(process.pid);
            let process_name = process
                .command
                .split_whitespace()
                .next()
                .unwrap_or("process")
                .rsplit('/')
                .next()
                .unwrap_or("process");
            let (process_uid, process_gid) = process_uid_gid(self.distribution, process.user);
            let uid = format!("{process_uid}\t{process_uid}\t{process_uid}\t{process_uid}");
            let gid = format!("{process_gid}\t{process_gid}\t{process_gid}\t{process_gid}");
            let groups = if process.user == "admin" { "4\t27" } else { "" };
            let voluntary_switches = process.pid.wrapping_mul(17) % 5000 + 120;
            let involuntary_switches = process.pid.wrapping_mul(7) % 1000 + 10;
            let vm_size = process.rss_kib.saturating_mul(4);
            let vm_peak = vm_size;
            let vm_hwm = process.rss_kib;
            let rss_anon = process.rss_kib.saturating_mul(3) / 4;
            let rss_file = process.rss_kib / 4;
            let vm_data = process.rss_kib.saturating_mul(2);
            let vm_lib = process.rss_kib / 8;
            let pid = process.pid;
            let state = process.state.description();
            fs.put_file(
                &format!("{dir}/status"),
                format!(
                    "Name:\t{process_name}\nUmask:\t0022\nState:\t{state}\nTgid:\t{pid}\nNgid:\t0\nPid:\t{pid}\nPPid:\t{parent_pid}\nTracerPid:\t0\nUid:\t{uid}\nGid:\t{gid}\nFDSize:\t64\nGroups:\t{groups}\nNStgid:\t{pid}\nNSpid:\t{pid}\nNSpgid:\t{pid}\nNSsid:\t{pid}\nThreads:\t1\nSigQ:\t0/15384\nSigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\nSigBlk:\t0000000000000000\nSigIgn:\t0000000000000000\nSigCgt:\t0000000000000000\nCapInh:\t0000000000000000\nCapPrm:\t0000003fffffffff\nCapEff:\t0000003fffffffff\nCapBnd:\t0000003fffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\nSeccomp:\t0\nSpeculation_Store_Bypass:\tthread vulnerable\nCpus_allowed:\t0000000f\nCpus_allowed_list:\t0-3\nMems_allowed:\t00000000,00000001\nMems_allowed_list:\t0\nvoluntary_ctxt_switches:\t{voluntary_switches}\nnonvoluntary_ctxt_switches:\t{involuntary_switches}\nVmPeak:\t{vm_peak} kB\nVmSize:\t{vm_size} kB\nVmLck:\t       0 kB\nVmPin:\t       0 kB\nVmHWM:\t{vm_hwm} kB\nVmRSS:\t{} kB\nRssAnon:\t{rss_anon} kB\nRssFile:\t{rss_file} kB\nRssShmem:\t       0 kB\nVmData:\t{vm_data} kB\nVmStk:\t     132 kB\nVmExe:\t       8 kB\nVmLib:\t{vm_lib} kB\nVmPTE:\t      48 kB\nVmSwap:\t       0 kB\n",
                    process.rss_kib,
                ),
                now,
            );
            fs.put_file(
                &format!("{dir}/cmdline"),
                process.command.replace(' ', "\0"),
                now,
            );
            let executable = if process.command == "-bash" {
                "/usr/bin/bash"
            } else if process.command.starts_with("nginx:") {
                if self.distribution == Distribution::Arch {
                    "/usr/bin/nginx"
                } else {
                    "/usr/sbin/nginx"
                }
            } else if process.command.contains("redis-server") {
                "/usr/bin/redis-server"
            } else {
                process
                    .command
                    .split_whitespace()
                    .next()
                    .filter(|value| value.starts_with('/'))
                    .unwrap_or("/usr/bin/systemd")
            };
            if !process.command.contains("redis-server")
                && (self.distribution != Distribution::Arch || fs.exists(executable))
            {
                ensure_executable(fs, executable, now);
            }
            fs.put_symlink(&format!("{dir}/exe"), executable, now);
            let cgroup = self
                .containers
                .values()
                .find(|container| container.running && container.pid == Some(process.pid))
                .map_or_else(
                    || {
                        format!(
                            "0::/system.slice/{}.service\n",
                            match process.pid {
                                1 => "init",
                                512 if self.distribution == Distribution::Arch =>
                                    "systemd-resolved",
                                542 if self.distribution == Distribution::Arch => "dbus-broker",
                                593 if self.distribution == Distribution::Arch => "cronie",
                                684 if self.distribution == Distribution::Arch => "sshd",
                                684 => "ssh",
                                721 if self.distribution == Distribution::Debian => {
                                    "postgresql@17-main"
                                }
                                721 => "postgresql",
                                901 => "docker",
                                1312 => "getty@tty1",
                                30000..=30099 => "docker",
                                _ => "user@1000",
                            }
                        )
                    },
                    |container| format!("0::/system.slice/docker-{}.scope\n", container.id),
                );
            fs.put_file(&format!("{dir}/cgroup"), cgroup, now);
        }
        for (index, process) in self.virtual_processes.iter().enumerate() {
            let pid = 4000 + index as u32;
            let dir = format!("/proc/{pid}");
            if !process.running {
                let _ = fs.remove(&dir, true);
                continue;
            }
            ensure_dir(fs, &dir, now);
            fs.put_file(
                &format!("{dir}/status"),
                format!("Name:\t{}\nState:\tS (sleeping)\nPid:\t{pid}\nUid:\t1000\t1000\t1000\t1000\nVmRSS:\t2048 kB\n", process.name),
                now,
            );
            fs.put_file(
                &format!("{dir}/cmdline"),
                process.command.replace(' ', "\0"),
                now,
            );
            let executable = process
                .command
                .split_whitespace()
                .next()
                .filter(|value| value.starts_with('/'))
                .unwrap_or("/usr/bin/worker");
            ensure_executable(fs, executable, now);
            fs.put_symlink(&format!("{dir}/exe"), executable, now);
            fs.put_file(
                &format!("{dir}/cgroup"),
                format!("0::/system.slice/{}.service\n", process.name),
                now,
            );
        }
        let uptime_seconds = now
            .signed_duration_since(self.booted_at)
            .num_milliseconds()
            .max(0) as f64
            / 1000.0;
        let idle_seconds = uptime_seconds * cpu_count as f64 * 0.994;
        fs.put_file(
            "/proc/uptime",
            format!("{uptime_seconds:.2} {idle_seconds:.2}\n"),
            now,
        );
        fs.put_file(
            "/proc/loadavg",
            format!(
                "0.08 0.04 0.01 1/{} {}\n",
                self.processes.len()
                    + self
                        .virtual_processes
                        .iter()
                        .filter(|process| process.running)
                        .count(),
                self.processes.keys().next_back().copied().unwrap_or(1312) + 1
            ),
            now,
        );
        let total_ticks = (uptime_seconds * cpu_count as f64 * 100.0) as u64;
        let idle_ticks = (idle_seconds * 100.0) as u64;
        let user_ticks = total_ticks / 500;
        let nice_ticks = total_ticks / 2_000;
        let system_ticks = total_ticks / 300;
        let iowait_ticks = total_ticks / 10_000;
        let cpu_line = format!(
            "{user_ticks} {nice_ticks} {system_ticks} {idle_ticks} {iowait_ticks} 0 0 0 0 0"
        );
        let per_cpu_line = format!(
            "{} {} {} {} {} 0 0 0 0 0",
            user_ticks / cpu_count as u64,
            nice_ticks / cpu_count as u64,
            system_ticks / cpu_count as u64,
            idle_ticks / cpu_count as u64,
            iowait_ticks / cpu_count as u64,
        );
        let mut stat = format!("cpu {cpu_line}\n");
        for cpu in 0..cpu_count {
            stat.push_str(&format!("cpu{cpu} {per_cpu_line}\n"));
        }
        let boot_time = self.booted_at.timestamp();
        stat.push_str(&format!(
            "intr {}\nctxt {}\nbtime {boot_time}\nprocesses {}\nprocs_running 1\nprocs_blocked 0\n",
            total_ticks.saturating_mul(8),
            total_ticks.saturating_mul(3),
            self.processes.len() + self.virtual_processes.len()
        ));
        fs.put_file("/proc/stat", stat, now);
        fs.put_file(
            "/proc/version",
            format!("{}\n", fs.distribution().proc_version()),
            now,
        );
        let mut tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n".to_owned();
        let mut slot = 0_u32;
        for service in self.services.values() {
            if service.active
                && let Some(port) = service.port
            {
                tcp.push_str(&proc_tcp_row(slot, service.address, port));
                slot = slot.saturating_add(1);
            }
        }
        for container in self.containers.values() {
            if container.running
                && let Some(port) = container.port
            {
                tcp.push_str(&proc_tcp_row(slot, "0.0.0.0", port));
                slot = slot.saturating_add(1);
            }
        }
        tcp.push_str(
            "  20: 1504140A:0016 2A7100CB:C8E8 01 00000000:00000000 00:00000000 00000000     0        0 300004\n",
        );
        fs.put_file("/proc/net/tcp", tcp, now);
    }
}

fn systemd_unit_file(distribution: Distribution, name: &str) -> String {
    let directory = distribution
        .linux_profile()
        .map_or("/lib/systemd/system", |profile| profile.systemd_unit_dir);
    let unit_name = if distribution == Distribution::Debian && name.starts_with("postgresql@") {
        "postgresql@"
    } else {
        name
    };
    format!("{directory}/{unit_name}.service")
}

fn service_command_for_profile(
    profile: Option<&'static crate::config::LinuxProfile>,
    name: &str,
) -> &'static str {
    match name {
        "postgresql-public" | "postgresql" | "postgresql@17-main" => profile
            .map_or("/usr/lib/postgresql/14/bin/postgres", |profile| {
                profile.postgres_command
            }),
        "ssh" | "sshd" => profile.map_or("/usr/sbin/sshd -D", |profile| profile.sshd_command),
        "cron" | "cronie" => profile.map_or("/usr/sbin/cron -f", |profile| profile.cron_command),
        "mysql" | "mariadb" => profile.map_or(
            "/usr/sbin/mysqld --defaults-file=/etc/mysql/mysql.conf.d/mysqld.cnf",
            |profile| profile.mysql_command,
        ),
        "redis-server" | "valkey" => profile
            .map_or("/usr/bin/redis-server /etc/redis/redis.conf", |profile| {
                profile.redis_process_command
            }),
        "nginx" => profile.map_or("nginx: master process /usr/sbin/nginx", |profile| {
            profile.nginx_master_command
        }),
        "vsftpd" | "vsftpd-data" => "/usr/sbin/vsftpd /etc/vsftpd.conf",
        "billing-api-http" => "/app/billing-api --config /app/config.toml",
        _ => "/usr/bin/systemd",
    }
}

/// Shared runtime transition API for Linux processes and their owning units.
/// STOP preserves the PID and active unit; exit removes the PID and marks the
/// owning unit/container inactive. Restart callers remove the old process and
/// register a fresh PID through this same registry.
fn apply_process_signal(
    processes: &mut BTreeMap<u32, Process>,
    services: &mut BTreeMap<&'static str, Service>,
    containers: &mut BTreeMap<&'static str, Container>,
    pid: u32,
    signal: ProcessSignal,
    now: DateTime<Utc>,
) {
    match signal {
        ProcessSignal::Stop | ProcessSignal::Continue => transition_process(processes, pid, signal),
        ProcessSignal::Exit => {
            transition_process(processes, pid, signal);
            for service in services.values_mut().filter(|service| service.pid == pid) {
                service.active = false;
                service.stopped_at = Some(now);
            }
            for container in containers
                .values_mut()
                .filter(|container| container.pid == Some(pid))
            {
                container.running = false;
            }
        }
    }
}

fn transition_service_process(
    processes: &mut BTreeMap<u32, Process>,
    service: &mut Service,
    pid: u32,
    signal: ProcessSignal,
    now: DateTime<Utc>,
) {
    transition_process(processes, pid, signal);
    if signal == ProcessSignal::Exit && service.pid == pid {
        service.active = false;
        service.stopped_at = Some(now);
    }
}

fn transition_process(processes: &mut BTreeMap<u32, Process>, pid: u32, signal: ProcessSignal) {
    match signal {
        ProcessSignal::Stop => {
            if let Some(process) = processes.get_mut(&pid) {
                process.state = ProcessState::Stopped;
            }
        }
        ProcessSignal::Continue => {
            if let Some(process) = processes.get_mut(&pid) {
                process.state = ProcessState::Sleeping;
            }
        }
        ProcessSignal::Exit => {
            processes.remove(&pid);
        }
    }
}

fn register_process(processes: &mut BTreeMap<u32, Process>, process: Process) {
    processes.insert(process.pid, process);
}

fn systemd_enabled_link(name: &str) -> String {
    format!("/etc/systemd/system/multi-user.target.wants/{name}.service")
}

fn systemd_unit_enabled(fs: &VirtualFileSystem, name: &str) -> bool {
    fs.exists(&systemd_enabled_link(name))
}

fn set_systemd_unit_enabled(
    fs: &mut VirtualFileSystem,
    distribution: Distribution,
    name: &str,
    enabled: bool,
    now: DateTime<Utc>,
) {
    let link = systemd_enabled_link(name);
    if enabled {
        let unit = systemd_unit_file(distribution, name);
        if !fs.exists(&unit) {
            let directory = unit
                .rsplit_once('/')
                .map_or("/lib/systemd/system", |(directory, _)| directory);
            ensure_dir(fs, directory, now);
            let command = service_command_for_profile(distribution.linux_profile(), name);
            fs.put_file(
                &unit,
                format!("[Unit]\nDescription={name} service\n[Service]\nExecStart={command}\n[Install]\nWantedBy=multi-user.target\n"),
                now,
            );
        }
        ensure_dir(fs, "/etc/systemd/system/multi-user.target.wants", now);
        fs.put_symlink(&link, &unit, now);
    } else if fs.exists(&link) {
        let _ = fs.remove(&link, false);
    }
}

fn ensure_dir(fs: &mut VirtualFileSystem, path: &str, now: DateTime<Utc>) {
    let mut current = String::new();
    for part in path.split('/').filter(|part| !part.is_empty()) {
        current.push('/');
        current.push_str(part);
        if !fs.exists(&current) {
            let _ = fs.mkdir(&current, now);
        }
    }
}

fn ensure_executable(fs: &mut VirtualFileSystem, path: &str, now: DateTime<Utc>) {
    if fs.exists(path) {
        return;
    }
    if let Some((parent, _)) = path.rsplit_once('/') {
        ensure_dir(fs, parent, now);
    }
    fs.put_file(
        path,
        format!("ELF 64-bit LSB executable, virtual process image for {path}\n"),
        now,
    );
    if let Ok(node) = fs.node_mut(path) {
        node.permissions = crate::filesystem::permissions::Permissions(0o755);
    }
}

fn docker_not_found(action: &str, target: &str) -> VirtualCommand {
    VirtualCommand::failure(
        "docker",
        format!("container_{action}"),
        Some(target.into()),
        format!("Error response from daemon: No such container: {target}\n"),
    )
}

fn docker_api_host(args: &[String]) -> Option<&str> {
    args.iter().enumerate().find_map(|(index, arg)| {
        arg.strip_prefix("--host=")
            .or_else(|| arg.strip_prefix("-H="))
            .or_else(|| {
                matches!(arg.as_str(), "-H" | "--host")
                    .then(|| args.get(index + 1).map(String::as_str))
                    .flatten()
            })
            .filter(|host| matches!(*host, "tcp://127.0.0.1:2375" | "tcp://localhost:2375"))
    })
}

fn virtual_fs_failure(
    bait: &'static str,
    action: &str,
    path: &str,
    error: FsError,
) -> VirtualCommand {
    VirtualCommand::failure(
        bait,
        action,
        Some(path.into()),
        format!("{action}: {path}: {error}\n"),
    )
}

fn key_fingerprint(key: &str) -> String {
    let checksum = key.bytes().fold(0_u64, |value, byte| {
        value.wrapping_mul(131).wrapping_add(u64::from(byte))
    });
    format!("SHA256:decoy{checksum:016x}")
}

fn state_word(running: bool) -> &'static str {
    if running { "healthy" } else { "stopped" }
}

fn proc_tcp_row(slot: u32, address: &str, port: u16) -> String {
    let encoded_address = match address {
        "127.0.0.1" => "0100007F",
        "10.20.4.12" => "0C04140A",
        _ => "00000000",
    };
    format!(
        " {slot:>3}: {encoded_address}:{port:04X} 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 10000{slot}\n"
    )
}

fn first_quoted_value(query: &str) -> Option<&str> {
    let start = query.find('\'')? + 1;
    let end = query[start..].find('\'')? + start;
    Some(&query[start..end])
}

fn value_after<'a>(input: &'a str, marker: &str) -> Option<&'a str> {
    let value = input
        .split_once(marker)?
        .1
        .trim()
        .trim_start_matches('=')
        .trim();
    value.split_whitespace().next()
}

fn git_show(reference: &str) -> Option<&'static str> {
    match reference {
        "HEAD" | "a8147d2" | "a8147d2ea41b59af027c64ef21dec0dec0dec001" => Some(
            "commit a8147d2ea41b59af027c64ef21dec0dec0dec001 (HEAD -> main, tag: v2.8.4)\nAuthor: Elena Volkova <elena@example.test>\nDate:   Sat Oct 11 19:22:04 2026 +0000\n\n    fix retry accounting for invoice worker\n\ndiff --git a/src/payments.rs b/src/payments.rs\nindex 7d81a22..e2a61c1 100644\n--- a/src/payments.rs\n+++ b/src/payments.rs\n@@ -41,2 +41,2 @@\n-    retries += 1;\n+    retries = retries.saturating_add(1);\n",
        ),
        "74d09b1" => Some(
            "commit 74d09b13f9a0dec0dec0dec0dec0dec0dec00002\nAuthor: Pavel Morozov <pavel@example.test>\nDate:   Fri Oct 10 14:08:51 2026 +0000\n\n    add refund feature flag\n",
        ),
        "21c3ee8" => Some(
            "commit 21c3ee8d000dec0dec0dec0dec0dec0dec000003\nAuthor: Elena Volkova <elena@example.test>\nDate:   Thu Oct 9 09:14:12 2026 +0000\n\n    rotate production database credentials\n",
        ),
        _ => None,
    }
}
