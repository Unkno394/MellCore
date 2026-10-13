use std::collections::BTreeMap;
use std::sync::OnceLock;

use chrono::{DateTime, Duration, Utc};

use crate::filesystem::{FsError, VirtualFileSystem};

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

#[derive(Clone, Debug)]
struct Process {
    pid: u32,
    user: &'static str,
    command: &'static str,
    state: ProcessState,
    rss_kib: u32,
}

#[derive(Clone, Debug)]
struct Service {
    description: &'static str,
    pid: u32,
    port: Option<u16>,
    address: &'static str,
    active: bool,
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
    processes: BTreeMap<u32, Process>,
    services: BTreeMap<&'static str, Service>,
    containers: BTreeMap<&'static str, Container>,
    cron: Vec<String>,
    authorized_keys: Vec<String>,
    git_baseline: BTreeMap<&'static str, &'static str>,
    db_users: Vec<DbUser>,
    db_audit: Vec<String>,
    backups: Vec<Backup>,
    booted_at: DateTime<Utc>,
}

impl VirtualServer {
    pub fn new(fs: &mut VirtualFileSystem, now: DateTime<Utc>) -> Self {
        static BOOTED_AT: OnceLock<DateTime<Utc>> = OnceLock::new();
        let booted_at = BOOTED_AT
            .get_or_init(|| now - Duration::days(17))
            .to_owned();
        let processes = [
            Process {
                pid: 1,
                user: "root",
                command: "/sbin/init",
                state: ProcessState::Sleeping,
                rss_kib: 11840,
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

        let services = BTreeMap::from([
            (
                "docker",
                Service {
                    description: "Docker Application Container Engine",
                    pid: 901,
                    port: None,
                    address: "",
                    active: true,
                },
            ),
            (
                "postgresql",
                Service {
                    description: "PostgreSQL RDBMS",
                    pid: 721,
                    port: Some(5432),
                    address: "10.20.4.12",
                    active: true,
                },
            ),
            (
                "ssh",
                Service {
                    description: "OpenBSD Secure Shell server",
                    pid: 684,
                    port: Some(22),
                    address: "0.0.0.0",
                    active: true,
                },
            ),
        ]);

        let containers = BTreeMap::from([
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
                    logs: "1:C 12 Oct 2026 07:40:58.011 # Redis is starting\n1:M 12 Oct 2026 07:40:58.012 * Ready to accept connections\n",
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

        let model = Self {
            processes,
            services,
            containers,
            cron,
            authorized_keys,
            git_baseline,
            db_users,
            db_audit: vec!["deploy completed for billing-api:2.8.4".into()],
            backups,
            booted_at,
        };
        model.seed_filesystem(fs, now);
        model
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
            "/home/admin/.bash_history",
            format!("{}\n", history.join("\n")),
            now,
        );
        if let Ok(node) = fs.node_mut("/home/admin/.bash_history") {
            node.permissions = crate::filesystem::permissions::Permissions(0o600);
        }
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
            "/home/admin/.ssh",
            "/root/.ssh",
            "/root/.aws",
            "/etc/billing",
            "/etc/systemd",
            "/etc/systemd/system",
            "/var/lib",
            "/var/lib/docker",
            "/var/lib/docker/volumes",
            "/opt",
            "/opt/companyctl",
        ] {
            ensure_dir(fs, path, now);
        }
        fs.put_file("/srv/billing-api/.env", "APP_ENV=production\nDATABASE_URL=postgres://billing_app:decoy-db-pass@db-internal:5432/billing\nREDIS_URL=redis://redis:6379/0\nJWT_SIGNING_KEY=decoy-jwt-signing-key-never-valid\n", now);
        fs.put_file("/srv/billing-api/.env.production", "SENTRY_DSN=https://decoy-public-key@errors.internal/42\nPAYMENTS_TOKEN=hf_decoy_payments_01J9Z8F2\n", now);
        fs.put_file("/home/admin/.ssh/id_deploy", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA-DECOY-KEY-NOT-VALID-AAAA\n-----END OPENSSH PRIVATE KEY-----\n", now);
        fs.put_file(
            "/home/admin/.ssh/authorized_keys",
            format!("{}\n", self.authorized_keys.join("\n")),
            now,
        );
        if let Ok(node) = fs.node_mut("/home/admin/.ssh/authorized_keys") {
            node.permissions = crate::filesystem::permissions::Permissions(0o600);
        }
        if let Ok(node) = fs.node_mut("/home/admin/.ssh") {
            node.permissions = crate::filesystem::permissions::Permissions(0o700);
        }
        if let Ok(node) = fs.node_mut("/home/admin/.ssh/id_deploy") {
            node.permissions = crate::filesystem::permissions::Permissions(0o600);
        }
        if let Ok(node) = fs.node_mut("/home/admin/.ssh/authorized_keys") {
            node.permissions = crate::filesystem::permissions::Permissions(0o600);
        }
        fs.put_file("/home/admin/.ssh/config", "Host db-internal\n    HostName 10.20.4.12\n    User deploy\n    IdentityFile ~/.ssh/id_deploy\n", now);
        fs.put_file("/root/.aws/credentials", "[production-readonly]\naws_access_key_id = AKIADECOY00000000000\naws_secret_access_key = decoySecretKeyMaterialNeverAccepted\n", now);
        fs.put_file("/etc/billing/config.toml", "environment = \"production\"\nregistry = \"registry.internal\"\nops_token = \"decoy-companyctl-token-4d18\"\n", now);
        for (name, service) in &self.services {
            fs.put_file(
                &format!("/etc/systemd/system/{name}.service"),
                format!(
                    "[Unit]\nDescription={}\nAfter=network.target\n\n[Service]\nExecStart=/usr/bin/{name}\nRestart=on-failure\n\n[Install]\nWantedBy=multi-user.target\n",
                    service.description
                ),
                now,
            );
        }
        fs.put_file("/srv/billing-api/compose.yml", "services:\n  api:\n    container_name: billing-api\n    image: registry.internal/billing-api:2.8.4\n    ports: [\"8080:8080\"]\n    depends_on: [redis]\n  worker:\n    container_name: billing-worker\n    image: registry.internal/billing-api:2.8.4\n    depends_on: [redis]\n  redis:\n    container_name: redis\n    image: redis:7.2-alpine\n    restart: unless-stopped\n", now);
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
        self.sync_cron(fs, now);
        self.sync_authorized_keys(fs, now);
        self.sync_proc(fs, now);
    }

    fn ps(&self, args: &[String]) -> VirtualCommand {
        let full = args
            .iter()
            .any(|arg| arg.contains('a') || arg.contains('e') || arg.contains('f'));
        let mut output = if full {
            "USER       PID %CPU %MEM STAT START   COMMAND\n".to_owned()
        } else {
            "  PID TTY          TIME CMD\n".to_owned()
        };
        for process in self.processes.values() {
            if full {
                output.push_str(&format!(
                    "{:<9} {:>5}  0.0  {:>3.1} {}    {}   {}\n",
                    process.user,
                    process.pid,
                    f64::from(process.rss_kib) / 40_000.0,
                    process.state.code(),
                    (self.booted_at + Duration::minutes(12)).format("%b%d"),
                    process.command
                ));
            } else if process.user == "admin" || process.pid == 1312 {
                output.push_str(&format!(
                    "{:>5} pts/0    00:00:00 {}\n",
                    process.pid,
                    process.command.trim_start_matches('-')
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
        let mut output = format!(
            "top - {} up {},  1 user,  load average: 0.08, 0.04, 0.01\nTasks: {:>3} total, {:>3} running, {:>3} sleeping, {:>3} stopped, {:>3} zombie\n%Cpu(s):  1.0 us,  0.3 sy, 98.7 id\nMiB Mem :   3930.0 total,   1124.2 free,    842.1 used,   1963.7 buff/cache\n\n  PID USER      S    RES COMMAND\n",
            now.format("%H:%M:%S"),
            format!("{} days", (now - self.booted_at).num_days().max(0)),
            self.processes.len(),
            running,
            sleeping,
            stopped,
            0
        );
        for process in self.processes.values() {
            output.push_str(&format!(
                "{:>5} {:<9} {} {:>6} {}\n",
                process.pid,
                process.user,
                process.state.code(),
                process.rss_kib,
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
        if !self.processes.contains_key(&pid) {
            return VirtualCommand::failure(
                "processes",
                "signal",
                Some(pid.to_string()),
                format!("kill: ({pid}) - No such process\n"),
            );
        }
        match signal.as_str() {
            "STOP" | "19" => {
                self.processes
                    .get_mut(&pid)
                    .expect("PID checked above")
                    .state = ProcessState::Stopped;
            }
            "CONT" | "18" => {
                self.processes
                    .get_mut(&pid)
                    .expect("PID checked above")
                    .state = ProcessState::Sleeping;
            }
            "TERM" | "15" | "KILL" | "9" | "INT" | "2" | "HUP" | "1" => {
                self.processes.remove(&pid);
                for service in self.services.values_mut() {
                    if service.pid == pid {
                        service.active = false;
                    }
                }
                for container in self.containers.values_mut() {
                    if container.pid == Some(pid) {
                        container.running = false;
                    }
                }
                let _ = fs.remove(&format!("/proc/{pid}"), true);
            }
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

    fn sockets(&self, command: &str, _args: &[String]) -> VirtualCommand {
        let mut rows = Vec::new();
        for (name, service) in &self.services {
            if service.active
                && let Some(port) = service.port
            {
                rows.push((service.address, port, service.pid, *name));
            }
        }
        for container in self.containers.values() {
            if container.running
                && let (Some(port), Some(pid)) = (container.port, container.pid)
            {
                rows.push(("0.0.0.0", port, pid, container.name));
            }
        }
        let output = if command == "ss" {
            let mut text =
                "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
                    .to_owned();
            for (address, port, pid, name) in rows {
                text.push_str(&format!("tcp   LISTEN 0      128    {address}:{port:<5}     0.0.0.0:*    users:((\"{name}\",pid={pid},fd=3))\n"));
            }
            text
        } else {
            let mut text = "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n".to_owned();
            for (address, port, pid, name) in rows {
                text.push_str(&format!("tcp        0      0 {address}:{port:<5}          0.0.0.0:*               LISTEN      {pid}/{name}\n"));
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
        if action == "list-units" || action == "list-unit-files" {
            let mut output =
                "UNIT                 LOAD   ACTIVE   SUB     DESCRIPTION\n".to_owned();
            for (name, service) in &self.services {
                let active = if service.active {
                    "active   running"
                } else {
                    "inactive dead   "
                };
                output.push_str(&format!(
                    "{name}.service{:width$} loaded {active} {}\n",
                    "",
                    service.description,
                    width = 21_usize.saturating_sub(name.len())
                ));
            }
            output.push_str("billing-backup.timer loaded active   waiting Daily billing backup\n");
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
        let Some(service) = self.services.get_mut(name) else {
            return VirtualCommand::failure(
                "persistence",
                format!("systemd_{action}"),
                Some(name.into()),
                format!("Unit {name}.service could not be found.\n"),
            );
        };
        if action == "is-active" {
            let mut result = VirtualCommand::success(
                "persistence",
                "systemd_is-active",
                Some(name.into()),
                format!("{}\n", if service.active { "active" } else { "inactive" }),
            );
            if !service.active {
                result.exit_status = 3;
                result.interaction.success = false;
            }
            return result;
        }
        let output = match action {
            "status" => {
                if service.active {
                    format!(
                        "● {name}.service - {}\n     Loaded: loaded (/lib/systemd/system/{name}.service; enabled)\n     Active: active (running) since {} UTC\n   Main PID: {} ({name})\n",
                        service.description,
                        (self.booted_at + Duration::minutes(12)).format("%a %Y-%m-%d %H:%M:%S"),
                        service.pid
                    )
                } else {
                    format!(
                        "○ {name}.service - {}\n     Loaded: loaded (/lib/systemd/system/{name}.service; enabled)\n     Active: inactive (dead) since Tue 2026-10-13 00:00:00 UTC\n",
                        service.description
                    )
                }
            }
            "start" | "restart" => {
                service.active = true;
                let process = match name {
                    "docker" => Process {
                        pid: 901,
                        user: "root",
                        command: "/usr/bin/dockerd -H fd://",
                        state: ProcessState::Sleeping,
                        rss_kib: 74600,
                    },
                    "postgresql" => Process {
                        pid: 721,
                        user: "postgres",
                        command: "/usr/lib/postgresql/14/bin/postgres",
                        state: ProcessState::Sleeping,
                        rss_kib: 42100,
                    },
                    "ssh" => Process {
                        pid: 684,
                        user: "root",
                        command: "/usr/sbin/sshd -D",
                        state: ProcessState::Sleeping,
                        rss_kib: 9260,
                    },
                    _ => unreachable!("service name came from the service map"),
                };
                self.processes.insert(service.pid, process);
                String::new()
            }
            "stop" => {
                service.active = false;
                self.processes.remove(&service.pid);
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
            "enable" | "disable" => String::new(),
            _ => {
                return VirtualCommand::failure(
                    "persistence",
                    format!("systemd_{action}"),
                    Some(name.into()),
                    format!("Unknown command verb {action}.\n"),
                );
            }
        };
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
                Some("admin".into()),
                format!("{}\n", self.authorized_keys.join("\n")),
            )
            .accessed("read", "/home/admin/.ssh/authorized_keys"),
            [single] if single == "list" => VirtualCommand::success(
                "persistence",
                "authorized_keys_list",
                Some("admin".into()),
                format!("{}\n", self.authorized_keys.join("\n")),
            )
            .accessed("read", "/home/admin/.ssh/authorized_keys"),
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
                .modified("write", "/home/admin/.ssh/authorized_keys")
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
                .modified("write", "/home/admin/.ssh/authorized_keys")
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
                    let ports = if container.running {
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
                let ports = if container.running {
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
        let operands: Vec<_> = args.iter().filter(|arg| !arg.starts_with('-')).collect();
        if operands.len() < 2 {
            return VirtualCommand::failure(
                "docker",
                "container_exec",
                None,
                "docker exec requires a container and command\n",
            );
        }
        let name = operands[0];
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
        let command = operands[1..]
            .iter()
            .map(|value| value.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let output = match command.as_str() {
            "ls /app" | "ls -la /app" | "ls -l /app" if container.name != "redis" => {
                "total 17420\ndrwxr-xr-x 1 root root     4096 Oct 12 07:40 .\ndrwxr-xr-x 1 root root     4096 Oct 12 07:40 ..\n-rwxr-xr-x 1 app  app  12492800 Oct 11 19:12 billing-api\n-rwxr-xr-x 1 app  app   5144576 Oct 11 19:12 billing-worker\n-rw-r--r-- 1 app  app      1024 Oct 12 07:39 config.toml\n".into()
            }
            "cat /app/config.toml" if container.name != "redis" => {
                "listen = \"0.0.0.0:8080\"\nredis_url = \"redis://redis:6379/0\"\nlog_level = \"info\"\n".into()
            }
            "env" | "printenv" if container.name == "redis" => {
                "REDIS_VERSION=7.2\nREDIS_PORT=6379\n".into()
            }
            "env" | "printenv" => {
                format!("APP_ENV=production\nHOSTNAME={}\nDATABASE_URL=postgres://billing_app:decoy-db-pass@db-internal:5432/billing\nREDIS_URL=redis://redis:6379/0\n", container.id)
            }
            "ps" | "ps aux" => {
                let process = if container.name == "billing-worker" {
                    "/app/billing-worker --queue invoices"
                } else if container.name == "redis" {
                    "redis-server *:6379"
                } else {
                    "/app/billing-api --config /app/config.toml"
                };
                let user = if container.name == "redis" { "redis" } else { "app" };
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
                let image_id = container.id.get(..12).unwrap_or(container.id);
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
                            container
                                .port
                                .map(|p| format!("0.0.0.0:{p}->{p}/tcp"))
                                .unwrap_or_default()
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
                "name: billing\nservices:\n  api:\n    container_name: billing-api\n    image: registry.internal/billing-api:2.8.4\n    depends_on:\n      - redis\n  worker:\n    container_name: billing-worker\n    image: registry.internal/billing-api:2.8.4\n    depends_on:\n      - redis\n  redis:\n    container_name: redis\n    image: redis:7.2-alpine\n    restart: unless-stopped\n",
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
                        user: "redis",
                        command: "redis-server *:6379",
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
                let postgres = self.services["postgresql"].active;
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
        self.containers
            .get(name)
            .map(|container| container.running)
            .or_else(|| self.services.get(name).map(|service| service.active))
    }

    fn sync_cron(&self, fs: &mut VirtualFileSystem, now: DateTime<Utc>) {
        ensure_dir(fs, "/var/spool", now);
        ensure_dir(fs, "/var/spool/cron", now);
        fs.put_file(
            "/var/spool/cron/admin",
            format!("{}\n", self.cron.join("\n")),
            now,
        );
    }

    fn sync_authorized_keys(&self, fs: &mut VirtualFileSystem, now: DateTime<Utc>) {
        fs.put_file(
            "/home/admin/.ssh/authorized_keys",
            format!("{}\n", self.authorized_keys.join("\n")),
            now,
        );
    }

    fn sync_proc(&self, fs: &mut VirtualFileSystem, now: DateTime<Utc>) {
        ensure_dir(fs, "/proc/net", now);
        for process in self.processes.values() {
            let dir = format!("/proc/{}", process.pid);
            ensure_dir(fs, &dir, now);
            fs.put_file(
                &format!("{dir}/status"),
                format!(
                    "Name:\t{}\nState:\t{}\nPid:\t{}\nUid:\t{}\nVmRSS:\t{} kB\n",
                    process
                        .command
                        .split_whitespace()
                        .next()
                        .unwrap_or("process")
                        .rsplit('/')
                        .next()
                        .unwrap_or("process"),
                    process.state.description(),
                    process.pid,
                    match process.user {
                        "root" => "0\t0\t0\t0",
                        "postgres" => "114\t114\t114\t114",
                        "redis" => "999\t999\t999\t999",
                        _ => "1000\t1000\t1000\t1000",
                    },
                    process.rss_kib
                ),
                now,
            );
            fs.put_file(
                &format!("{dir}/cmdline"),
                process.command.replace(' ', "\0"),
                now,
            );
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
                                684 => "ssh",
                                721 => "postgresql",
                                901 => "docker",
                                1312 => "getty@tty1",
                                _ => "user@1000",
                            }
                        )
                    },
                    |container| format!("0::/system.slice/docker-{}.scope\n", container.id),
                );
            fs.put_file(&format!("{dir}/cgroup"), cgroup, now);
        }
        let uptime_seconds = now
            .signed_duration_since(self.booted_at)
            .num_milliseconds()
            .max(0) as f64
            / 1000.0;
        fs.put_file(
            "/proc/uptime",
            format!("{uptime_seconds:.2} 5839142.44\n"),
            now,
        );
        fs.put_file(
            "/proc/version",
            "Linux version 5.15.0-119-generic (buildd@lcy02-amd64-118) #129-Ubuntu SMP\n",
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
        fs.put_file("/proc/net/tcp", tcp, now);
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

fn docker_not_found(action: &str, target: &str) -> VirtualCommand {
    VirtualCommand::failure(
        "docker",
        format!("container_{action}"),
        Some(target.into()),
        format!("Error response from daemon: No such container: {target}\n"),
    )
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
