use chrono::{TimeZone, Utc};
use hf_core::{BaitConfig, BaitFile, BaitKind};
use pritvoryashka::{
    filesystem::VirtualFileSystem,
    shell::{Shell, commands::SUPPORTED, parser},
};
use uuid::Uuid;

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 11, 12, 0, 0).unwrap()
}

#[test]
fn configured_bait_is_a_real_virtual_file_and_records_only_opens() {
    let bait = BaitFile {
        id: Uuid::new_v4(),
        name: "Financial report".into(),
        path: Some("/home/admin/Documents/finance-2026.txt".into()),
        content: "Quarterly revenue: decoy\n".into(),
        kind: BaitKind::File,
        implementation: None,
        config: BaitConfig::default(),
    };
    let mut shell = Shell::with_baits("srv", 8192, now(), &[bait.clone()]);
    let bait_path = bait.path.as_deref().unwrap();
    assert!(shell.filesystem().exists(bait_path));
    assert!(
        shell
            .execute("ls /home/admin/Documents", now())
            .bait_opens
            .is_empty()
    );
    let opened = shell.execute("cat /home/admin/Documents/finance-2026.txt", now());
    assert_eq!(opened.output, bait.content);
    assert_eq!(opened.bait_opens.len(), 1);
    assert_eq!(opened.bait_opens[0].id, bait.id);
    assert_eq!(opened.bait_opens[0].operation, "read");

    let changed = BaitFile {
        content: "Updated decoy\n".into(),
        ..bait.clone()
    };
    let mut updated_shell = Shell::with_baits("srv", 8192, now(), &[changed]);
    assert_eq!(
        updated_shell
            .execute("cat /home/admin/Documents/finance-2026.txt", now())
            .output,
        "Updated decoy\n"
    );
    let removed_shell = Shell::with_baits("srv", 8192, now(), &[]);
    assert!(!removed_shell.filesystem().exists(bait_path));
}

#[test]
fn parser_supports_quotes_redirection_and_virtual_shell_operators() {
    assert_eq!(
        parser::parse("echo 'hello world' \"again\"", 1024).unwrap(),
        ["echo", "hello world", "again"]
    );
    assert_eq!(
        parser::parse("echo \"$HOME\"", 1024).unwrap(),
        ["echo", "$HOME"]
    );
    assert_eq!(
        parser::parse("pwd && id; echo x | grep x", 1024).unwrap(),
        ["pwd", "&&", "id", ";", "echo", "x", "|", "grep", "x"]
    );
    for dangerous in ["echo $(id)", "echo `id`", "pwd & id"] {
        assert!(parser::parse(dangerous, 1024).is_err(), "{dangerous}");
    }
    let mut quoted_shell = Shell::new("srv", 8192, now());
    assert_eq!(quoted_shell.execute("echo '|'", now()).output, "|\n");
    assert_eq!(quoted_shell.execute("echo '>'", now()).output, ">\n");
    assert_eq!(
        quoted_shell
            .execute("echo hello | grep hello", now())
            .output,
        "hello\n"
    );
    assert_eq!(
        quoted_shell.execute("echo yes && echo done", now()).output,
        "yes\ndone\n"
    );
    assert_eq!(
        parser::parse("echo x > /tmp/x", 1024).unwrap(),
        ["echo", "x", ">", "/tmp/x"]
    );
    assert!(parser::parse("echo 'unfinished", 1024).is_err());
}

#[test]
fn virtual_filesystem_normalizes_paths_without_escaping_root() {
    for (cwd, input, expected) in [
        (
            "/home/admin",
            "../admin/./README.txt",
            "/home/admin/README.txt",
        ),
        ("/", "../../etc/passwd", "/etc/passwd"),
        ("/var/log", "/tmp/x", "/tmp/x"),
    ] {
        assert_eq!(VirtualFileSystem::normalize(cwd, input).unwrap(), expected);
    }
    assert!(VirtualFileSystem::normalize("/", "bad\0path").is_err());
}

#[test]
fn supported_commands_are_simulated_and_never_delegated() {
    let mut shell = Shell::new("srv-app-01", 8192, now());
    let commands = [
        "pwd",
        "ls",
        "cd /tmp",
        "cat /etc/hostname",
        "echo hello",
        "echo hello > /tmp/redirected.txt",
        "echo world >> /tmp/redirected.txt",
        "cat /tmp/redirected.txt",
        "whoami",
        "id",
        "sudo -l",
        "uname -a",
        "hostname",
        "date",
        "uptime",
        "df -h",
        "free -h",
        "ps",
        "pgrep cron",
        "pidof cron",
        "top",
        "kill -STOP 1312",
        "ip addr",
        "ss -lntp",
        "netstat -lntp",
        "crontab -l",
        "systemctl status ssh",
        "authorized_keys list",
        "docker ps",
        "docker-compose ps",
        "cd /srv/billing-api",
        "git status",
        "psql -c '\\dt'",
        "tar -tzf /var/backups/billing-2026-10-11.tar.gz",
        "unzip -l /var/backups/ops-config-2026-10-10.zip",
        "zipinfo /var/backups/ops-config-2026-10-10.zip",
        "companyctl services list",
        "history",
        "mkdir /tmp/a",
        "touch /tmp/a/file",
        "cp /tmp/a/file /tmp/copy",
        "mv /tmp/copy /tmp/moved",
        "head /etc/passwd",
        "tail /etc/passwd",
        "du /etc/passwd",
        "grep root /etc/passwd",
        "find /tmp",
        "rm /tmp/moved",
        "clear",
    ];
    for command in commands {
        let result = shell.execute(command, now());
        assert!(!result.output.contains("command not found"), "{command}");
        assert_eq!(result.exit_status, 0, "{command}: {}", result.output);
    }
    let exit = shell.execute("exit", now());
    assert!(exit.close);
    for command in SUPPORTED {
        assert!(commands.iter().any(|line| line.starts_with(command)) || *command == "exit");
    }
}

#[test]
fn all_ten_baits_are_seeded_and_emit_interactions() {
    let mut shell = Shell::new("srv-app-01", 8192, now());
    let cases = [
        ("ps aux", "processes"),
        ("cat /srv/billing-api/.env", "secrets"),
        ("ss -lntp", "network"),
        ("crontab -l", "persistence"),
        ("docker ps", "docker"),
        ("cd /srv/billing-api", "filesystem-only"),
        ("git log --oneline", "git"),
        ("psql -c '\\dt'", "postgresql"),
        ("tar -tzf /var/backups/billing-2026-10-11.tar.gz", "backups"),
        ("history", "history-only"),
        ("companyctl services list", "companyctl"),
    ];
    for (command, expected_bait) in cases {
        let result = shell.execute(command, now());
        assert_eq!(result.exit_status, 0, "{command}: {}", result.output);
        if !expected_bait.ends_with("-only") {
            assert_eq!(result.virtual_interactions.len(), 1, "{command}");
            assert_eq!(
                result.virtual_interactions[0].bait, expected_bait,
                "{command}"
            );
        }
    }
    assert!(shell.filesystem().exists("/proc/721/status"));
    assert!(shell.filesystem().exists("/home/admin/.ssh/id_deploy"));
    assert!(shell.filesystem().exists("/home/admin/.bash_history"));
}

#[test]
fn process_container_and_network_state_stay_consistent() {
    let mut shell = Shell::new("srv", 8192, now());
    assert!(shell.execute("ss -lntp", now()).output.contains(":8080"));
    assert!(
        shell
            .execute("cat /proc/net/tcp", now())
            .output
            .contains(":1F90")
    );

    assert_eq!(
        shell.execute("docker stop billing-api", now()).exit_status,
        0
    );
    assert!(!shell.execute("ss -lntp", now()).output.contains(":8080"));
    assert!(
        !shell
            .execute("cat /proc/net/tcp", now())
            .output
            .contains(":1F90")
    );
    let ps = shell.execute("ps aux", now()).output;
    assert!(!ps.lines().any(|line| line.contains("1134")));
    assert!(!shell.filesystem().exists("/proc/1134"));
    assert_ne!(shell.execute("cat /proc/1134/status", now()).exit_status, 0);
    let inspect = shell.execute("docker inspect billing-api", now()).output;
    let inspect_json: serde_json::Value = serde_json::from_str(&inspect).unwrap();
    assert_eq!(inspect_json[0]["State"]["Running"], false);
    assert_eq!(inspect_json[0]["State"]["Pid"], 0);
    assert_eq!(
        inspect_json[0]["NetworkSettings"]["Ports"],
        serde_json::json!({})
    );
    assert!(inspect.contains("\"Running\": false"));
    assert!(inspect.contains("\"Pid\": 0"));
    assert!(inspect.contains("\"IPAddress\": \"\""));
    assert!(!inspect.contains("HostPort"));
    let stopped = shell.execute("docker ps -a", now()).output;
    let api = stopped
        .lines()
        .find(|line| line.split_whitespace().last() == Some("billing-api"))
        .unwrap();
    assert!(api.contains("Exited (0)"));
    assert!(!api.contains("8080"));
    let services = shell.execute("companyctl services list", now()).output;
    assert!(services.lines().any(|line| {
        line.starts_with("billing-api") && line.contains("stopped") && line.ends_with('-')
    }));

    assert_eq!(
        shell.execute("docker start billing-api", now()).exit_status,
        0
    );
    assert!(shell.execute("ss -lntp", now()).output.contains(":8080"));
    assert!(shell.execute("ps aux", now()).output.contains("1134"));
    assert!(shell.filesystem().exists("/proc/1134/status"));
    let inspect = shell.execute("docker inspect billing-api", now()).output;
    let inspect_json: serde_json::Value = serde_json::from_str(&inspect).unwrap();
    assert_eq!(inspect_json[0]["State"]["Running"], true);
    assert_eq!(inspect_json[0]["State"]["Pid"], 1134);
    assert_eq!(
        inspect_json[0]["NetworkSettings"]["IPAddress"],
        "172.18.0.3"
    );
    assert!(inspect.contains("\"Running\": true"));
    assert!(inspect.contains("\"Pid\": 1134"));
    assert!(inspect.contains("\"IPAddress\": \"172.18.0.3\""));

    assert_eq!(
        shell
            .execute("sudo systemctl stop postgresql", now())
            .exit_status,
        0
    );
    assert!(
        !shell
            .execute("netstat -lntp", now())
            .output
            .contains(":5432")
    );
    assert!(!shell.filesystem().exists("/proc/721"));
    assert!(!shell.execute("ps aux", now()).output.contains("721"));
    let status = shell.execute("systemctl status postgresql", now()).output;
    assert!(status.contains("inactive (dead)"));
    assert!(!status.contains("Main PID"));
    assert_eq!(
        shell
            .execute("systemctl is-active postgresql", now())
            .exit_status,
        3
    );
    assert_eq!(
        shell
            .execute("sudo systemctl start postgresql", now())
            .exit_status,
        0
    );
    assert!(shell.execute("ss -lntp", now()).output.contains(":5432"));
    assert!(shell.filesystem().exists("/proc/721/status"));

    assert_eq!(shell.execute("kill -STOP 1224", now()).exit_status, 0);
    assert!(
        shell
            .execute("ps aux", now())
            .output
            .lines()
            .any(|line| { line.contains("1224") && line.contains(" T ") })
    );
    assert!(shell.execute("ss -lntp", now()).output.contains(":6379"));
    assert_eq!(shell.execute("kill -CONT 1224", now()).exit_status, 0);
    assert_eq!(shell.execute("kill -KILL 1224", now()).exit_status, 0);
    let sockets_after_redis_exit = shell.execute("ss -lntp", now()).output;
    assert!(
        !sockets_after_redis_exit.contains(":6379"),
        "Redis socket remained after process exit: {sockets_after_redis_exit}\nservice status: {}",
        shell.execute("systemctl status redis-server", now()).output
    );
    assert!(!shell.execute("ps aux", now()).output.contains("1224"));
    assert!(!shell.filesystem().exists("/proc/1224"));
}

#[test]
fn companyctl_help_is_a_successful_command() {
    let mut shell = Shell::new("srv", 8192, now());
    for command in ["companyctl", "companyctl --help", "companyctl -h"] {
        let result = shell.execute(command, now());
        assert_eq!(result.exit_status, 0, "{command}: {}", result.output);
        assert!(result.output.contains("Usage: companyctl <command>"));
        assert!(result.output.contains("services"));
        assert_eq!(result.virtual_interactions[0].bait, "companyctl");
        assert_eq!(result.virtual_interactions[0].action, "help");
    }
    let scoped = shell.execute("companyctl services --help", now());
    assert_eq!(scoped.exit_status, 0);
    assert!(scoped.output.contains("companyctl services"));
}

#[test]
fn stopping_docker_daemon_terminates_containers_until_explicit_restart() {
    let mut shell = Shell::new("srv", 8192, now());
    assert_eq!(
        shell
            .execute("sudo systemctl stop docker", now())
            .exit_status,
        0
    );
    let ps = shell.execute("ps aux", now()).output;
    for pid in ["901", "1134", "1188"] {
        assert!(!ps.lines().any(|line| line.contains(pid)), "PID {pid}");
        assert!(!shell.filesystem().exists(&format!("/proc/{pid}")));
    }
    assert!(!shell.execute("ss -lntp", now()).output.contains(":8080"));
    let unavailable = shell.execute("docker ps", now());
    assert_ne!(unavailable.exit_status, 0);
    assert!(
        unavailable
            .output
            .contains("Cannot connect to the Docker daemon")
    );

    assert_eq!(
        shell
            .execute("sudo systemctl start docker", now())
            .exit_status,
        0
    );
    assert!(shell.filesystem().exists("/proc/901/status"));
    assert_eq!(shell.execute("docker ps", now()).exit_status, 0);
    assert!(
        !shell
            .execute("docker ps", now())
            .output
            .lines()
            .any(|line| { line.split_whitespace().last() == Some("billing-api") })
    );
    assert_eq!(
        shell.execute("docker start billing-api", now()).exit_status,
        0
    );
    assert!(shell.filesystem().exists("/proc/1134/status"));
    assert!(shell.execute("ss -lntp", now()).output.contains(":8080"));

    assert_eq!(
        shell
            .execute("docker start payments-migrate", now())
            .exit_status,
        0
    );
    assert!(
        !shell
            .execute("docker ps", now())
            .output
            .lines()
            .any(|line| { line.split_whitespace().last() == Some("payments-migrate") })
    );
    let migration = shell
        .execute("docker inspect payments-migrate", now())
        .output;
    let migration: serde_json::Value = serde_json::from_str(&migration).unwrap();
    assert_eq!(migration[0]["State"]["Running"], false);
    assert_eq!(migration[0]["State"]["Pid"], 0);
}

#[test]
fn persistence_changes_are_saved_in_virtual_files() {
    let mut shell = Shell::new("srv", 8192, now());
    assert_eq!(
        shell
            .execute("crontab add @reboot /tmp/.health-agent", now())
            .exit_status,
        0
    );
    assert!(
        shell
            .execute("crontab -l", now())
            .output
            .contains(".health-agent")
    );
    assert!(
        shell
            .execute("cat /var/spool/cron/admin", now())
            .output
            .contains(".health-agent")
    );

    let add = shell.execute(
        "authorized_keys add ssh-ed25519 AAAAC3NzaDecoyAttackerKey operator@host",
        now(),
    );
    assert_eq!(add.exit_status, 0, "{}", add.output);
    assert!(
        shell
            .execute("cat /home/admin/.ssh/authorized_keys", now())
            .output
            .contains("operator@host")
    );
}

#[test]
fn git_database_backups_and_company_cli_share_the_vfs_model() {
    let mut shell = Shell::new("srv", 8192, now());
    assert_eq!(shell.execute("cd /srv/billing-api", now()).exit_status, 0);
    assert!(
        shell
            .execute("git status", now())
            .output
            .contains("working tree clean")
    );
    assert_eq!(shell.execute("rm src/main.rs", now()).exit_status, 0);
    assert!(
        shell
            .execute("git status", now())
            .output
            .contains("deleted:   src/main.rs")
    );

    assert_eq!(
        shell
            .execute(
                "psql -c \"insert into audit_log (event) values ('manual probe')\"",
                now(),
            )
            .exit_status,
        0
    );
    assert!(
        shell
            .execute("psql -c 'select * from audit_log'", now())
            .output
            .contains("manual probe")
    );

    assert_eq!(shell.execute("mkdir /tmp/restore", now()).exit_status, 0);
    let extract = shell.execute(
        "unzip /var/backups/ops-config-2026-10-10.zip -d /tmp/restore",
        now(),
    );
    assert_eq!(extract.exit_status, 0, "{}", extract.output);
    assert!(shell.filesystem().exists("/tmp/restore/ops/hosts.ini"));
    assert!(
        shell
            .execute("companyctl config get production-env", now())
            .output
            .contains("DATABASE_URL")
    );
}

#[test]
fn mutable_bait_state_is_isolated_and_invalid_commands_are_bounded() {
    let mut first = Shell::new("srv", 8192, now());
    let mut second = Shell::new("srv", 8192, now());
    first.execute("docker stop billing-api", now());
    first.execute("crontab -r", now());
    assert!(
        !first
            .execute("docker ps", now())
            .output
            .lines()
            .any(|line| line.split_whitespace().last() == Some("billing-api"))
    );
    assert!(
        second
            .execute("docker ps", now())
            .output
            .contains("billing-api")
    );
    assert!(
        !first
            .execute("crontab -l", now())
            .output
            .contains("companyctl backups")
    );
    assert!(
        second
            .execute("crontab -l", now())
            .output
            .contains("companyctl backups")
    );

    for command in [
        "kill nope",
        "kill -NOPE 1312",
        "docker inspect missing",
        "sudo systemctl restart missing",
        "psql -c 'drop database billing'",
        "authorized_keys add invalid",
        "companyctl backups restore missing",
        "tar -xf /etc/passwd",
    ] {
        let result = first.execute(command, now());
        assert_ne!(result.exit_status, 0, "{command}");
        assert!(!result.output.is_empty(), "{command}");
        assert_eq!(result.virtual_interactions.len(), 1, "{command}");
        assert!(!result.virtual_interactions[0].success, "{command}");
    }
}

#[test]
fn session_filesystems_are_isolated() {
    let mut first = Shell::new("srv", 8192, now());
    let second = Shell::new("srv", 8192, now());
    assert_eq!(first.execute("touch /tmp/private", now()).exit_status, 0);
    assert!(first.filesystem().exists("/tmp/private"));
    assert!(!second.filesystem().exists("/tmp/private"));
}

#[test]
fn virtual_user_environment_expands_without_host_access() {
    let mut shell = Shell::new("srv", 8192, now());
    let result = shell.execute("echo $HOME $USER $HOSTNAME $SHELL $PWD", now());
    assert_eq!(
        result.output,
        "/home/admin admin srv /bin/bash /home/admin\n"
    );
}

#[test]
fn adaptive_deception_is_deterministic_and_tracks_depth() {
    let mut shell = Shell::new("srv", 8192, now());
    let first = shell.execute("ls /var/log", now());
    assert_eq!(first.deception.unwrap().to, 1);
    assert!(shell.filesystem().exists("/var/log/auth.log"));
    let second = shell.execute("cat /var/log/auth.log", now());
    assert_eq!(second.deception.unwrap().to, 2);
    assert!(shell.filesystem().exists("/var/backups/app.env.bak"));
    let third = shell.execute("cat /var/backups/app.env.bak", now());
    assert_eq!(third.deception.unwrap().to, 3);
    assert!(shell.filesystem().exists("/home/admin/.ssh/config"));
    let metrics = shell.metrics();
    assert_eq!(metrics.stages_reached, 3);
    assert_eq!(metrics.transitions, 3);
    assert!(metrics.unique_objects >= 3);
    assert!(shell.execute("ls /var/log", now()).deception.is_none());
}

#[test]
fn malformed_and_oversized_commands_fail_without_panicking() {
    let mut shell = Shell::new("srv", 16, now());
    assert_ne!(shell.execute("unknown-command", now()).exit_status, 0);
    assert_ne!(
        shell
            .execute("echo 12345678901234567890", now())
            .exit_status,
        0
    );
    assert_ne!(shell.execute("rm -r /", now()).exit_status, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_shells_keep_independent_state() {
    let tasks: Vec<_> = (0..32)
        .map(|index| {
            tokio::spawn(async move {
                let mut shell = Shell::new("srv", 8192, now());
                let path = format!("/tmp/session-{index}");
                assert_eq!(
                    shell.execute(&format!("touch {path}"), now()).exit_status,
                    0
                );
                assert!(shell.filesystem().exists(&path));
            })
        })
        .collect();
    for task in tasks {
        task.await.unwrap();
    }
}
