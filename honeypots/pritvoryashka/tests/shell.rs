use chrono::{TimeZone, Utc};
use pritvoryashka::{
    filesystem::VirtualFileSystem,
    shell::{Shell, commands::SUPPORTED, parser},
};

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 11, 12, 0, 0).unwrap()
}

#[test]
fn parser_supports_quotes_but_rejects_host_shell_operators() {
    assert_eq!(
        parser::parse("echo 'hello world' \"again\"", 1024).unwrap(),
        ["echo", "hello world", "again"]
    );
    assert_eq!(
        parser::parse("echo \"$HOME\"", 1024).unwrap(),
        ["echo", "$HOME"]
    );
    for dangerous in [
        "cat /etc/passwd | sh",
        "echo x > /tmp/x",
        "pwd && id",
        "echo $(id)",
        "echo `id`",
        "pwd; id",
    ] {
        assert!(parser::parse(dangerous, 1024).is_err(), "{dangerous}");
    }
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
        "whoami",
        "id",
        "uname -a",
        "hostname",
        "date",
        "uptime",
        "ps",
        "top",
        "history",
        "mkdir /tmp/a",
        "touch /tmp/a/file",
        "cp /tmp/a/file /tmp/copy",
        "mv /tmp/copy /tmp/moved",
        "head /etc/passwd",
        "tail /etc/passwd",
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
