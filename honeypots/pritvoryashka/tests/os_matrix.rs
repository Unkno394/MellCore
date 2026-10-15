use chrono::{TimeZone, Utc};
use hf_core::{BaitConfig, BaitFile, BaitImplementation, BaitKind, VirtualAccountConfig};
use pritvoryashka::{
    config::Distribution,
    filesystem::{VirtualFileSystem, persistence::PersistentVirtualFileSystem},
    session::SessionState,
    shell::SessionShell,
};
use std::{
    fs,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 14, 12, 0, 0).unwrap()
}

fn shell(os: Distribution, baits: &[BaitFile], profiles: &[&str]) -> SessionShell {
    SessionShell::new_with_scenarios(
        "matrix-host",
        "admin",
        os,
        8192,
        baits,
        &[],
        &profiles
            .iter()
            .map(|profile| (*profile).to_owned())
            .collect::<Vec<_>>(),
    )
}

fn run(shell: &mut SessionShell, command: &str) -> String {
    let result = shell.execute(command, now());
    assert_eq!(result.exit_status, 0, "{command}: {}", result.output);
    result.output
}

#[test]
fn linux_profiles_keep_identity_commands_and_package_files_consistent() {
    for (os, marker, kernel, manager, absent) in [
        (
            Distribution::Ubuntu,
            "Ubuntu",
            "generic",
            "/usr/bin/apt",
            "/usr/bin/pacman",
        ),
        (
            Distribution::Debian,
            "Debian",
            "deb13",
            "/usr/bin/apt",
            "/usr/bin/pacman",
        ),
        (
            Distribution::Arch,
            "Arch",
            "arch",
            "/usr/bin/pacman",
            "/usr/bin/apt",
        ),
    ] {
        let mut guest = shell(os, &[], &[]);
        assert_eq!(run(&mut guest, "hostname").trim(), "matrix-host");
        assert_eq!(run(&mut guest, "whoami").trim(), "admin");
        assert!(run(&mut guest, "cat /etc/os-release").contains(marker));
        assert!(run(&mut guest, "cat /etc/issue").contains(marker));
        assert!(run(&mut guest, "uname -r").contains(kernel));
        assert!(
            guest.filesystem().exists(manager),
            "{} lacks {manager}",
            os.as_str()
        );
        assert!(
            !guest.filesystem().exists(absent),
            "{} exposes {absent}",
            os.as_str()
        );
        assert_eq!(
            run(
                &mut guest,
                &format!("which {}", manager.rsplit('/').next().unwrap())
            )
            .trim(),
            manager
        );
        assert_eq!(
            guest
                .execute(
                    &format!("which {}", absent.rsplit('/').next().unwrap()),
                    now()
                )
                .exit_status,
            1
        );
        assert!(guest.filesystem().exists("/bin/sh"));
        assert!(guest.filesystem().exists("/etc/shells"));
        assert!(guest.filesystem().exists("/etc/shadow"));
        assert!(run(&mut guest, "pwd").contains("/home/admin"));
        run(&mut guest, "echo matrix > /tmp/matrix.txt");
        assert_eq!(run(&mut guest, "cat /tmp/matrix.txt").trim(), "matrix");
        assert_ne!(guest.execute("cat /etc/shadow", now()).exit_status, 0);
        assert_ne!(
            guest.execute("touch /root/matrix.txt", now()).exit_status,
            0
        );
    }
}

#[test]
fn ubuntu_shell_commands_and_procfs_state_match_the_virtual_system() {
    let mut guest = shell(Distribution::Ubuntu, &[], &[]);

    assert_eq!(
        run(&mut guest, "for i in {1..5}; do echo number=$i; done"),
        "number=1\nnumber=2\nnumber=3\nnumber=4\nnumber=5\n"
    );
    assert_eq!(run(&mut guest, "hostname -I").trim(), "10.20.4.21");
    assert!(run(&mut guest, "ls --version").starts_with("ls (GNU coreutils) 8.32"));
    assert!(run(&mut guest, "getent hosts localhost").contains("127.0.0.1 localhost"));

    let find = run(&mut guest, "find /etc -maxdepth 1 -type f");
    assert!(find.lines().any(|path| path == "/etc/passwd"));
    assert!(!find.lines().any(|path| path == "/etc/apt"));
    assert!(run(&mut guest, "id nobody").contains("uid=65534(nobody) gid=65534(nogroup)"));

    let ps = run(&mut guest, "ps -eo pid,ppid,user,stat,etime,time,comm");
    assert!(ps.starts_with("PID PPID USER STAT ETIME TIME COMM\n"));
    assert!(ps.lines().any(|line| line.starts_with("2 0 root S ")));
    assert_eq!(
        run(&mut guest, "ps -p 2 -o pid,ppid,comm").trim(),
        "PID PPID COMM\n2 0 [kthreadd]"
    );
    assert!(run(&mut guest, "cat /proc/2/status").contains("PPid:\t0\n"));
    let init_status = run(&mut guest, "cat /proc/1/status");
    assert!(init_status.contains("Threads:\t1\n"));
    assert!(init_status.contains("VmSize:"));
    assert!(run(&mut guest, "cat /proc/stat").contains("cpu3 "));
    let proc_stat = run(&mut guest, "cat /proc/stat");
    let aggregate_cpu = proc_stat
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let per_cpu_sum = proc_stat
        .lines()
        .filter(|line| {
            line.starts_with("cpu") && line.chars().nth(3).is_some_and(|ch| ch.is_ascii_digit())
        })
        .map(|line| {
            line.split_whitespace()
                .nth(1)
                .unwrap()
                .parse::<u64>()
                .unwrap()
        })
        .sum::<u64>();
    assert!(aggregate_cpu >= per_cpu_sum && aggregate_cpu - per_cpu_sum < 4);
    assert!(run(&mut guest, "cat /proc/loadavg").contains("0.08 0.04 0.01"));
    assert!(run(&mut guest, "cat /proc/net/tcp").contains("1504140A:0016 2A7100CB:C8E8 01"));
    assert!(run(&mut guest, "ss -tan").contains("ESTAB"));
    assert!(!run(&mut guest, "ss -tuln").contains("ESTAB"));
    let uptime_before = run(&mut guest, "cat /proc/uptime");
    let uptime_after = guest
        .execute("cat /proc/uptime", now() + chrono::Duration::seconds(2))
        .output;
    let idle_before = uptime_before
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse::<f64>()
        .unwrap();
    let idle_after = uptime_after
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse::<f64>()
        .unwrap();
    assert!(idle_after > idle_before);

    assert_eq!(run(&mut guest, "nproc").trim(), "4");
    assert!(run(&mut guest, "lsblk").contains("sda1"));
    assert!(run(&mut guest, "service ssh status").contains("active (running)"));
    assert!(run(&mut guest, "who").contains("admin pts/0"));
    assert!(run(&mut guest, "w").contains("admin     pts/0"));
    assert_eq!(run(&mut guest, "users").trim(), "admin");
    assert!(run(&mut guest, "ping -c 2 127.0.0.1").contains("2 packets transmitted, 2 received"));
    assert!(run(&mut guest, "ip neigh").contains("10.20.4.1 dev eth0"));
    assert!(run(&mut guest, "lsb_release -a").contains("Codename:\tjammy"));
    assert!(run(&mut guest, "dpkg -s openssh-server").contains("Status: install ok installed"));
    assert_ne!(
        run(&mut guest, "du -sh /etc").split_whitespace().next(),
        Some("3K")
    );
    assert_ne!(
        run(&mut guest, "du -sh /var/log").split_whitespace().next(),
        Some("0K")
    );

    let sudo = guest.execute("sudo -n true", now());
    assert_ne!(sudo.exit_status, 0);
    assert!(sudo.output.contains("sudo: a password is required"));
    assert!(!sudo.output.contains("command not found"));
    let missing_rm = guest.execute("rm /tmp/mellcore-no-such-file", now());
    assert_ne!(missing_rm.exit_status, 0);
    assert!(missing_rm.output.contains("No such file or directory"));
}

#[test]
fn linux_distribution_profile_and_bash_package_version_are_consistent() {
    for (os, expected_manager, expected_bash, expected_package_version) in [
        (Distribution::Ubuntu, "apt", "5.1.16", "5.1-6ubuntu1.1"),
        (Distribution::Debian, "apt", "5.2.37", "5.2.37-2+b5"),
        (Distribution::Arch, "pacman", "5.3.20", "5.3.20-1"),
    ] {
        let profile = os.linux_profile().expect("Linux profile");
        assert_eq!(profile.distribution, os);
        assert_eq!(
            match profile.package_manager {
                pritvoryashka::config::PackageManager::Apt => "apt",
                pritvoryashka::config::PackageManager::Pacman => "pacman",
            },
            expected_manager
        );

        let mut guest = shell(os, &[], &[]);
        let output = run(&mut guest, "bash --version");
        assert!(output.contains(expected_bash), "{os:?}: {output}");
        match profile.package_manager {
            pritvoryashka::config::PackageManager::Apt => {
                let status = String::from_utf8_lossy(
                    guest.filesystem().read("/var/lib/dpkg/status").unwrap(),
                );
                let bash = status
                    .split("\n\n")
                    .find(|entry| {
                        entry.contains("Package: bash\n")
                            && entry.contains("Status: install ok installed\n")
                    })
                    .expect("Bash is installed in the apt profile");
                assert!(bash.contains(&format!("Version: {expected_package_version}")));
            }
            pritvoryashka::config::PackageManager::Pacman => {
                assert!(run(&mut guest, "pacman -Qi bash").contains(expected_package_version));
            }
        }
    }
}

#[test]
fn journald_process_and_systemd_unit_share_the_same_identity() {
    for os in [
        Distribution::Ubuntu,
        Distribution::Debian,
        Distribution::Arch,
    ] {
        let mut guest = shell(os, &[], &[]);
        let ps = run(&mut guest, "ps aux");
        assert!(
            ps.contains("362") && ps.contains("systemd-journald"),
            "{os:?}: {ps}"
        );

        let status = run(&mut guest, "systemctl status systemd-journald");
        assert!(status.contains("active (running)"), "{os:?}: {status}");
        assert!(status.contains("Main PID: 362"), "{os:?}: {status}");
        assert!(
            run(&mut guest, "systemctl list-units --type=service")
                .contains("systemd-journald.service")
        );
        assert!(
            run(
                &mut guest,
                "systemctl list-unit-files systemd-journald.service"
            )
            .contains("static")
        );
    }
}

#[test]
fn installed_coreutils_commands_are_present_and_executable_on_linux_profiles() {
    for os in [
        Distribution::Ubuntu,
        Distribution::Debian,
        Distribution::Arch,
    ] {
        let mut guest = shell(os, &[], &[]);
        let package = match os {
            Distribution::Arch => run(&mut guest, "pacman -Q coreutils"),
            _ => run(&mut guest, "dpkg -s coreutils"),
        };
        assert!(package.contains("coreutils"), "{os:?}: {package}");
        let package_files = match os {
            Distribution::Arch => run(&mut guest, "pacman -Ql coreutils"),
            _ => run(&mut guest, "dpkg -L coreutils"),
        };

        for (command, args) in [
            ("df", "-h"),
            ("du", "-sh /tmp"),
            ("sort", "/etc/os-release"),
            ("wc", "-l /etc/os-release"),
        ] {
            let path = format!("/usr/bin/{command}");
            assert!(guest.filesystem().is_executable(&path), "{os:?}: {path}");
            assert!(
                package_files.contains(&path),
                "{os:?}: package omits {path}"
            );
            assert_eq!(run(&mut guest, &format!("which {command}")).trim(), path);
            let output = guest.execute(&format!("{command} {args}"), now());
            assert_eq!(output.exit_status, 0, "{os:?} {command}: {}", output.output);
            assert!(!output.output.contains("command not found"));
        }
    }
}

#[test]
fn systemd_service_lifecycle_keeps_main_pid_and_process_table_consistent() {
    fn main_pid(status: &str) -> u32 {
        status
            .lines()
            .find_map(|line| line.trim().strip_prefix("Main PID:"))
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse().ok())
            .expect("active service status includes its main PID")
    }

    fn process_has_pid(ps: &str, pid: u32) -> bool {
        ps.lines().any(|line| {
            line.split_whitespace()
                .nth(1)
                .and_then(|value| value.parse::<u32>().ok())
                == Some(pid)
        })
    }

    for os in [
        Distribution::Ubuntu,
        Distribution::Debian,
        Distribution::Arch,
    ] {
        let service = if os == Distribution::Arch {
            "sshd"
        } else {
            "ssh"
        };
        let mut guest = shell(os, &[], &[]);

        run(&mut guest, &format!("systemctl start {service}"));
        let started = run(&mut guest, &format!("systemctl status {service}"));
        assert!(started.contains("active (running)"), "{os:?}: {started}");
        let initial_pid = main_pid(&started);
        assert!(process_has_pid(&run(&mut guest, "ps aux"), initial_pid));

        run(&mut guest, &format!("systemctl restart {service}"));
        let restarted = run(&mut guest, &format!("systemctl status {service}"));
        assert!(
            restarted.contains("active (running)"),
            "{os:?}: {restarted}\nprocesses: {}",
            run(&mut guest, "ps aux")
        );
        let restarted_pid = main_pid(&restarted);
        assert_ne!(
            restarted_pid, initial_pid,
            "restart must replace the main PID"
        );
        let ps_after_restart = run(&mut guest, "ps aux");
        assert!(process_has_pid(&ps_after_restart, restarted_pid));
        assert!(!process_has_pid(&ps_after_restart, initial_pid));

        run(&mut guest, &format!("systemctl stop {service}"));
        let stopped = run(&mut guest, &format!("systemctl status {service}"));
        assert!(stopped.contains("inactive (dead)"), "{os:?}: {stopped}");
        assert!(!process_has_pid(&run(&mut guest, "ps aux"), restarted_pid));

        run(&mut guest, &format!("systemctl restart {service}"));
        let active_again = run(&mut guest, &format!("systemctl status {service}"));
        assert!(
            active_again.contains("active (running)"),
            "{os:?}: {active_again}"
        );
        let final_pid = main_pid(&active_again);
        assert!(process_has_pid(&run(&mut guest, "ps aux"), final_pid));

        run(&mut guest, &format!("kill -STOP {final_pid}"));
        let process_stopped = run(&mut guest, &format!("systemctl status {service}"));
        assert!(
            process_stopped.contains("active (running)"),
            "{os:?}: {process_stopped}"
        );
        let stopped_ps = run(&mut guest, "ps aux");
        assert!(process_has_pid(&stopped_ps, final_pid));
        assert!(stopped_ps.lines().any(|line| {
            line.split_whitespace()
                .nth(1)
                .and_then(|pid| pid.parse::<u32>().ok())
                == Some(final_pid)
                && line.split_whitespace().any(|field| field.starts_with('T'))
        }));
        run(&mut guest, &format!("kill -CONT {final_pid}"));
        assert!(
            run(&mut guest, &format!("systemctl status {service}")).contains("active (running)")
        );

        run(&mut guest, &format!("kill -KILL {final_pid}"));
        let killed = run(&mut guest, &format!("systemctl status {service}"));
        assert!(killed.contains("inactive (dead)"), "{os:?}: {killed}");
        assert!(!process_has_pid(&run(&mut guest, "ps aux"), final_pid));
    }
}

#[test]
fn debian_release_registry_matches_installed_binaries_and_services() {
    let mut guest = shell(Distribution::Debian, &[], &[]);

    assert_eq!(run(&mut guest, "cat /etc/debian_version").trim(), "13.7");
    assert!(run(&mut guest, "cat /etc/dpkg/origins/debian").contains("Vendor: Debian"));
    let sources = run(&mut guest, "cat /etc/apt/sources.list.d/debian.sources");
    for expected in [
        "URIs: http://deb.debian.org/debian/",
        "Suites: trixie trixie-updates",
        "URIs: http://security.debian.org/debian-security/",
        "Suites: trixie-security",
        "Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg",
    ] {
        assert!(sources.contains(expected), "sources lack {expected}");
    }
    for path in ["/etc/debian_version", "/etc/dpkg/origins/debian"] {
        assert!(
            run(&mut guest, &format!("dpkg -S {path}")).contains(&format!("base-files: {path}")),
            "base-files does not own {path}"
        );
    }

    for (package, path) in [
        ("openssh-client", "/usr/bin/ssh"),
        ("openssh-server", "/usr/sbin/sshd"),
        ("openssh-sftp-server", "/usr/lib/openssh/sftp-server"),
        ("postgresql", "/usr/lib/postgresql/17/bin/postgres"),
        ("docker.io", "/usr/bin/dockerd"),
        ("containerd", "/usr/bin/containerd"),
        ("docker-compose", "/usr/bin/docker-compose"),
        ("dbus", "/usr/bin/dbus-daemon"),
        ("cron", "/usr/sbin/cron"),
    ] {
        let status = run(&mut guest, &format!("dpkg -s {package}"));
        assert!(
            status.contains("Status: install ok installed"),
            "{package} is not registered as installed: {status}"
        );
        assert!(
            guest.filesystem().is_executable(path),
            "{package} lacks executable {path}"
        );
        assert!(
            run(&mut guest, &format!("dpkg -L {package}"))
                .lines()
                .any(|line| line == path),
            "{package} file list omits {path}"
        );
        assert!(
            run(&mut guest, &format!("dpkg -S {path}")).contains(&format!("{package}: {path}")),
            "dpkg does not attribute {path} to {package}"
        );
    }

    assert_eq!(run(&mut guest, "which sshd").trim(), "/usr/sbin/sshd");
    for service in ["ssh", "postgresql", "docker", "cron"] {
        let status = run(&mut guest, &format!("systemctl status {service}"));
        if service == "postgresql" {
            assert!(status.contains("active (exited)"), "{service}: {status}");
            assert!(
                run(&mut guest, "systemctl status postgresql@17-main").contains("active (running)")
            );
        } else {
            assert!(status.contains("active (running)"), "{service}: {status}");
        }
    }
    let systemctl_version = run(&mut guest, "systemctl --version");
    assert!(systemctl_version.starts_with("systemd 257 (257.9-1~deb13u1)"));
    assert!(run(&mut guest, "systemctl status systemd-journald").contains("active (running)"));
    assert!(
        run(&mut guest, "systemctl list-units --type=service").contains("systemd-journald.service")
    );
    assert!(
        run(
            &mut guest,
            "systemctl list-unit-files systemd-journald.service"
        )
        .contains("static")
    );
    assert!(
        guest
            .filesystem()
            .exists("/usr/lib/systemd/system/systemd-journald.service")
    );
    assert!(
        run(&mut guest, "dpkg -L systemd")
            .lines()
            .any(|path| path == "/usr/lib/systemd/systemd-journald")
    );
    assert!(
        run(&mut guest, "dpkg -L systemd")
            .lines()
            .any(|path| path == "/usr/lib/systemd/system/systemd-journald.service")
    );
    for (package, command, expected) in [
        ("openssh-client", "ssh -V", "OpenSSH_10.0p1"),
        ("openssh-client", "ssh-keygen -V", "OpenSSH_10.0p1"),
        ("debianutils", "run-parts --version", "debianutils"),
        ("login", "nologin", "account is currently not available"),
        ("containerd", "containerd --version", "containerd"),
        ("docker.io", "dockerd --version", "Docker version"),
        ("dbus", "dbus-daemon --version", "D-Bus Message Bus Daemon"),
    ] {
        let listed = run(&mut guest, &format!("dpkg -l {package}"));
        assert!(listed.contains(package), "dpkg -l omitted {package}");
        let result = guest.execute(command, now());
        assert!(
            result.output.contains(expected),
            "{command} from installed package {package} did not run: {}",
            result.output
        );
    }
    for (package, unit) in [
        ("openssh-server", "/usr/lib/systemd/system/ssh.service"),
        ("postgresql", "/usr/lib/systemd/system/postgresql.service"),
        ("docker.io", "/usr/lib/systemd/system/docker.service"),
        ("cron", "/usr/lib/systemd/system/cron.service"),
    ] {
        assert!(guest.filesystem().exists(unit), "missing {unit}");
        assert!(
            run(&mut guest, &format!("dpkg -L {package}"))
                .lines()
                .any(|line| line == unit)
        );
        assert!(
            run(&mut guest, &format!("dpkg -S {unit}")).contains(&format!("{package}: {unit}"))
        );
    }

    run(&mut guest, "sudo apt remove postgresql");
    assert_ne!(guest.execute("which psql", now()).exit_status, 0);
    assert_ne!(
        guest
            .execute("systemctl status postgresql", now())
            .exit_status,
        0
    );
}

#[test]
fn windows_has_matching_virtual_users_files_and_scenarios() {
    let account = BaitFile {
        id: Uuid::new_v4(),
        name: "Backup user".into(),
        path: None,
        content: String::new(),
        kind: BaitKind::Account,
        implementation: Some(BaitImplementation::VirtualAccount),
        config: BaitConfig {
            account: Some(VirtualAccountConfig {
                login: "svc-backup".into(),
                uid: None,
                home_directory: Some("/C/Users/svc-backup".into()),
                shell: None,
            }),
            ..BaitConfig::default()
        },
    };
    let mut guest = shell(
        Distribution::Windows,
        &[account],
        &[
            "win_autologon_credentials",
            "win_always_install_elevated",
            "win_writable_service_binary",
            "win_guest_share",
        ],
    );
    let fs = guest.filesystem();
    for path in [
        "/C/Users/svc-backup",
        "/C/ProgramData/OpsBackup/backup.exe",
        "/C/ProgramData/PublicShare/README.txt",
        "/C/Windows/System32/msiexec.exe",
        "/Registry/HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Winlogon.txt",
        "/Registry/HKLM/SYSTEM/CurrentControlSet/Services/OpsBackup.txt",
    ] {
        assert!(fs.exists(path), "Windows guest lacks {path}");
    }
    let users = String::from_utf8_lossy(fs.read("/State/users.json").unwrap());
    assert!(users.contains("svc-backup"));

    assert_eq!(run(&mut guest, "hostname").trim(), "matrix-host");
    assert!(
        run(&mut guest, "whoami")
            .to_ascii_lowercase()
            .contains("admin")
    );
    assert!(run(&mut guest, "Get-LocalUser svc-backup").contains("svc-backup"));
    assert!(run(&mut guest, "net user").contains("svc-backup"));
    assert!(run(&mut guest, "sc.exe qc OpsBackup").contains("backup.exe"));
    assert!(run(&mut guest, "Get-Service OpsBackup").contains("OpsBackup"));
    assert!(run(&mut guest, "net share").contains("PublicShare"));
    assert!(run(&mut guest, "Get-SmbShare").contains("PublicShare"));
    assert!(
        run(&mut guest, "Get-Command msiexec.exe").contains("C:\\Windows\\System32\\msiexec.exe")
    );
    assert!(run(&mut guest, "Get-Acl C:\\ProgramData\\OpsBackup\\backup.exe").contains("Modify"));
    assert!(
        run(
            &mut guest,
            "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'"
        )
        .contains("DECOY-ONLY")
    );
    assert!(
        run(
            &mut guest,
            "Get-ItemProperty 'HKCU:\\Software\\Policies\\Microsoft\\Windows\\Installer'"
        )
        .contains("AlwaysInstallElevated")
    );
    run(
        &mut guest,
        "Set-Content C:\\ProgramData\\OpsBackup\\backup.exe -Value virtual",
    );
    assert!(
        run(
            &mut guest,
            "Get-Content C:\\ProgramData\\OpsBackup\\backup.exe"
        )
        .contains("virtual")
    );
}

#[test]
fn windows_powershell_core_commands_and_expressions_work() {
    pritvoryashka::shell::windows::check_parser().unwrap();
    let mut guest = shell(Distribution::Windows, &[], &[]);
    let assignment = run(
        &mut guest,
        "$testDir = Join-Path $env:TEMP \"honeyforge-test\"",
    );
    assert!(
        assignment.contains(r"C:\Users\admin\AppData\Local\Temp\honeyforge-test"),
        "Join-Path did not evaluate the assignment: {assignment}"
    );
    assert!(run(&mut guest, "Write-Host \"PowerShell 5.1\"").contains("PowerShell 5.1"));
    run(&mut guest, "New-Item -ItemType Directory -Path $testDir");
    run(
        &mut guest,
        "Set-Content -Path $testDir\\probe.txt -Value \"saved\"",
    );
    assert_eq!(
        run(&mut guest, "Get-Content $testDir\\probe.txt").trim(),
        "saved"
    );

    assert!(run(&mut guest, "Get-ExecutionPolicy").contains("RemoteSigned"));
    assert!(
        run(&mut guest, "Get-Module -ListAvailable").contains("Microsoft.PowerShell.Management")
    );
    assert!(run(&mut guest, "cmd /c ver").contains("10.0.20348"));
    assert!(
        run(
            &mut guest,
            "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\" /v ProductName"
        )
        .contains("Windows Server 2022 Standard")
    );
    assert!(run(&mut guest, "Get-Command Write-Host").contains("Write-Host"));
    assert!(run(&mut guest, "Get-Command reg.exe").contains("C:\\Windows\\System32\\reg.exe"));
    assert!(run(&mut guest, "Get-Item C:\\Windows\\System32\\cmd.exe").contains("289792"));

    let missing_service = guest.execute("Get-Service HoneyForgeMissingService", now());
    assert_ne!(missing_service.exit_status, 0);
    assert!(missing_service.output.contains("Cannot find any service"));
}

#[test]
fn windows_reported_powershell_paths_return_consistent_virtual_results() {
    let mut guest = shell(Distribution::Windows, &[], &[]);
    assert_eq!(
        run(&mut guest, "Write-Host \"Hello Windows\"").trim(),
        "Hello Windows"
    );
    assert!(run(&mut guest, "cmd /c ver").contains("10.0.20348"));
    assert!(run(&mut guest, "Get-ExecutionPolicy").contains("RemoteSigned"));
    assert!(run(&mut guest, "Get-ChildItem Env:").contains("USERNAME"));
    assert_eq!(run(&mut guest, "\"hello\".ToUpper()").trim(), "HELLO");

    let first_five = run(&mut guest, "Get-Process | Select-Object -First 5");
    assert!(
        first_five.contains("Name"),
        "pipeline returned no process objects: {first_five:?}"
    );
    let process_rows = ["System", "Registry", "smss", "csrss", "wininit", "services"]
        .iter()
        .filter(|name| {
            first_five
                .lines()
                .any(|line| line.split_whitespace().last() == Some(**name))
        })
        .count();
    assert_eq!(process_rows, 5, "Select-Object -First failed: {first_five}");
    let mut handle_counts = run(
        &mut guest,
        "Get-Process | Select-Object -ExpandProperty Handles",
    )
    .lines()
    .filter_map(|line| line.trim().parse::<u32>().ok())
    .collect::<Vec<_>>();
    handle_counts.sort_unstable();
    handle_counts.dedup();
    assert!(
        handle_counts.len() > 1,
        "process handle counts look templated"
    );

    let running = run(
        &mut guest,
        "Get-Service | Where-Object {$_.Status -eq 'Running'}",
    );
    assert!(running.contains("Running"));
    assert!(
        !running.contains("Stopped"),
        "Where-Object retained stopped services: {running}"
    );

    let missing_process = guest.execute("Get-Process -Name nonexistent123", now());
    assert_ne!(missing_process.exit_status, 0);
    assert!(missing_process.output.contains("Cannot find a process"));
    assert!(run(&mut guest, "route print").contains("IPv4 Route Table"));
    assert!(run(&mut guest, "arp -a").contains("Physical Address"));
    assert!(
        run(
            &mut guest,
            "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\" /v ProductName"
        )
        .contains("Windows Server 2022 Standard")
    );

    run(
        &mut guest,
        "Set-Content C:\\Users\\Public\\Documents\\probe.txt -Value writable",
    );
    assert_eq!(
        run(
            &mut guest,
            "Get-Content C:\\Users\\Public\\Documents\\probe.txt"
        )
        .trim(),
        "writable"
    );
    for (path, expected_size) in [
        ("C:\\Windows\\System32\\cmd.exe", 289_792),
        ("C:\\Windows\\System32\\hostname.exe", 45_056),
        ("C:\\Windows\\System32\\ipconfig.exe", 114_688),
    ] {
        let info = run(&mut guest, &format!("Get-Item '{path}'"));
        assert!(
            info.contains(&expected_size.to_string()),
            "implausible virtual PE size for {path}: {info}"
        );
    }
    let tasklist = run(&mut guest, "tasklist");
    assert!(
        tasklist
            .lines()
            .any(|line| line.contains("System") && line.contains("Services"))
    );
    assert!(
        tasklist
            .lines()
            .any(|line| line.contains("powershell.exe") && line.contains("Console"))
    );
    assert_ne!(
        guest
            .filesystem()
            .node("/C/Windows/System32/cmd.exe")
            .unwrap()
            .modified_at,
        guest
            .filesystem()
            .node("/C/Windows/System32/hostname.exe")
            .unwrap()
            .modified_at,
        "virtual Windows file timestamps should not all be identical"
    );
}

#[test]
fn windows_files_persist_between_ssh_session_states() {
    let directory = tempfile::tempdir().unwrap();
    let snapshot = directory.path().join("windows-vfs.json");
    let initial = VirtualFileSystem::windows("matrix-host", "admin", now());
    let persistent = Arc::new(Mutex::new(
        PersistentVirtualFileSystem::open(&snapshot, initial.clone()).unwrap(),
    ));

    let mut first_session = SessionState::with_persistent_environment_and_scenarios(
        "matrix-host",
        8192,
        &[],
        &[],
        persistent.clone(),
        "admin",
        Distribution::Windows,
        &[],
    );
    for command in [
        "$testDir = Join-Path $env:TEMP \"honeyforge-test\"",
        "New-Item -ItemType Directory -Path $testDir",
        "Set-Content -Path $testDir\\reconnect.txt -Value \"persisted across SSH\"",
    ] {
        let result = first_session.execute_command(command);
        assert_eq!(result.exit_status, 0, "{command}: {}", result.output);
    }
    drop(first_session);

    let mut reconnected_session = SessionState::with_persistent_environment_and_scenarios(
        "matrix-host",
        8192,
        &[],
        &[],
        persistent,
        "admin",
        Distribution::Windows,
        &[],
    );
    let result = reconnected_session.execute_command(
        "Get-Content C:\\Users\\admin\\AppData\\Local\\Temp\\honeyforge-test\\reconnect.txt",
    );
    assert_eq!(result.exit_status, 0, "{}", result.output);
    assert!(result.output.contains("persisted across SSH"));

    // A fresh service instance must read the same snapshot from disk too.
    let reopened = PersistentVirtualFileSystem::open(&snapshot, initial).unwrap();
    assert!(
        reopened
            .filesystem()
            .exists("/C/Users/admin/AppData/Local/Temp/honeyforge-test/reconnect.txt")
    );
}

#[test]
fn linux_virtual_filesystem_changes_persist_across_commands_and_sessions() {
    for distribution in [
        Distribution::Ubuntu,
        Distribution::Debian,
        Distribution::Arch,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let snapshot = directory.path().join("linux-vfs.json");
        let initial = shell(distribution, &[], &[]).filesystem().clone();
        let persistent = Arc::new(Mutex::new(
            PersistentVirtualFileSystem::open(&snapshot, initial.clone()).unwrap(),
        ));

        let mut first_session = SessionState::with_persistent_environment_and_scenarios(
            "matrix-host",
            8192,
            &[],
            &[],
            persistent,
            "admin",
            distribution,
            &[],
        );

        let snapshot_before_read = fs::read(&snapshot).unwrap();
        let whoami = first_session.execute_command("whoami");
        assert_eq!(whoami.exit_status, 0, "{distribution:?}: {}", whoami.output);
        assert_eq!(whoami.output.trim(), "admin");
        assert_eq!(
            fs::read(&snapshot).unwrap(),
            snapshot_before_read,
            "read-only commands must not rewrite the persisted snapshot ({distribution:?})"
        );

        for command in [
            "mkdir mellcore-test",
            "cd mellcore-test",
            "touch test.txt",
            "echo hello > test.txt",
            "echo world >> test.txt",
        ] {
            let result = first_session.execute_command(command);
            assert_eq!(
                result.exit_status, 0,
                "{distribution:?} {command}: {}",
                result.output
            );
            assert!(
                !result.output.contains("snapshot"),
                "{distribution:?} {command}: {}",
                result.output
            );
        }
        let contents = first_session.execute_command("cat test.txt");
        assert_eq!(contents.exit_status, 0, "{}", contents.output);
        assert_eq!(contents.output, "hello\nworld\n");
        first_session.finish_session();
        drop(first_session);

        let reopened = PersistentVirtualFileSystem::open(&snapshot, initial.clone()).unwrap();
        assert_eq!(
            String::from_utf8_lossy(
                reopened
                    .filesystem()
                    .read("/home/admin/mellcore-test/test.txt")
                    .unwrap()
            ),
            "hello\nworld\n",
            "file contents should survive a new persistent store ({distribution:?})"
        );
        let persistent = Arc::new(Mutex::new(reopened));
        let mut second_session = SessionState::with_persistent_environment_and_scenarios(
            "matrix-host",
            8192,
            &[],
            &[],
            persistent,
            "admin",
            distribution,
            &[],
        );
        let read_after_reconnect =
            second_session.execute_command("cat /home/admin/mellcore-test/test.txt");
        assert_eq!(
            read_after_reconnect.exit_status, 0,
            "{}",
            read_after_reconnect.output
        );
        assert_eq!(read_after_reconnect.output, "hello\nworld\n");

        let removed = second_session.execute_command("rm /home/admin/mellcore-test/test.txt");
        assert_eq!(removed.exit_status, 0, "{}", removed.output);
        second_session.finish_session();
        drop(second_session);

        let reopened = PersistentVirtualFileSystem::open(&snapshot, initial).unwrap();
        assert!(
            !reopened
                .filesystem()
                .exists("/home/admin/mellcore-test/test.txt"),
            "removed files must stay removed after reconnect ({distribution:?})"
        );
    }
}

#[test]
fn file_bait_read_is_attributed_to_the_same_bait_on_each_os() {
    for os in [
        Distribution::Ubuntu,
        Distribution::Debian,
        Distribution::Arch,
        Distribution::Windows,
    ] {
        let windows = os == Distribution::Windows;
        let path = if windows {
            "/C/Users/Public/Documents/report.txt"
        } else {
            "/home/admin/report.txt"
        };
        let bait = BaitFile {
            id: Uuid::new_v4(),
            name: "Report".into(),
            path: Some(path.into()),
            content: "DECOY-MATRIX\n".into(),
            kind: BaitKind::File,
            implementation: Some(BaitImplementation::VirtualFile),
            config: BaitConfig::default(),
        };
        let mut guest = shell(os, &[bait.clone()], &[]);
        assert_eq!(guest.filesystem().read(path).unwrap(), b"DECOY-MATRIX\n");
        let command = if windows {
            "Get-Content C:\\Users\\Public\\Documents\\report.txt"
        } else {
            "cat /home/admin/report.txt"
        };
        let result = guest.execute(command, now());
        assert_eq!(result.exit_status, 0, "{}: {}", os.as_str(), result.output);
        assert!(result.output.contains("DECOY-MATRIX"));
        assert!(
            result.bait_opens.iter().any(|open| open.id == bait.id),
            "{} did not attribute read",
            os.as_str()
        );
    }
}

#[test]
fn common_investigation_steps_have_consistent_virtual_effects() {
    for os in [
        Distribution::Ubuntu,
        Distribution::Debian,
        Distribution::Arch,
        Distribution::Windows,
    ] {
        let mut guest = shell(os, &[], &[]);
        let windows = os == Distribution::Windows;
        let (identity, processes, services, network, write, read, path) = if windows {
            (
                "whoami",
                "Get-Process",
                "Get-Service",
                "netstat -ano",
                "Set-Content C:\\Users\\admin\\matrix.txt -Value matrix",
                "Get-Content C:\\Users\\admin\\matrix.txt",
                "/C/Users/admin/matrix.txt",
            )
        } else {
            (
                "whoami",
                "ps",
                "systemctl list-units",
                "ss -lnt",
                "echo matrix > /home/admin/matrix.txt",
                "cat /home/admin/matrix.txt",
                "/home/admin/matrix.txt",
            )
        };
        assert!(
            run(&mut guest, identity)
                .to_ascii_lowercase()
                .contains("admin")
        );
        assert!(
            !run(&mut guest, processes).trim().is_empty(),
            "{} processes",
            os.as_str()
        );
        assert!(
            !run(&mut guest, services).trim().is_empty(),
            "{} services",
            os.as_str()
        );
        assert!(
            !run(&mut guest, network).trim().is_empty(),
            "{} network",
            os.as_str()
        );
        run(&mut guest, write);
        assert!(guest.filesystem().exists(path));
        assert!(run(&mut guest, read).contains("matrix"));
    }
}

#[test]
fn linux_package_install_updates_commands_files_and_service_together() {
    for os in [
        Distribution::Ubuntu,
        Distribution::Debian,
        Distribution::Arch,
    ] {
        let mut guest = shell(os, &[], &[]);
        let install = if os == Distribution::Arch {
            "sudo pacman -S nginx"
        } else {
            "sudo apt install nginx"
        };
        let executable = if os == Distribution::Arch {
            "/usr/bin/nginx"
        } else {
            "/usr/sbin/nginx"
        };
        assert_ne!(
            guest
                .execute(install.trim_start_matches("sudo "), now())
                .exit_status,
            0
        );
        assert!(!guest.filesystem().exists(executable));
        assert!(
            run(&mut guest, install)
                .to_ascii_lowercase()
                .contains("nginx")
        );
        assert!(
            guest.filesystem().exists(executable),
            "{} lacks installed executable",
            os.as_str()
        );
        assert_eq!(run(&mut guest, "which nginx").trim(), executable);
        assert!(run(&mut guest, "nginx -v").contains("nginx/"));
        assert!(run(&mut guest, "systemctl status nginx").contains("nginx"));
        assert!(
            guest
                .filesystem()
                .exists("/etc/systemd/system/multi-user.target.wants/nginx.service"),
            "{} lacks nginx enabled link",
            os.as_str()
        );
        assert!(run(&mut guest, "systemctl is-enabled nginx").contains("enabled"));
        let registry = if os == Distribution::Arch {
            "pacman -Q nginx"
        } else {
            "dpkg -l nginx"
        };
        assert!(run(&mut guest, registry).contains("nginx"));
        if os != Distribution::Arch {
            let status = run(&mut guest, "dpkg -s nginx");
            assert!(
                status.contains("Status: install ok installed"),
                "{}: {status}",
                os.as_str()
            );
            run(&mut guest, "sudo apt remove nginx");
            assert_ne!(guest.execute("which nginx", now()).exit_status, 0);
            let status = guest.execute("dpkg -s nginx", now());
            assert_eq!(status.exit_status, 0);
            assert!(status.output.contains("Status: deinstall ok config-files"));
            let unit = guest.execute("systemctl status nginx", now());
            assert_ne!(unit.exit_status, 0);
            assert!(unit.output.contains("could not be found"));
            run(&mut guest, "sudo apt purge nginx");
            let purged = guest.execute("dpkg -s nginx", now());
            assert_ne!(purged.exit_status, 0);
            assert!(purged.output.contains("no packages found"));
        }
    }
}

#[test]
fn arch_profile_matches_pacman_database_filesystem_and_systemd() {
    let mut guest = shell(Distribution::Arch, &[], &[]);
    assert_eq!(guest.filesystem().readlink("/bin").unwrap(), "/usr/bin");
    assert!(
        run(&mut guest, "ls /bin")
            .split_whitespace()
            .any(|name| name == "bash")
    );
    assert_eq!(run(&mut guest, "readlink -f /bin").trim(), "/usr/bin");
    assert!(guest.filesystem().exists("/etc/resolv.conf"));
    assert!(run(&mut guest, "cat /etc/resolv.conf").contains("nameserver 127.0.0.53"));
    for path in [
        "/etc/fstab",
        "/etc/machine-id",
        "/etc/nsswitch.conf",
        "/etc/profile",
        "/etc/ld.so.conf",
        "/usr/bin/df",
        "/usr/bin/du",
        "/usr/bin/free",
        "/usr/bin/uptime",
        "/usr/bin/pgrep",
    ] {
        assert!(guest.filesystem().exists(path), "Arch profile lacks {path}");
    }
    assert!(!run(&mut guest, "df -h").is_empty());
    assert!(!run(&mut guest, "du -sh /etc").is_empty());
    assert!(!run(&mut guest, "free -h").is_empty());
    assert!(!run(&mut guest, "uptime").is_empty());
    assert!(run(&mut guest, "pgrep systemd").contains("1"));

    let installed = run(&mut guest, "pacman -Qq");
    assert!(installed.lines().any(|name| name == "bash"));
    assert!(run(&mut guest, "pacman -Qq bash").trim() == "bash");
    for (package, size, date, expected_altered) in [
        (
            "bash",
            "Installed Size  : 9600 KiB",
            "Build Date      : 2026-09-15",
            0,
        ),
        (
            "systemd",
            "Installed Size  : 40500 KiB",
            "Build Date      : 2026-09-22",
            0,
        ),
        (
            "openssh",
            "Installed Size  : 6800 KiB",
            "Build Date      : 2026-10-06",
            1,
        ),
    ] {
        let info = run(&mut guest, &format!("pacman -Qi {package}"));
        assert!(info.contains(size), "{package}: {info}");
        assert!(info.contains(date), "{package}: {info}");
        assert!(run(&mut guest, &format!("pacman -Qk {package}")).contains("0 missing files"));
        let detailed_check = run(&mut guest, &format!("pacman -Qkk {package}"));
        assert!(
            detailed_check.contains(&format!("{expected_altered} altered files")),
            "{package}: {detailed_check}"
        );
    }

    assert!(!guest.filesystem().exists("/usr/bin/nginx"));
    assert!(run(&mut guest, "sudo pacman -S nginx").contains("installing nginx-"));
    let nginx_info = run(&mut guest, "pacman -Qi nginx");
    assert!(nginx_info.contains("Installed Size  : 1700 KiB"));
    assert!(
        guest
            .filesystem()
            .exists("/usr/lib/systemd/system/nginx.service")
    );
    assert!(run(&mut guest, "systemctl status nginx").contains("nginx"));
    assert!(run(&mut guest, "systemctl is-enabled nginx").contains("enabled"));

    run(&mut guest, "sudo pacman -R nginx");
    assert!(!guest.filesystem().exists("/usr/bin/nginx"));
    assert!(
        !guest
            .filesystem()
            .exists("/usr/lib/systemd/system/nginx.service")
    );
    assert!(
        !guest
            .filesystem()
            .exists("/etc/systemd/system/multi-user.target.wants/nginx.service")
    );
    let removed = guest.execute("pacman -Qi nginx", now());
    assert_ne!(removed.exit_status, 0);
}

#[test]
fn linux_system_tools_share_virtual_proc_network_and_service_state() {
    for os in [
        Distribution::Ubuntu,
        Distribution::Debian,
        Distribution::Arch,
    ] {
        let mut guest = shell(os, &[], &[]);
        assert!(run(&mut guest, "cat /proc/cpuinfo").contains("Intel(R) Xeon"));
        assert!(run(&mut guest, "cat /etc/resolv.conf").contains("nameserver 127.0.0.53"));
        assert!(run(&mut guest, "uptime").contains("up "));
        assert!(run(&mut guest, "df -h").contains("/dev/sda1"));
        assert!(run(&mut guest, "free -h").contains("Mem:"));
        let cron_process = if os == Distribution::Arch {
            "crond"
        } else {
            "cron"
        };
        assert!(
            !run(&mut guest, &format!("pgrep {cron_process}"))
                .trim()
                .is_empty()
        );
        assert!(
            !run(&mut guest, &format!("pidof {cron_process}"))
                .trim()
                .is_empty()
        );
        let cron_unit = if os == Distribution::Arch {
            "cronie"
        } else {
            "cron"
        };
        assert!(run(&mut guest, &format!("systemctl status {cron_unit}")).contains(".service"));
        assert!(run(&mut guest, &format!("systemctl is-enabled {cron_unit}")).contains("enabled"));
        let default_ss = run(&mut guest, "ss -lnt");
        assert!(!default_ss.contains("Process"));
        assert!(!default_ss.contains("10.20.4.12:5432"));
        if os == Distribution::Ubuntu {
            assert!(default_ss.contains("127.0.0.1:5432"));
            let process_sockets = run(&mut guest, "ss -lntp");
            assert!(process_sockets.contains("127.0.0.1:5432"));
            assert!(!process_sockets.contains("users:((\"postgresql\""));
            assert!(!process_sockets.contains("pid="));
        }
        assert!(run(&mut guest, "ls /bin").contains("bash"));
    }
}

#[test]
fn bash_status_parameter_tracks_each_command_and_chain() {
    let mut guest = shell(Distribution::Ubuntu, &[], &[]);
    assert_eq!(guest.execute("false", now()).exit_status, 1);
    assert_eq!(run(&mut guest, "echo $?").trim(), "1");
    assert_eq!(run(&mut guest, "false; echo $?").trim(), "1");
    assert_eq!(run(&mut guest, "true; echo $?").trim(), "0");
    assert_eq!(run(&mut guest, "false || echo $?").trim(), "1");
    assert_eq!(guest.execute("false && echo skipped", now()).exit_status, 1);
}

#[test]
fn sudo_output_and_policy_allow_only_the_advertised_virtual_commands() {
    let mut guest = shell(Distribution::Ubuntu, &[], &[]);
    let listed = run(&mut guest, "sudo -l");
    assert!(listed.contains("/usr/bin/apt"));
    assert!(listed.contains("/usr/bin/systemctl"));
    assert!(!listed.contains("NOPASSWD: ALL"));
    run(&mut guest, "touch /tmp/sudo-policy-check");
    assert_ne!(
        guest
            .execute("sudo rm /tmp/sudo-policy-check", now())
            .exit_status,
        0
    );
    assert!(guest.filesystem().exists("/tmp/sudo-policy-check"));
    assert_ne!(
        guest
            .execute("sudo /usr/bin/rm /tmp/sudo-policy-check", now())
            .exit_status,
        0
    );
    assert_eq!(
        guest
            .execute("sudo /usr/bin/apt --version", now())
            .exit_status,
        0
    );
}
