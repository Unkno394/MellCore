pub mod node;
pub mod permissions;
pub mod persistence;

use std::collections::BTreeMap;

use crate::config::Distribution;
use chrono::{DateTime, Duration, Utc};
use hf_core::BaitFile;
use node::{Node, NodeKind};
use thiserror::Error;

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct VirtualFileSystem {
    nodes: BTreeMap<String, Node>,
    #[serde(default = "default_primary_user")]
    primary_user: String,
    #[serde(default)]
    distribution: Distribution,
}

fn default_primary_user() -> String {
    "admin".into()
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FsError {
    #[error("No such file or directory")]
    NotFound,
    #[error("Not a directory")]
    NotDirectory,
    #[error("Is a directory")]
    IsDirectory,
    #[error("File exists")]
    Exists,
    #[error("Directory not empty")]
    NotEmpty,
    #[error("Operation not permitted")]
    Forbidden,
    #[error("Permission denied")]
    PermissionDenied,
    #[error("Invalid path")]
    InvalidPath,
    #[error("No space left on device")]
    NoSpace,
}

const MAX_NODES: usize = 4096;
const MAX_FILE_BYTES: usize = 1024 * 1024;
const MAX_TOTAL_FILE_BYTES: usize = 4 * 1024 * 1024;

pub(crate) fn windows_pe_fixture(size: usize, seed: u32) -> Vec<u8> {
    let size = size.max(0x600);
    let mut image = vec![0u8; size];
    image[0..2].copy_from_slice(b"MZ");
    image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    let dos_message = b"This program cannot be run in DOS mode.\r\r\n$";
    image[0x40..0x40 + dos_message.len()].copy_from_slice(dos_message);
    image[0x80..0x84].copy_from_slice(b"PE\0\0");
    let coff = 0x84;
    image[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    image[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
    image[coff + 16..coff + 18].copy_from_slice(&0x00f0u16.to_le_bytes());
    image[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes());

    let optional = coff + 20;
    let raw_size = size.saturating_sub(0x400) as u32;
    let image_size = (0x1000u32.saturating_add(raw_size).saturating_add(0xfff)) & !0xfff;
    image[optional..optional + 2].copy_from_slice(&0x020bu16.to_le_bytes());
    image[optional + 2] = 14;
    image[optional + 4..optional + 8].copy_from_slice(&raw_size.to_le_bytes());
    image[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    image[optional + 20..optional + 24].copy_from_slice(&0x1000u32.to_le_bytes());
    image[optional + 24..optional + 32].copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes());
    image[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    image[optional + 36..optional + 40].copy_from_slice(&0x200u32.to_le_bytes());
    image[optional + 40..optional + 42].copy_from_slice(&10u16.to_le_bytes());
    image[optional + 48..optional + 50].copy_from_slice(&10u16.to_le_bytes());
    image[optional + 56..optional + 60].copy_from_slice(&image_size.to_le_bytes());
    image[optional + 60..optional + 64].copy_from_slice(&0x400u32.to_le_bytes());
    image[optional + 68..optional + 70].copy_from_slice(&3u16.to_le_bytes());
    image[optional + 70..optional + 72].copy_from_slice(&0x8160u16.to_le_bytes());
    image[optional + 72..optional + 80].copy_from_slice(&0x0010_0000u64.to_le_bytes());
    image[optional + 80..optional + 88].copy_from_slice(&0x1000u64.to_le_bytes());
    image[optional + 88..optional + 96].copy_from_slice(&0x0010_0000u64.to_le_bytes());
    image[optional + 96..optional + 104].copy_from_slice(&0x1000u64.to_le_bytes());
    image[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());

    let section = optional + 0xf0;
    image[section..section + 5].copy_from_slice(b".text");
    image[section + 8..section + 12].copy_from_slice(&raw_size.to_le_bytes());
    image[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    image[section + 16..section + 20].copy_from_slice(&raw_size.to_le_bytes());
    image[section + 20..section + 24].copy_from_slice(&0x400u32.to_le_bytes());
    image[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    if size > 0x410 {
        image[0x400..0x410].copy_from_slice(&[
            0x48, 0x83, 0xec, 0x28, 0x48, 0x8b, 0x05, 0x11, 0x22, 0x33, 0x44, 0x48, 0x83, 0xc4,
            0x28, 0xc3,
        ]);
        let mut state = seed.max(1);
        for byte in &mut image[0x410..] {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = state as u8;
        }
    }
    image
}

/// Baseline commands represented as executable nodes in every virtual Linux filesystem.
/// Shell command discovery uses these nodes as its source of truth.
pub const VIRTUAL_SYSTEM_BINARIES: &[(&str, &str)] = &[
    ("/usr/bin/bash", "GNU bash"),
    ("/usr/bin/dash", "Debian Almquist shell"),
    ("/usr/bin/ls", "GNU coreutils"),
    ("/usr/bin/cat", "GNU coreutils"),
    ("/usr/bin/env", "GNU coreutils"),
    ("/usr/bin/printenv", "GNU coreutils"),
    ("/usr/bin/tr", "GNU coreutils"),
    ("/usr/bin/seq", "GNU coreutils"),
    ("/usr/bin/wc", "GNU coreutils"),
    ("/usr/bin/sort", "GNU coreutils"),
    ("/usr/bin/rmdir", "GNU coreutils"),
    ("/usr/bin/file", "file"),
    ("/usr/bin/mount", "util-linux"),
    ("/usr/bin/findmnt", "util-linux"),
    ("/usr/bin/lscpu", "util-linux"),
    ("/usr/bin/grep", "GNU grep"),
    ("/usr/bin/printf", "GNU coreutils"),
    ("/usr/bin/chmod", "GNU coreutils"),
    ("/usr/bin/stat", "GNU coreutils"),
    ("/usr/bin/su", "util-linux"),
    ("/usr/bin/sudo", "sudo"),
    ("/usr/bin/getent", "GNU C Library"),
    ("/usr/bin/groups", "GNU coreutils"),
    ("/usr/bin/nologin", "shadow"),
    ("/usr/bin/which", "which"),
    ("/usr/bin/readlink", "GNU coreutils"),
    ("/usr/bin/hostnamectl", "systemd"),
    ("/usr/bin/nano", "GNU nano"),
    ("/usr/bin/whoami", "GNU coreutils"),
    ("/usr/bin/id", "GNU coreutils"),
    ("/usr/bin/uname", "GNU coreutils"),
    ("/usr/bin/hostname", "GNU coreutils"),
    ("/usr/bin/date", "GNU coreutils"),
    ("/usr/bin/uptime", "procps"),
    ("/usr/bin/df", "GNU coreutils"),
    ("/usr/bin/du", "GNU coreutils"),
    ("/usr/bin/free", "procps"),
    ("/usr/bin/pgrep", "procps"),
    ("/usr/bin/pidof", "procps"),
    ("/usr/bin/pwd", "GNU coreutils"),
    ("/usr/bin/find", "GNU findutils"),
    ("/usr/bin/mkdir", "GNU coreutils"),
    ("/usr/bin/touch", "GNU coreutils"),
    ("/usr/bin/rm", "GNU coreutils"),
    ("/usr/bin/cp", "GNU coreutils"),
    ("/usr/bin/mv", "GNU coreutils"),
    ("/usr/bin/head", "GNU coreutils"),
    ("/usr/bin/tail", "GNU coreutils"),
    ("/usr/bin/ps", "procps"),
    ("/usr/bin/top", "procps"),
    ("/usr/bin/kill", "procps"),
    ("/usr/bin/ip", "iproute2"),
    ("/usr/bin/ss", "iproute2"),
    ("/usr/bin/netstat", "net-tools"),
    ("/usr/bin/crontab", "cron"),
    ("/usr/bin/systemctl", "systemd"),
    (
        "/usr/bin/authorized_keys",
        "HoneyForge virtual authorized keys utility",
    ),
    ("/usr/bin/docker", "Docker CLI"),
    ("/usr/bin/docker-compose", "Docker Compose"),
    ("/usr/bin/git", "Git"),
    ("/usr/bin/tar", "GNU tar"),
    ("/usr/bin/unzip", "Info-ZIP"),
    ("/usr/bin/zipinfo", "Info-ZIP"),
    ("/usr/bin/companyctl", "MellCore virtual utility"),
];

fn baseline_dpkg_status(distribution: Distribution) -> String {
    let packages: &[(&str, &str, &str)] = match distribution {
        Distribution::Debian => &[
            (
                "base-files",
                "13.8+deb13u7",
                "Debian base system miscellaneous files",
            ),
            ("bash", "5.2.37-2+b5", "GNU Bourne Again SHell"),
            ("coreutils", "9.7-3", "GNU core utilities"),
            ("file", "1:5.46-5", "Recognize the type of data in a file"),
            ("dash", "0.5.12-12", "POSIX-compliant shell"),
            ("dpkg", "1.22.22", "Debian package management system"),
            ("apt", "3.0.3", "commandline package manager"),
            ("libc6", "2.41-12", "GNU C Library: Shared libraries"),
            ("systemd", "257.9-1~deb13u1", "system and service manager"),
            ("procps", "2:4.0.4-9", "utilities for proc filesystem"),
            (
                "iproute2",
                "6.15.0-1",
                "networking and traffic control tools",
            ),
            ("net-tools", "2.10-1.3", "NET-3 networking toolkit"),
            ("cron", "3.0pl1-197", "process scheduling daemon"),
            ("grep", "3.11-4", "GNU grep, egrep and fgrep"),
            ("findutils", "4.10.0-3", "utilities for finding files"),
            ("util-linux", "2.41-5", "miscellaneous system utilities"),
            (
                "sudo",
                "1.9.16p2-3",
                "Provide limited super user privileges to specific users",
            ),
            (
                "debianutils",
                "5.23.2",
                "Miscellaneous utilities specific to Debian",
            ),
            (
                "git",
                "1:2.47.3-0+deb13u1",
                "fast, scalable, distributed revision control system",
            ),
            (
                "tar",
                "1.35+dfsg-3.1",
                "GNU version of the tar archiving utility",
            ),
            ("unzip", "6.0-29", "De-archiver for .zip files"),
            (
                "nano",
                "8.4-1",
                "small, friendly text editor inspired by Pico",
            ),
            ("which", "2.21-1", "locate a command"),
            (
                "openssh-client",
                "1:10.0p1-7+deb13u4",
                "secure shell (SSH) client",
            ),
            (
                "openssh-server",
                "1:10.0p1-7+deb13u4",
                "secure shell (SSH) server",
            ),
            (
                "openssh-sftp-server",
                "1:10.0p1-7+deb13u4",
                "secure shell (SSH) sftp server module",
            ),
            (
                "postgresql",
                "17+276",
                "object-relational SQL database (supported version)",
            ),
            (
                "docker.io",
                "26.1.5+dfsg1-9+deb13u1",
                "Linux container runtime",
            ),
            (
                "containerd",
                "1.7.24~ds1-6+deb13u1",
                "open and reliable container runtime",
            ),
            (
                "docker-compose",
                "2.26.1-4",
                "define and run multi-container Docker applications",
            ),
            ("dbus", "1.16.2-2", "simple interprocess messaging system"),
            ("login", "1:4.16.0-2", "system login tools"),
        ],
        Distribution::Ubuntu => &[
            (
                "base-files",
                "12ubuntu4.7",
                "Ubuntu base system miscellaneous files",
            ),
            ("bash", "5.1-6ubuntu1.1", "GNU Bourne Again SHell"),
            ("coreutils", "8.32-4.1ubuntu1.2", "GNU core utilities"),
            (
                "file",
                "1:5.41-3ubuntu0.1",
                "Recognize the type of data in a file",
            ),
            (
                "dash",
                "0.5.11+git20210903+057cd650a4ed-3build1",
                "POSIX-compliant shell",
            ),
            (
                "dpkg",
                "1.21.1ubuntu2.3",
                "Debian package management system",
            ),
            ("apt", "2.4.12", "commandline package manager"),
            (
                "libc6",
                "2.35-0ubuntu3.9",
                "GNU C Library: Shared libraries",
            ),
            (
                "systemd",
                "249.11-0ubuntu3.12",
                "system and service manager",
            ),
            (
                "procps",
                "2:3.3.17-6ubuntu2.1",
                "utilities for proc filesystem",
            ),
            (
                "iproute2",
                "5.15.0-1ubuntu2",
                "networking and traffic control tools",
            ),
            (
                "net-tools",
                "1.60+git20181103.0eebece-1ubuntu5",
                "NET-3 networking toolkit",
            ),
            ("cron", "3.0pl1-137ubuntu3", "process scheduling daemon"),
            ("grep", "3.7-1build1", "GNU grep, egrep and fgrep"),
            ("findutils", "4.8.0-1ubuntu3", "utilities for finding files"),
            (
                "util-linux",
                "2.37.2-4ubuntu3",
                "miscellaneous system utilities",
            ),
            (
                "sudo",
                "1.9.9-1ubuntu2.4",
                "Provide limited super user privileges to specific users",
            ),
            (
                "git",
                "1:2.34.1-1ubuntu1.12",
                "fast, scalable, distributed revision control system",
            ),
            (
                "tar",
                "1.34+dfsg-1ubuntu0.1",
                "GNU version of the tar archiving utility",
            ),
            ("unzip", "6.0-26ubuntu3.2", "De-archiver for .zip files"),
            (
                "nano",
                "6.2-1ubuntu0.1",
                "small, friendly text editor inspired by Pico",
            ),
        ],
        Distribution::Arch | Distribution::Windows => return String::new(),
    };
    packages
        .iter()
        .map(|(name, version, description)| {
            format!(
                "Package: {name}\nStatus: install ok installed\nPriority: required\nSection: base\nInstalled-Size: 1024\nMaintainer: Debian System Team\nArchitecture: amd64\nVersion: {version}\nDescription: {description}\n\n"
            )
        })
        .collect()
}

impl VirtualFileSystem {
    pub(crate) fn validate_snapshot(&self) -> Result<(), String> {
        if self.nodes.len() > MAX_NODES || !self.nodes.get("/").is_some_and(Node::is_dir) {
            return Err("virtual filesystem snapshot has an invalid root or too many nodes".into());
        }
        let mut total_bytes = 0usize;
        for (path, node) in &self.nodes {
            if Self::normalize("/", path).as_deref() != Ok(path.as_str()) {
                return Err("virtual filesystem snapshot contains an invalid path".into());
            }
            if node.is_dir() {
                continue;
            }
            let size = node.len();
            if size > MAX_FILE_BYTES {
                return Err("virtual filesystem snapshot contains an oversized file".into());
            }
            total_bytes = total_bytes.saturating_add(size);
            if total_bytes > MAX_TOTAL_FILE_BYTES {
                return Err("virtual filesystem snapshot exceeds the storage limit".into());
            }
        }
        for path in self.nodes.keys().filter(|path| path.as_str() != "/") {
            let parent = path
                .rsplit_once('/')
                .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
                .ok_or_else(|| {
                    "virtual filesystem snapshot contains a parentless path".to_owned()
                })?;
            if !self.nodes.get(parent).is_some_and(Node::is_dir) {
                return Err(format!(
                    "virtual filesystem snapshot has a missing or invalid parent: {path:?} requires directory {parent:?}"
                ));
            }
        }
        Ok(())
    }

    pub fn windows(hostname: &str, username: &str, now: DateTime<Utc>) -> Self {
        let mut fs = Self {
            nodes: BTreeMap::new(),
            primary_user: username.to_owned(),
            distribution: Distribution::Windows,
        };
        for path in [
            "/",
            "/C",
            "/C/Users",
            "/C/Users/Public",
            "/C/Users/Public/Desktop",
            "/C/Users/Public/Downloads",
            "/C/Users/Public/Documents",
            "/C/Users/Public/Music",
            "/C/Users/Public/Pictures",
            "/C/Users/Public/Videos",
            "/C/Users/Administrator",
            "/C/Windows",
            "/C/Windows/System32",
            "/C/Windows/System32/OpenSSH",
            "/C/Windows/System32/drivers",
            "/C/Windows/System32/drivers/etc",
            "/C/Windows/System32/config",
            "/C/Windows/System32/WindowsPowerShell",
            "/C/Windows/System32/WindowsPowerShell/v1.0",
            "/C/Windows/System32/WindowsPowerShell/v1.0/Modules",
            "/C/Windows/System32/wbem",
            "/C/Windows/SysWOW64",
            "/C/Windows/Temp",
            "/C/Windows/Logs",
            "/C/Windows/Logs/CBS",
            "/C/Program Files",
            "/C/Program Files/WindowsPowerShell",
            "/C/Program Files/WindowsPowerShell/Modules",
            "/C/Program Files (x86)",
            "/C/ProgramData",
            "/C/ProgramData/ssh",
            "/Registry",
            "/Registry/HKLM",
            "/Registry/HKLM/SOFTWARE",
            "/Registry/HKLM/SOFTWARE/Microsoft",
            "/Registry/HKLM/SOFTWARE/Microsoft/Windows NT",
            "/Registry/HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion",
            "/Registry/HKLM/SOFTWARE/Microsoft/Windows",
            "/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion",
            "/Registry/HKLM/SYSTEM",
            "/Registry/HKLM/SYSTEM/CurrentControlSet",
            "/Registry/HKLM/SYSTEM/CurrentControlSet/Services",
            "/Registry/HKLM/SAM",
            "/Registry/HKLM/SECURITY",
            "/Registry/HKCU",
            "/Registry/HKCU/Software",
            "/Registry/HKCU/Software/Microsoft",
            "/Registry/HKCU/Software/Microsoft/Windows",
            "/Registry/HKCU/Software/Microsoft/Windows/CurrentVersion",
            "/State",
        ] {
            fs.nodes.insert(path.into(), Node::directory(now));
        }
        let home = format!("/C/Users/{username}");
        let mut home_node = Node::directory(now);
        home_node.owner = username.to_owned();
        home_node.group = username.to_owned();
        fs.nodes.insert(home.clone(), home_node);
        for path in [
            format!("{home}/Desktop"),
            format!("{home}/AppData"),
            format!("{home}/AppData/Local"),
            format!("{home}/AppData/Local/Temp"),
        ] {
            let mut node = Node::directory(now);
            node.owner = username.to_owned();
            node.group = username.to_owned();
            fs.nodes.insert(path, node);
        }
        fs.put_file(
            &format!("{home}/Desktop/README.txt"),
            "Internal server. Authorized access only.\n",
            now,
        );
        for path in [
            "/C/Windows/System32/cmd.exe",
            "/C/Windows/System32/OpenSSH/ssh.exe",
            "/C/Windows/System32/OpenSSH/sshd.exe",
            "/C/Windows/System32/OpenSSH/ssh-keygen.exe",
            "/C/Windows/System32/OpenSSH/sftp.exe",
            "/C/Windows/System32/whoami.exe",
            "/C/Windows/System32/hostname.exe",
            "/C/Windows/System32/ipconfig.exe",
            "/C/Windows/System32/route.exe",
            "/C/Windows/System32/arp.exe",
            "/C/Windows/System32/net.exe",
            "/C/Windows/System32/tasklist.exe",
            "/C/Windows/System32/netstat.exe",
            "/C/Windows/System32/sc.exe",
            "/C/Windows/System32/where.exe",
            "/C/Windows/System32/reg.exe",
            "/C/Windows/System32/msiexec.exe",
            "/C/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
            "/C/Windows/SysWOW64/cmd.exe",
            "/C/Windows/SysWOW64/whoami.exe",
            "/C/Windows/SysWOW64/ipconfig.exe",
            "/C/Windows/SysWOW64/reg.exe",
        ] {
            let size = match path.to_ascii_lowercase().as_str() {
                "/c/windows/system32/cmd.exe" | "/c/windows/syswow64/cmd.exe" => 289_792,
                "/c/windows/system32/whoami.exe"
                | "/c/windows/syswow64/whoami.exe"
                | "/c/windows/system32/hostname.exe" => 45_056,
                "/c/windows/system32/ipconfig.exe" | "/c/windows/syswow64/ipconfig.exe" => 114_688,
                "/c/windows/system32/route.exe" => 49_152,
                "/c/windows/system32/arp.exe" => 45_056,
                "/c/windows/system32/net.exe" => 82_432,
                "/c/windows/system32/tasklist.exe" => 81_920,
                "/c/windows/system32/netstat.exe" => 44_032,
                "/c/windows/system32/sc.exe" => 86_016,
                "/c/windows/system32/where.exe" => 45_568,
                "/c/windows/system32/reg.exe" | "/c/windows/syswow64/reg.exe" => 85_504,
                "/c/windows/system32/msiexec.exe" => 149_504,
                "/c/windows/system32/windowspowershell/v1.0/powershell.exe" => 464_384,
                "/c/windows/system32/openssh/ssh.exe" => 355_328,
                "/c/windows/system32/openssh/sshd.exe" => 421_888,
                "/c/windows/system32/openssh/ssh-keygen.exe" => 233_472,
                "/c/windows/system32/openssh/sftp.exe" => 340_992,
                _ => 81_920,
            };
            let seed = path.bytes().fold(0x9e37_79b9u32, |state, byte| {
                state.rotate_left(5) ^ u32::from(byte)
            });
            fs.put_file(path, windows_pe_fixture(size, seed), now);
            if let Ok(node) = fs.node_mut(path) {
                node.permissions = permissions::Permissions(0o755);
            }
        }
        for (name, version) in [
            ("Microsoft.PowerShell.Archive", "1.2.5"),
            ("Microsoft.PowerShell.Diagnostics", "3.0.0.0"),
            ("Microsoft.PowerShell.Host", "3.0.0.0"),
            ("Microsoft.PowerShell.Management", "3.1.0.0"),
            ("Microsoft.PowerShell.Security", "3.0.0.0"),
            ("Microsoft.PowerShell.Utility", "3.1.0.0"),
            ("Microsoft.WSMan.Management", "3.0.0.0"),
        ] {
            let directory = format!("/C/Windows/System32/WindowsPowerShell/v1.0/Modules/{name}");
            let _ = fs.mkdir(&directory, now);
            fs.put_file(
                &format!("{directory}/{name}.psd1"),
                format!("@{{ ModuleVersion = '{version}'; GUID = '00000000-0000-0000-0000-000000000000' }}\n"),
                now,
            );
        }
        for (name, version) in [
            ("PackageManagement", "1.4.8.1"),
            ("PowerShellGet", "2.2.5"),
            ("PSReadline", "2.0.0"),
        ] {
            let directory = format!("/C/Program Files/WindowsPowerShell/Modules/{name}");
            let _ = fs.mkdir(&directory, now);
            fs.put_file(
                &format!("{directory}/{name}.psd1"),
                format!("@{{ ModuleVersion = '{version}'; GUID = '00000000-0000-0000-0000-000000000000' }}\n"),
                now,
            );
        }
        fs.put_file("/C/Windows/System32/drivers/etc/hosts", format!("# Copyright (c) Microsoft Corp.\n127.0.0.1 localhost\n::1 localhost\n10.20.0.24 {hostname}\n"), now);
        fs.put_file(
            "/C/ProgramData/ssh/sshd_config",
            "# OpenSSH server configuration\nPort 22\nAddressFamily any\nListenAddress 0.0.0.0\nPubkeyAuthentication yes\nPasswordAuthentication yes\nSubsystem sftp sftp-server.exe\n",
            now,
        );
        fs.put_file(
            "/C/Windows/System32/config/SOFTWARE",
            "REGISTRY FILE\n",
            now,
        );
        fs.put_file("/C/Windows/System32/config/SYSTEM", "REGISTRY FILE\n", now);
        fs.put_file("/C/Windows/System32/config/SAM", "REGISTRY FILE\n", now);
        fs.put_file(
            "/C/Windows/System32/config/SECURITY",
            "REGISTRY FILE\n",
            now,
        );
        fs.put_file("/C/Windows/System32/config/DEFAULT", "REGISTRY FILE\n", now);
        fs.put_file(
            "/C/Windows/System32/config/COMPONENTS",
            "REGISTRY FILE\n",
            now,
        );
        fs.put_file(
            "/C/Windows/Logs/CBS/CBS.log",
            "2026-10-14 00:00:00, Info                  CBS    Starting servicing stack\n",
            now,
        );
        fs.put_file(
            "/Registry/HKLM/SOFTWARE/AppSuite.txt",
            format!("ComputerName={hostname}\nInstallPath=C:\\Program Files\\AppSuite\n"),
            now,
        );
        fs.put_file("/Registry/HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion.txt", "ProductName=Windows Server 2022 Standard\nCurrentBuild=20348\nCurrentBuildNumber=20348\nReleaseId=2009\nDisplayVersion=21H2\nEditionID=ServerStandard\nInstallationType=Server\n", now);
        fs.put_file("/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion.txt", "ProgramFilesDir=C:\\Program Files\nSystemRoot=C:\\Windows\nCommonFilesDir=C:\\Program Files\\Common Files\n", now);
        fs.put_file(
            "/Registry/HKCU/Software/Microsoft/Windows/CurrentVersion.txt",
            format!("ExplorerStartupTraceRecorded=1\nUserProfile=C:\\Users\\{username}\n"),
            now,
        );
        fs.put_file("/State/services.json", "[]", now);
        fs.put_file("/State/processes.json", "[]", now);
        fs.put_file("/State/network.json", r#"{"adapter":"Ethernet","interface_index":4,"mac":"00-15-5D-2A-4B-10","ipv4":"10.20.0.24","prefix":24,"gateway":"10.20.0.1","dns":["10.20.0.10","10.20.0.11"],"dhcp":true,"dns_suffix":"corp.local"}"#, now);
        fs.put_file("/State/users.json", "[]", now);
        fs.put_file("/State/acls.json", "{}", now);
        for (path, node) in fs.nodes.iter_mut() {
            if path.starts_with("/C/Windows/")
                || path == "/C/Windows"
                || path.starts_with("/C/Program Files/")
                || path == "/C/Program Files"
                || path.starts_with("/C/Program Files (x86)/")
                || path == "/C/Program Files (x86)"
                || path.starts_with("/Registry/HKLM/")
                || path == "/Registry/HKLM"
            {
                node.owner = "SYSTEM".into();
                node.group = "Administrators".into();
            }
        }
        for path in [
            "/C/Windows/System32/config",
            "/Registry/HKLM/SAM",
            "/Registry/HKLM/SECURITY",
        ] {
            if let Ok(node) = fs.node_mut(path) {
                node.owner = "SYSTEM".into();
                node.group = "SYSTEM".into();
                node.permissions = permissions::Permissions(0o700);
            }
        }
        for (path, node) in fs.nodes.iter_mut() {
            if path == "/C/Users/Public" || path.starts_with("/C/Users/Public/") {
                node.owner = "SYSTEM".into();
                node.group = "Users".into();
                node.permissions =
                    permissions::Permissions(if node.is_dir() { 0o777 } else { 0o666 });
            }
            if path.starts_with("/C/") {
                let hash = path.bytes().fold(2_166_136_261u32, |state, byte| {
                    (state ^ u32::from(byte)).wrapping_mul(16_777_619)
                });
                let age_seconds = i64::from(hash % (180 * 24 * 60 * 60) + 60 * 60);
                node.modified_at = now - Duration::seconds(age_seconds);
            }
        }
        fs
    }

    pub fn linux(hostname: &str, now: DateTime<Utc>) -> Self {
        Self::linux_with_user(hostname, "admin", now)
    }

    pub fn linux_with_user(hostname: &str, username: &str, now: DateTime<Utc>) -> Self {
        Self::linux_with_profile(hostname, username, Distribution::Ubuntu, now)
    }

    pub fn linux_with_profile(
        hostname: &str,
        username: &str,
        distribution: Distribution,
        now: DateTime<Utc>,
    ) -> Self {
        let home = format!("/home/{username}");
        let mut fs = Self {
            nodes: BTreeMap::new(),
            primary_user: username.to_owned(),
            distribution,
        };
        for path in [
            "/",
            "/boot",
            "/dev",
            "/etc",
            "/home",
            "/lib",
            "/lib64",
            "/media",
            "/mnt",
            "/opt",
            "/proc",
            "/root",
            "/run",
            "/run/systemd",
            "/run/systemd/resolve",
            "/sbin",
            "/srv",
            "/sys",
            "/tmp",
            "/usr",
            "/usr/bin",
            "/usr/lib",
            // Ubuntu and Debian expose /lib through usr-merge. The systemd
            // unit directory therefore resolves to /usr/lib/systemd/system.
            "/usr/lib/systemd",
            "/usr/lib/systemd/system",
            "/usr/lib/systemd/user",
            "/usr/lib64",
            "/usr/local",
            "/usr/local/bin",
            "/usr/local/sbin",
            "/usr/sbin",
            "/usr/share",
            "/var",
            "/var/backups",
            "/var/cache",
            "/var/lib",
            "/var/log",
            "/var/tmp",
        ] {
            if distribution == Distribution::Arch
                && (path.starts_with("/var/lib/dpkg")
                    || path.starts_with("/etc/dpkg")
                    || path.starts_with("/var/log/apt")
                    || path == "/etc/alternatives"
                    || path == "/usr/share/keyrings")
            {
                continue;
            }
            let mut node = Node::directory(now);
            if path == "/root" {
                node.permissions = permissions::Permissions(0o700);
            } else if path == "/tmp" || path == "/var/tmp" {
                node.permissions = permissions::Permissions(0o1777);
            }
            fs.nodes.insert(path.into(), node);
        }
        if distribution.is_apt() {
            for path in [
                "/var/lib/dpkg",
                "/etc/dpkg",
                "/etc/dpkg/origins",
                "/etc/dpkg/dpkg.cfg.d",
                "/etc/alternatives",
                "/var/lib/dpkg/alternatives",
                "/var/lib/dpkg/info",
                "/var/lib/dpkg/updates",
                "/var/log/apt",
                "/usr/share/keyrings",
            ] {
                fs.nodes.insert(path.into(), Node::directory(now));
            }
        }
        if distribution == Distribution::Arch {
            for path in [
                "/usr/lib/systemd",
                "/usr/lib/systemd/system",
                "/usr/lib/systemd/user",
                "/etc/pacman.d",
                "/etc/pacman.d/hooks",
                "/etc/ld.so.conf.d",
                "/var/lib/pacman",
                "/var/lib/pacman/local",
                "/var/lib/pacman/sync",
                "/var/cache/pacman",
                "/var/cache/pacman/pkg",
                "/etc/ssh",
                "/etc/ssh/sshd_config.d",
                "/var/lib/postgres",
                "/var/lib/nginx",
                "/var/log/nginx",
            ] {
                fs.nodes.insert(path.into(), Node::directory(now));
            }
        }
        fs.put_symlink("/bin", "/usr/bin", now);
        fs.put_symlink("/sbin", "/usr/sbin", now);
        fs.put_symlink("/lib", "/usr/lib", now);
        fs.put_symlink("/lib64", "/usr/lib64", now);
        let mut home_node = Node::directory(now);
        home_node.owner = username.to_owned();
        home_node.group = username.to_owned();
        fs.nodes.insert(home.clone(), home_node);
        fs.put_file("/etc/hostname", format!("{hostname}\n"), now);
        fs.put_file("/etc/hosts", format!("127.0.0.1 localhost\n127.0.1.1 {hostname}\n::1 localhost ip6-localhost ip6-loopback\n"), now);
        fs.put_file("/etc/issue", distribution.issue(), now);
        fs.put_file(
            "/run/systemd/resolve/stub-resolv.conf",
            "# This is /run/systemd/resolve/stub-resolv.conf managed by man:systemd-resolved(8).\n# Do not edit.\n#\n# This file might be symlinked as /etc/resolv.conf. If you're looking at\n# /etc/resolv.conf and seeing this text, you have followed the symlink.\n#\nnameserver 127.0.0.53\noptions edns0 trust-ad\nsearch .\n",
            now,
        );
        fs.put_symlink(
            "/etc/resolv.conf",
            "../run/systemd/resolve/stub-resolv.conf",
            now,
        );
        if distribution == Distribution::Arch {
            fs.put_file("/usr/lib/os-release", distribution.os_release(), now);
            fs.put_symlink("/etc/os-release", "../usr/lib/os-release", now);
            fs.put_file("/etc/arch-release", "Arch Linux\n", now);
        } else {
            fs.put_file("/etc/os-release", distribution.os_release(), now);
        }
        fs.put_file(
            "/etc/shells",
            "# /etc/shells: valid login shells\n/bin/sh\n/bin/bash\n/bin/rbash\n",
            now,
        );
        fs.put_file("/etc/passwd", format!("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nadm:x:4:4:adm:/var/log:/usr/sbin/nologin\nmessagebus:x:100:104::/nonexistent:/usr/sbin/nologin\nsyslog:x:101:105::/home/syslog:/usr/sbin/nologin\nsystemd-resolve:x:102:102:systemd Resolver:/run/systemd:/usr/sbin/nologin\nsystemd-timesync:x:103:103:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\npostgres:x:114:120:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash\nredis:x:117:124:Redis server,,,:/var/lib/redis:/usr/sbin/nologin\napp:x:1001:1001:Application service:/srv/billing-api:/usr/sbin/nologin\n{username}:x:1000:1000:Operator:{home}:/bin/bash\n"), now);
        fs.put_file("/etc/group", format!("root:x:0:\ndaemon:x:1:\nbin:x:2:\nsys:x:3:\nadm:x:4:{username}\ntty:x:5:\ndisk:x:6:\nshadow:x:42:\nsudo:x:27:{username}\nwww-data:x:33:\nsystemd-resolve:x:102:\nsystemd-timesync:x:103:\nmessagebus:x:104:\nsyslog:x:105:\npostgres:x:120:\nredis:x:124:\napp:x:1001:\n{username}:x:1000:\n"), now);
        fs.put_file(
            "/etc/shadow",
            format!("root:!:19200:0:99999:7:::\n{username}:!:19200:0:99999:7:::\n"),
            now,
        );
        let sudoers = if distribution == Distribution::Arch {
            "root ALL=(ALL:ALL) ALL\n%wheel ALL=(ALL:ALL) NOPASSWD: /usr/bin/pacman, /usr/bin/systemctl, /usr/bin/whoami, /usr/bin/id\n"
        } else {
            "root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) NOPASSWD: /usr/bin/apt, /usr/bin/apt-get, /usr/bin/systemctl, /usr/bin/whoami, /usr/bin/id\n"
        };
        fs.put_file("/etc/sudoers", sudoers, now);
        if let Ok(node) = fs.node_mut("/etc/sudoers") {
            node.permissions = permissions::Permissions(0o440);
        }
        if distribution == Distribution::Arch {
            fs.put_file("/etc/passwd", format!("root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/usr/bin/nologin\ndaemon:x:2:2:daemon:/:/usr/bin/nologin\nsys:x:3:3:sys:/:/usr/bin/nologin\nadm:x:4:4:adm:/var/log:/usr/bin/nologin\nnobody:x:65534:65534:nobody:/:/usr/bin/nologin\ndbus:x:81:81:System Message Bus:/:/usr/bin/nologin\nsystemd-resolve:x:975:975:systemd Resolver:/:/usr/bin/nologin\nhttp:x:33:33:HTTP:/srv/http:/usr/bin/nologin\nsshd:x:50:50:sshd privilege separation:/var/empty:/usr/bin/nologin\npostgres:x:967:967:PostgreSQL user:/var/lib/postgres:/usr/bin/nologin\nvalkey:x:971:971:Valkey:/var/lib/valkey:/usr/bin/nologin\napp:x:1001:1001:Application service:/srv/billing-api:/usr/bin/nologin\n{username}:x:1000:1000:Operator:{home}:/bin/bash\n"), now);
            fs.put_file("/etc/group", format!("root:x:0:\nbin:x:1:\ndaemon:x:2:\nsys:x:3:\nadm:x:4:\ndisk:x:6:\nwheel:x:10:{username}\ntty:x:5:\nshadow:x:42:\ndbus:x:81:\nsystemd-resolve:x:975:\nhttp:x:33:\nsshd:x:50:\npostgres:x:967:\nvalkey:x:971:\ndocker:x:994:{username}\napp:x:1001:\n{username}:x:1000:\n"), now);
            fs.put_file(
                "/etc/sudoers",
                "root ALL=(ALL:ALL) ALL\n%wheel ALL=(ALL:ALL) NOPASSWD: /usr/bin/pacman, /usr/bin/systemctl, /usr/bin/whoami, /usr/bin/id\n",
                now,
            );
            if let Ok(node) = fs.node_mut("/etc/sudoers") {
                node.permissions = permissions::Permissions(0o440);
            }
            fs.put_file("/etc/shadow", format!("root:!:19200:0:99999:7:::\nbin:!:19200:0:99999:7:::\ndaemon:!:19200:0:99999:7:::\nsys:!:19200:0:99999:7:::\nadm:!:19200:0:99999:7:::\nnobody:!:19200:0:99999:7:::\ndbus:!:19200:0:99999:7:::\nsystemd-resolve:!:19200:0:99999:7:::\nhttp:!:19200:0:99999:7:::\nsshd:!:19200:0:99999:7:::\npostgres:!:19200:0:99999:7:::\nvalkey:!:19200:0:99999:7:::\napp:!:19200:0:99999:7:::\n{username}:!:19200:0:99999:7:::\n"), now);
            fs.put_file("/etc/shadow", format!("root:!:19200:0:99999:7:::\nbin:!:19200:0:99999:7:::\ndaemon:!:19200:0:99999:7:::\nsys:!:19200:0:99999:7:::\nadm:!:19200:0:99999:7:::\nnobody:!:19200:0:99999:7:::\ndbus:!:19200:0:99999:7:::\nhttp:!:19200:0:99999:7:::\nsshd:!:19200:0:99999:7:::\npostgres:!:19200:0:99999:7:::\nvalkey:!:19200:0:99999:7:::\napp:!:19200:0:99999:7:::\n{username}:!:19200:0:99999:7:::\n"), now);
        }
        if let Ok(shadow) = fs.node_mut("/etc/shadow") {
            shadow.permissions = permissions::Permissions(0o640);
            shadow.group = "shadow".into();
        }
        for (path, package) in VIRTUAL_SYSTEM_BINARIES {
            if distribution == Distribution::Arch && *path == "/usr/bin/dash" {
                continue;
            }
            if distribution.is_apt() && *path == "/usr/bin/nologin" {
                continue;
            }
            fs.put_file(path, format!("ELF 64-bit LSB executable, {package}\n"), now);
            if let Ok(node) = fs.node_mut(path) {
                node.permissions = permissions::Permissions(0o755);
            }
        }
        if distribution.is_apt() {
            fs.put_file(
                "/usr/sbin/nologin",
                "ELF 64-bit LSB executable, shadow\n",
                now,
            );
            if let Ok(node) = fs.node_mut("/usr/sbin/nologin") {
                node.permissions = permissions::Permissions(0o755);
            }
            if distribution == Distribution::Debian {
                fs.put_file(
                    "/usr/lib/systemd/systemd-journald",
                    "ELF 64-bit LSB executable, systemd-journald\n",
                    now,
                );
                if let Ok(node) = fs.node_mut("/usr/lib/systemd/systemd-journald") {
                    node.permissions = permissions::Permissions(0o755);
                }
                fs.put_file(
                    "/usr/bin/run-parts",
                    "ELF 64-bit LSB executable, debianutils\n",
                    now,
                );
                if let Ok(node) = fs.node_mut("/usr/bin/run-parts") {
                    node.permissions = permissions::Permissions(0o755);
                }
            }
        }
        fs.put_symlink("/usr/bin/sh", "dash", now);
        fs.put_symlink("/usr/bin/rbash", "bash", now);
        if distribution == Distribution::Arch {
            fs.put_symlink("/usr/bin/sh", "bash", now);
        }

        if distribution.is_apt() {
            for path in [
                "/etc/apt",
                "/etc/apt/apt.conf.d",
                "/etc/apt/auth.conf.d",
                "/etc/apt/preferences.d",
                "/etc/apt/sources.list.d",
                "/var/lib/apt",
                "/var/lib/apt/lists",
                "/var/lib/apt/lists/partial",
                "/var/cache/apt",
                "/var/cache/apt/archives",
                "/var/cache/apt/archives/partial",
            ] {
                let mut node = Node::directory(now);
                if path.ends_with("/partial") {
                    node.permissions = permissions::Permissions(0o700);
                }
                fs.nodes.insert(path.into(), node);
            }
            for (path, package) in [
                ("/usr/bin/apt", "Debian APT"),
                ("/usr/bin/apt-get", "Debian APT"),
                ("/usr/bin/apt-cache", "Debian APT"),
                ("/usr/bin/dpkg", "Debian dpkg"),
                ("/usr/bin/dpkg-query", "Debian dpkg"),
                ("/usr/bin/update-alternatives", "Debian dpkg"),
            ] {
                fs.put_file(path, format!("ELF 64-bit LSB executable, {package}\n"), now);
                if let Ok(node) = fs.node_mut(path) {
                    node.permissions = permissions::Permissions(0o755);
                }
            }
            fs.put_file("/etc/dpkg/dpkg.cfg", "# dpkg configuration file\n\n", now);
            fs.put_file(
                "/etc/apt/apt.conf.d/01autoremove",
                "APT::NeverAutoRemove {\n  \"^firmware-linux.*\";\n};\n",
                now,
            );
            fs.put_file(
                "/var/lib/dpkg/status",
                baseline_dpkg_status(distribution),
                now,
            );
            fs.put_symlink("/etc/alternatives/editor", "/usr/bin/nano", now);
            fs.put_symlink("/usr/bin/editor", "/etc/alternatives/editor", now);
            fs.put_file(
                "/var/lib/dpkg/alternatives/editor",
                "auto\n/usr/bin/editor\n\n/usr/bin/nano\n40\n",
                now,
            );
            if distribution == Distribution::Debian {
                fs.put_file("/etc/debian_version", "13.7\n", now);
                fs.put_file(
                    "/etc/dpkg/origins/debian",
                    "Vendor: Debian\nVendor-URL: https://www.debian.org/\nBugs: debbugs://bugs.debian.org\n",
                    now,
                );
                fs.put_file(
                    "/etc/apt/sources.list.d/debian.sources",
                    "Types: deb\nURIs: http://deb.debian.org/debian/\nSuites: trixie trixie-updates\nComponents: main contrib non-free non-free-firmware\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n\nTypes: deb\nURIs: http://security.debian.org/debian-security/\nSuites: trixie-security\nComponents: main contrib non-free non-free-firmware\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n",
                    now,
                );
                fs.put_file(
                    "/usr/share/keyrings/debian-archive-keyring.gpg",
                    "virtual Debian archive signing keyring\n",
                    now,
                );
                for path in ["/etc/ssh", "/etc/ssh/sshd_config.d", "/usr/lib/openssh"] {
                    let _ = fs.mkdir(path, now);
                }
                for path in [
                    "/usr/bin/ssh",
                    "/usr/bin/ssh-add",
                    "/usr/bin/ssh-agent",
                    "/usr/bin/ssh-keygen",
                    "/usr/bin/ssh-keyscan",
                    "/usr/bin/scp",
                    "/usr/bin/sftp",
                    "/usr/sbin/sshd",
                    "/usr/lib/openssh/sftp-server",
                ] {
                    fs.put_file(
                        path,
                        format!("ELF virtual OpenSSH executable {path}\n"),
                        now,
                    );
                    if let Ok(node) = fs.node_mut(path) {
                        node.permissions = permissions::Permissions(0o755);
                    }
                }
                fs.put_file(
                    "/etc/ssh/sshd_config",
                    "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\nPermitRootLogin prohibit-password\nPubkeyAuthentication yes\nPasswordAuthentication yes\nKbdInteractiveAuthentication no\nUsePAM yes\nSubsystem sftp /usr/lib/openssh/sftp-server\n",
                    now,
                );
                fs.put_file(
                    "/etc/ssh/ssh_config",
                    "Host *\n    SendEnv LANG LC_*\n    HashKnownHosts yes\n",
                    now,
                );
                fs.put_file("/usr/bin/psql", "ELF virtual PostgreSQL 17 client\n", now);
                if let Ok(node) = fs.node_mut("/usr/bin/psql") {
                    node.permissions = permissions::Permissions(0o755);
                }
                for path in [
                    "/usr/lib/postgresql",
                    "/usr/lib/postgresql/17",
                    "/usr/lib/postgresql/17/bin",
                    "/etc/postgresql",
                    "/etc/postgresql/17",
                    "/etc/postgresql/17/main",
                ] {
                    let _ = fs.mkdir(path, now);
                }
                fs.put_file(
                    "/usr/lib/postgresql/17/bin/postgres",
                    "ELF virtual PostgreSQL 17 server\n",
                    now,
                );
                if let Ok(node) = fs.node_mut("/usr/lib/postgresql/17/bin/postgres") {
                    node.permissions = permissions::Permissions(0o755);
                }
                fs.put_file(
                    "/etc/postgresql/17/main/postgresql.conf",
                    "listen_addresses = 'localhost'\nport = 5432\n",
                    now,
                );
                for path in [
                    "/usr/bin/docker",
                    "/usr/bin/dockerd",
                    "/usr/bin/docker-compose",
                    "/usr/bin/containerd",
                    "/usr/bin/dbus-daemon",
                ] {
                    fs.put_file(path, format!("ELF virtual Debian executable {path}\n"), now);
                    if let Ok(node) = fs.node_mut(path) {
                        node.permissions = permissions::Permissions(0o755);
                    }
                }
            } else {
                fs.put_file(
                    "/etc/apt/sources.list",
                    "deb http://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse\ndeb http://archive.ubuntu.com/ubuntu jammy-updates main restricted universe multiverse\ndeb http://security.ubuntu.com/ubuntu jammy-security main restricted universe multiverse\n",
                    now,
                );
            }
        } else if distribution == Distribution::Arch {
            fs.put_file(
                "/usr/bin/pacman",
                "ELF 64-bit LSB executable, pacman\n",
                now,
            );
            if let Ok(node) = fs.node_mut("/usr/bin/pacman") {
                node.permissions = permissions::Permissions(0o755);
            }
            fs.put_file("/etc/pacman.conf", "[options]\nArchitecture = auto\nCheckSpace\nSigLevel = Required DatabaseOptional\nLocalFileSigLevel = Optional\n\n[core]\nInclude = /etc/pacman.d/mirrorlist\n\n[extra]\nInclude = /etc/pacman.d/mirrorlist\n", now);
            fs.put_file("/etc/pacman.d/mirrorlist", "## Arch Linux repository mirrorlist\nServer = https://geo.mirror.pkgbuild.com/$repo/os/$arch\nServer = https://mirror.rackspace.com/archlinux/$repo/os/$arch\n", now);
            fs.put_file(
                "/etc/fstab",
                "# Static information about the filesystems.\n# <file system> <dir> <type> <options> <dump> <pass>\nUUID=7c2b7d42-4b9d-4f5c-a101-6d29aa9c1841 / ext4 rw,relatime 0 1\nUUID=4A1B-2C3D /boot vfat rw,relatime,fmask=0022,dmask=0022 0 2\n",
                now,
            );
            fs.put_file("/etc/machine-id", "f5c9912df4894de5a9320e904a3cc527\n", now);
            fs.put_file(
                "/etc/nsswitch.conf",
                "passwd: files systemd\ngroup: files systemd\nshadow: files\ngshadow: files\nhosts: files mymachines resolve [!UNAVAIL=return] dns myhostname\nnetworks: files\nprotocols: files\nservices: files\nethers: files\nrpc: files\n",
                now,
            );
            fs.put_file(
                "/etc/profile",
                "# /etc/profile\n# System-wide environment and startup programs.\nexport PATH=/usr/local/sbin:/usr/local/bin:/usr/bin\nif [ -n \"${BASH_VERSION-}\" ]; then\n  [ -f /etc/bash.bashrc ] && . /etc/bash.bashrc\nfi\n",
                now,
            );
            fs.put_file(
                "/etc/ld.so.conf",
                "/usr/local/lib\ninclude /etc/ld.so.conf.d/*.conf\n",
                now,
            );
            fs.put_file("/etc/makepkg.conf", "CARCH=\"x86_64\"\nCHOST=\"x86_64-pc-linux-gnu\"\nCFLAGS=\"-march=x86-64 -mtune=generic -O2 -pipe -fno-plt\"\nCXXFLAGS=\"$CFLAGS -Wp,-D_GLIBCXX_ASSERTIONS\"\nLDFLAGS=\"-Wl,-O1,--sort-common,--as-needed,-z,relro,-z,now\"\nMAKEFLAGS=\"-j2\"\nCOMPRESSZST=(zstd -c -T0 --ultra -20 -)\n", now);
            fs.put_file(
                "/etc/locale.gen",
                "#en_US.UTF-8 UTF-8\n#en_GB.UTF-8 UTF-8\n",
                now,
            );
            fs.put_file("/etc/locale.conf", "LANG=en_US.UTF-8\n", now);
            fs.put_file(
                "/usr/lib/systemd/system/systemd-journald.service",
                "[Unit]\nDescription=Journal Service\nDocumentation=man:systemd-journald.service(8)\nDefaultDependencies=no\nBefore=sysinit.target\n\n[Service]\nExecStart=/usr/lib/systemd/systemd-journald\nRestart=always\n",
                now,
            );
            fs.put_file(
                "/usr/lib/systemd/system/systemd-journald.socket",
                "[Unit]\nDescription=Journal Socket\nDocumentation=man:systemd-journald.service(8)\nDefaultDependencies=no\nBefore=sockets.target\n\n[Socket]\nListenStream=/run/systemd/journal/socket\nSocketMode=0666\nPassCredentials=yes\n\n[Install]\nWantedBy=sockets.target\n",
                now,
            );
            fs.put_file("/etc/ssh/sshd_config", "Port 22\nPermitRootLogin prohibit-password\nPubkeyAuthentication yes\nPasswordAuthentication yes\nAuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2\nSubsystem sftp /usr/lib/ssh/sftp-server\n", now);
            fs.put_file(
                "/etc/ssh/ssh_config",
                "Host *\n    SendEnv LANG LC_*\n    HashKnownHosts yes\n",
                now,
            );
        }
        fs.put_file(
            &format!("{home}/README.txt"),
            "Internal application server.\n",
            now,
        );
        fs.age_image_nodes(now);
        fs
    }

    fn age_image_nodes(&mut self, now: DateTime<Utc>) {
        for (path, node) in &mut self.nodes {
            let hash = path.bytes().fold(2_166_136_261_u32, |hash, byte| {
                (hash ^ u32::from(byte)).wrapping_mul(16_777_619)
            });
            let days_old = 21 + i64::from(hash % 180);
            node.modified_at = now - chrono::Duration::days(days_old);
        }
    }

    pub fn upgrade_linux_layout(&mut self, baseline: &Self, now: DateTime<Utc>) {
        if self.distribution == Distribution::Windows {
            return;
        }
        for (alias, target) in [
            ("/bin", "/usr/bin"),
            ("/sbin", "/usr/sbin"),
            ("/lib", "/usr/lib"),
            ("/lib64", "/usr/lib64"),
        ] {
            if self.nodes.get(alias).is_some_and(Node::is_dir) {
                let prefix = format!("{alias}/");
                let children = self
                    .nodes
                    .keys()
                    .filter(|path| path.starts_with(&prefix))
                    .cloned()
                    .collect::<Vec<_>>();
                for old_path in &children {
                    let suffix = old_path.strip_prefix(alias).unwrap_or_default();
                    let new_path = format!("{target}{suffix}");
                    if !self.nodes.contains_key(&new_path) {
                        if let Some(node) = self.nodes.get(old_path).cloned() {
                            self.nodes.insert(new_path, node);
                        }
                    }
                }
                for old_path in children {
                    self.nodes.remove(&old_path);
                }
            }
            self.nodes.insert(alias.into(), Node::symlink(target, now));
        }
        for (path, node) in &baseline.nodes {
            if matches!(
                path.as_str(),
                "/bin" | "/sbin" | "/lib" | "/lib64" | "/etc/passwd" | "/etc/group" | "/etc/shadow"
            ) {
                continue;
            }
            self.nodes
                .entry(path.clone())
                .or_insert_with(|| node.clone());
        }
        for path in ["/etc/passwd", "/etc/group", "/etc/shadow"] {
            if let (Some(existing), Some(fresh)) =
                (self.nodes.get(path).cloned(), baseline.nodes.get(path))
            {
                let (NodeKind::File(existing_bytes), NodeKind::File(fresh_bytes)) =
                    (&existing.kind, &fresh.kind)
                else {
                    continue;
                };
                let mut rows = String::from_utf8_lossy(&existing_bytes)
                    .lines()
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                let present = rows
                    .iter()
                    .filter_map(|line| line.split(':').next().map(str::to_owned))
                    .collect::<std::collections::BTreeSet<_>>();
                for line in String::from_utf8_lossy(fresh_bytes).lines() {
                    if line
                        .split(':')
                        .next()
                        .is_some_and(|name| !present.contains(name))
                    {
                        rows.push(line.to_owned());
                    }
                }
                let mut node = existing;
                node.kind = NodeKind::File(format!("{}\n", rows.join("\n")).into_bytes());
                if path == "/etc/shadow" {
                    node.group = "shadow".into();
                    node.permissions = permissions::Permissions(0o640);
                }
                self.nodes.insert(path.into(), node);
            }
        }
        if let Some(node) = self.nodes.get_mut("/tmp") {
            node.permissions = permissions::Permissions(0o1777);
        }
        if let Some(node) = self.nodes.get_mut("/var/tmp") {
            node.permissions = permissions::Permissions(0o1777);
        }
        if let Some(node) = self.nodes.get_mut("/root") {
            node.permissions = permissions::Permissions(0o700);
        }
    }

    /// Add newer Windows baseline files to a persisted virtual machine image
    /// without replacing operator-created files or runtime state.
    pub fn upgrade_windows_layout(&mut self, baseline: &Self, now: DateTime<Utc>) {
        if self.distribution != Distribution::Windows {
            return;
        }
        for (path, node) in &baseline.nodes {
            self.nodes
                .entry(path.clone())
                .or_insert_with(|| node.clone());
        }
        self.primary_user = baseline.primary_user.clone();
        self.distribution = Distribution::Windows;
        let home = format!("/C/Users/{}", self.primary_user);
        for (path, node) in self.nodes.iter_mut() {
            if path == &home || path.starts_with(&(home.clone() + "/")) {
                node.owner = self.primary_user.clone();
                node.group = self.primary_user.clone();
            } else if path.starts_with("/C/Windows/")
                || path == "/C/Windows"
                || path.starts_with("/C/Program Files/")
                || path == "/C/Program Files"
                || path.starts_with("/C/Program Files (x86)/")
                || path == "/C/Program Files (x86)"
                || path.starts_with("/Registry/HKLM/")
                || path == "/Registry/HKLM"
            {
                node.owner = "SYSTEM".into();
                node.group = "Administrators".into();
            }
        }
        if let Some(node) = self.nodes.get_mut("/C/Windows/System32/config") {
            node.owner = "SYSTEM".into();
            node.group = "SYSTEM".into();
            node.permissions = permissions::Permissions(0o700);
        }
        for path in ["/Registry/HKLM/SAM", "/Registry/HKLM/SECURITY"] {
            if let Some(node) = self.nodes.get_mut(path) {
                node.owner = "SYSTEM".into();
                node.group = "SYSTEM".into();
                node.permissions = permissions::Permissions(0o700);
            }
        }
        if self.nodes.is_empty() {
            let _ = now;
            *self = baseline.clone();
        }
    }

    fn allowed(&self, path: &str, user: &str, mask: u16) -> Result<bool, FsError> {
        let node = self.node(path)?;
        if user == "root" {
            return Ok(true);
        }
        let bits = if node.owner == user {
            (node.permissions.0 >> 6) & 7
        } else if self.is_group_member(user, &node.group) {
            (node.permissions.0 >> 3) & 7
        } else {
            node.permissions.0 & 7
        };
        Ok(bits & mask == mask)
    }

    fn is_group_member(&self, user: &str, group: &str) -> bool {
        let Some(gid) = self.read("/etc/passwd").ok().and_then(|contents| {
            String::from_utf8_lossy(contents)
                .lines()
                .find(|line| line.split(':').next() == Some(user))
                .and_then(|line| line.split(':').nth(3)?.parse::<u32>().ok())
        }) else {
            return false;
        };
        let group_line = self.read("/etc/group").ok().and_then(|contents| {
            String::from_utf8_lossy(contents)
                .lines()
                .find(|line| line.split(':').next() == Some(group))
                .map(str::to_owned)
        });
        let Some(group_line) = group_line else {
            return false;
        };
        let fields = group_line.split(':').collect::<Vec<_>>();
        fields.get(2).and_then(|value| value.parse::<u32>().ok()) == Some(gid)
            || fields
                .get(3)
                .is_some_and(|members| members.split(',').any(|member| member == user))
    }

    pub fn primary_group(&self, user: &str) -> String {
        let gid = self.read("/etc/passwd").ok().and_then(|contents| {
            String::from_utf8_lossy(contents)
                .lines()
                .find(|line| line.split(':').next() == Some(user))
                .and_then(|line| line.split(':').nth(3)?.parse::<u32>().ok())
        });
        gid.and_then(|gid| {
            self.read("/etc/group").ok().and_then(|contents| {
                String::from_utf8_lossy(contents)
                    .lines()
                    .find(|line| {
                        let fields = line.split(':').collect::<Vec<_>>();
                        fields.get(2).and_then(|value| value.parse::<u32>().ok()) == Some(gid)
                    })
                    .and_then(|line| line.split(':').next())
                    .map(str::to_owned)
            })
        })
        .unwrap_or_else(|| user.to_owned())
    }

    pub fn authorize_traverse(&self, path: &str, user: &str) -> Result<(), FsError> {
        let mut parent = "/";
        if !self.allowed(parent, user, 1)? {
            return Err(FsError::PermissionDenied);
        }
        for (index, _) in path.match_indices('/').skip(1) {
            parent = &path[..index];
            if !self.allowed(parent, user, 1)? {
                return Err(FsError::PermissionDenied);
            }
        }
        Ok(())
    }

    pub fn authorize_read(&self, path: &str, user: &str) -> Result<(), FsError> {
        self.authorize_traverse(path, user)?;
        if self.allowed(path, user, 4)? {
            Ok(())
        } else {
            Err(FsError::PermissionDenied)
        }
    }

    pub fn authorize_list(&self, path: &str, user: &str) -> Result<(), FsError> {
        self.authorize_traverse(path, user)?;
        if self.allowed(path, user, 5)? {
            Ok(())
        } else {
            Err(FsError::PermissionDenied)
        }
    }

    pub fn authorize_enter(&self, path: &str, user: &str) -> Result<(), FsError> {
        self.authorize_traverse(path, user)?;
        if self.allowed(path, user, 1)? {
            Ok(())
        } else {
            Err(FsError::PermissionDenied)
        }
    }

    pub fn authorize_write(&self, path: &str, user: &str) -> Result<(), FsError> {
        self.authorize_traverse(path, user)?;
        if self.exists(path) {
            if self.allowed(path, user, 2)? {
                return Ok(());
            }
        } else {
            let parent = path
                .rsplit_once('/')
                .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
                .ok_or(FsError::InvalidPath)?;
            if self.allowed(parent, user, 3)? {
                return Ok(());
            }
        }
        Err(FsError::PermissionDenied)
    }

    pub fn authorize_remove(&self, path: &str, user: &str) -> Result<(), FsError> {
        self.authorize_traverse(path, user)?;
        let parent = path
            .rsplit_once('/')
            .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
            .ok_or(FsError::InvalidPath)?;
        if !self.allowed(parent, user, 3)? {
            return Err(FsError::PermissionDenied);
        }
        if let Ok(parent_node) = self.node(parent) {
            if parent_node.permissions.0 & 0o1000 != 0 && user != "root" {
                let owner = self.node(path)?.owner.as_str();
                if owner != user && parent_node.owner != user {
                    return Err(FsError::PermissionDenied);
                }
            }
        }
        Ok(())
    }

    pub fn distribution(&self) -> Distribution {
        self.distribution
    }

    pub fn canonicalize(&self, path: &str) -> Result<String, FsError> {
        self.resolve_path(path)
    }

    pub fn is_executable(&self, path: &str) -> bool {
        self.node(path).is_ok_and(|node| {
            matches!(node.kind, NodeKind::File(_)) && node.permissions.0 & 0o111 != 0
        })
    }

    pub fn normalize(cwd: &str, path: &str) -> Result<String, FsError> {
        if path.as_bytes().contains(&0) || path.len() > 4096 {
            return Err(FsError::InvalidPath);
        }
        let joined = if path.starts_with('/') {
            path.to_owned()
        } else if cwd == "/" {
            format!("/{path}")
        } else {
            format!("{cwd}/{path}")
        };
        let mut parts = Vec::new();
        for part in joined.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                value if value.len() <= 255 => parts.push(value),
                _ => return Err(FsError::InvalidPath),
            }
        }
        Ok(if parts.is_empty() {
            "/".into()
        } else {
            format!("/{}", parts.join("/"))
        })
    }

    fn resolve_path(&self, path: &str) -> Result<String, FsError> {
        let mut pending = path
            .split('/')
            .filter(|part| !part.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let mut resolved = Vec::<String>::new();
        let mut links_followed = 0;
        let mut index = 0;
        while index < pending.len() {
            let part = pending[index].clone();
            if part == "." || part.is_empty() {
                index += 1;
                continue;
            }
            if part == ".." {
                resolved.pop();
                index += 1;
                continue;
            }
            resolved.push(part);
            let candidate = format!("/{}", resolved.join("/"));
            if let Some(Node {
                kind: NodeKind::Symlink(target),
                ..
            }) = self.nodes.get(&candidate)
            {
                links_followed += 1;
                if links_followed > 16 {
                    return Err(FsError::InvalidPath);
                }
                let parent = candidate.rsplit_once('/').map_or("/", |(parent, _)| {
                    if parent.is_empty() { "/" } else { parent }
                });
                let target_path = Self::normalize(parent, target)?;
                let mut replacement = target_path
                    .split('/')
                    .filter(|part| !part.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                replacement.extend(pending[index + 1..].iter().cloned());
                pending = replacement;
                resolved.clear();
                index = 0;
                continue;
            }
            index += 1;
        }
        Ok(if resolved.is_empty() {
            "/".into()
        } else {
            format!("/{}", resolved.join("/"))
        })
    }

    fn destination_path(&self, path: &str) -> Result<String, FsError> {
        if self.nodes.contains_key(path) {
            return self.resolve_path(path);
        }
        let (parent, name) = path.rsplit_once('/').ok_or(FsError::InvalidPath)?;
        let parent = if parent.is_empty() { "/" } else { parent };
        let resolved_parent = self.resolve_path(parent)?;
        Ok(if resolved_parent == "/" {
            format!("/{name}")
        } else {
            format!("{resolved_parent}/{name}")
        })
    }

    pub fn exists(&self, path: &str) -> bool {
        self.resolve_path(path)
            .is_ok_and(|resolved| self.nodes.contains_key(&resolved))
    }

    pub fn is_dir(&self, path: &str) -> bool {
        self.node(path).is_ok_and(Node::is_dir)
    }

    pub fn node(&self, path: &str) -> Result<&Node, FsError> {
        let resolved = self.resolve_path(path)?;
        self.nodes.get(&resolved).ok_or(FsError::NotFound)
    }

    /// Return the directory entry itself, following links in parent components only.
    pub fn lstat(&self, path: &str) -> Result<&Node, FsError> {
        let (parent, name) = path.rsplit_once('/').ok_or(FsError::InvalidPath)?;
        let parent = if parent.is_empty() { "/" } else { parent };
        let resolved_parent = self.resolve_path(parent)?;
        let physical_path = if resolved_parent == "/" {
            format!("/{name}")
        } else {
            format!("{resolved_parent}/{name}")
        };
        self.nodes.get(&physical_path).ok_or(FsError::NotFound)
    }

    pub fn node_mut(&mut self, path: &str) -> Result<&mut Node, FsError> {
        let resolved = self.resolve_path(path)?;
        self.nodes.get_mut(&resolved).ok_or(FsError::NotFound)
    }

    pub fn readlink(&self, path: &str) -> Result<&str, FsError> {
        let (parent, name) = path.rsplit_once('/').ok_or(FsError::InvalidPath)?;
        let parent = if parent.is_empty() { "/" } else { parent };
        let resolved_parent = self.resolve_path(parent)?;
        let physical_path = if resolved_parent == "/" {
            format!("/{name}")
        } else {
            format!("{resolved_parent}/{name}")
        };
        match self.nodes.get(&physical_path).map(|node| &node.kind) {
            Some(NodeKind::Symlink(target)) => Ok(target),
            Some(_) => Err(FsError::InvalidPath),
            None => Err(FsError::NotFound),
        }
    }

    pub fn read(&self, path: &str) -> Result<&[u8], FsError> {
        match &self.node(path)?.kind {
            NodeKind::File(data) => Ok(data),
            NodeKind::Directory => Err(FsError::IsDirectory),
            NodeKind::Symlink(_) => Err(FsError::NotFound),
        }
    }

    pub fn list(&self, path: &str) -> Result<Vec<(String, &Node)>, FsError> {
        let path = self.resolve_path(path)?;
        if !self.node(&path)?.is_dir() {
            return Err(FsError::NotDirectory);
        }
        let prefix = if path == "/" {
            "/".to_owned()
        } else {
            format!("{path}/")
        };
        Ok(self
            .nodes
            .iter()
            .filter_map(|(candidate, node)| {
                let rest = candidate.strip_prefix(&prefix)?;
                (!rest.is_empty() && !rest.contains('/')).then(|| (rest.to_owned(), node))
            })
            .collect())
    }

    pub fn put_file(&mut self, path: &str, content: impl Into<Vec<u8>>, now: DateTime<Utc>) {
        let path = self
            .destination_path(path)
            .unwrap_or_else(|_| path.to_owned());
        let mut node = Node::file(content, now);
        let home = if self.distribution == Distribution::Windows {
            format!("/C/Users/{}", self.primary_user)
        } else {
            format!("/home/{}", self.primary_user)
        };
        if path == home || path.starts_with(&(home + "/")) {
            node.owner = self.primary_user.clone();
            node.group = self.primary_user.clone();
        } else if path == "/C/Users/Public" || path.starts_with("/C/Users/Public/") {
            node.owner = self.primary_user.clone();
            node.group = "Users".into();
        }
        self.nodes.insert(path, node);
    }

    pub fn put_symlink(&mut self, path: &str, target: &str, now: DateTime<Utc>) {
        self.nodes
            .insert(path.to_owned(), Node::symlink(target, now));
    }

    pub fn install_bait(
        &mut self,
        bait: &BaitFile,
        path: &str,
        now: DateTime<Utc>,
    ) -> Result<(), FsError> {
        if self.is_dir(path) {
            return Err(FsError::IsDirectory);
        }
        let parent = path.rsplit_once('/').ok_or(FsError::InvalidPath)?.0;
        let mut current = String::new();
        for part in parent.split('/').filter(|part| !part.is_empty()) {
            current.push('/');
            current.push_str(part);
            if !self.exists(&current) {
                self.mkdir(&current, now)?;
            }
            if !self.is_dir(&current) {
                return Err(FsError::NotDirectory);
            }
        }
        self.write(path, bait.content.as_bytes().to_vec(), now)
    }

    fn require_parent(&self, path: &str) -> Result<(), FsError> {
        let parent = path
            .rsplit_once('/')
            .map(|(p, _)| if p.is_empty() { "/" } else { p });
        let resolved_parent = parent.map(|p| self.resolve_path(p)).transpose()?;
        match resolved_parent.as_deref().and_then(|p| self.nodes.get(p)) {
            Some(node) if node.is_dir() => Ok(()),
            Some(_) => Err(FsError::NotDirectory),
            None => Err(FsError::NotFound),
        }
    }

    pub fn touch(&mut self, path: &str, now: DateTime<Utc>) -> Result<(), FsError> {
        if self.exists(path) {
            let node = self.node_mut(path)?;
            if node.is_dir() {
                return Err(FsError::IsDirectory);
            }
            node.modified_at = now;
            return Ok(());
        }
        if self.nodes.len() >= MAX_NODES {
            return Err(FsError::NoSpace);
        }
        let destination = self.destination_path(path)?;
        self.require_parent(&destination)?;
        self.put_file(&destination, Vec::new(), now);
        Ok(())
    }

    pub fn mkdir(&mut self, path: &str, now: DateTime<Utc>) -> Result<(), FsError> {
        if self.exists(path) {
            return Err(FsError::Exists);
        }
        if self.nodes.len() >= MAX_NODES {
            return Err(FsError::NoSpace);
        }
        let destination = self.destination_path(path)?;
        self.require_parent(&destination)?;
        let mut node = Node::directory(now);
        let home = if self.distribution == Distribution::Windows {
            format!("/C/Users/{}", self.primary_user)
        } else {
            format!("/home/{}", self.primary_user)
        };
        if path == home || path.starts_with(&(home + "/")) {
            node.owner = self.primary_user.clone();
            node.group = self.primary_user.clone();
        } else if path == "/C/Users/Public" || path.starts_with("/C/Users/Public/") {
            node.owner = self.primary_user.clone();
            node.group = "Users".into();
        }
        self.nodes.insert(destination, node);
        Ok(())
    }

    pub fn write(&mut self, path: &str, data: Vec<u8>, now: DateTime<Utc>) -> Result<(), FsError> {
        if data.len() > MAX_FILE_BYTES {
            return Err(FsError::NoSpace);
        }
        let destination = self.destination_path(path)?;
        self.require_parent(&destination)?;
        if self.is_dir(&destination) {
            return Err(FsError::IsDirectory);
        }
        if !self.nodes.contains_key(&destination) && self.nodes.len() >= MAX_NODES {
            return Err(FsError::NoSpace);
        }
        let previous = self.nodes.get(&destination).map_or(0, Node::len);
        let total: usize = self
            .nodes
            .values()
            .filter(|node| !node.is_dir())
            .map(Node::len)
            .sum();
        if total.saturating_sub(previous).saturating_add(data.len()) > MAX_TOTAL_FILE_BYTES {
            return Err(FsError::NoSpace);
        }
        let metadata = self
            .nodes
            .get(&destination)
            .map(|node| (node.owner.clone(), node.group.clone(), node.permissions));
        self.put_file(&destination, data, now);
        if let Some((owner, group, permissions)) = metadata {
            if let Some(node) = self.nodes.get_mut(&destination) {
                node.owner = owner;
                node.group = group;
                node.permissions = permissions;
            }
        }
        Ok(())
    }

    pub fn chmod(
        &mut self,
        path: &str,
        user: &str,
        mode: u16,
        now: DateTime<Utc>,
    ) -> Result<(), FsError> {
        let node = self.node_mut(path)?;
        if user != "root" && node.owner != user {
            return Err(FsError::PermissionDenied);
        }
        node.permissions = permissions::Permissions(mode & 0o7777);
        node.modified_at = now;
        Ok(())
    }

    pub fn remove(&mut self, path: &str, recursive: bool) -> Result<(), FsError> {
        if path == "/" || path == "/etc" || path == "/bin" {
            return Err(FsError::Forbidden);
        }
        let actual = if matches!(
            self.nodes.get(path).map(|node| &node.kind),
            Some(NodeKind::Symlink(_))
        ) {
            path.to_owned()
        } else {
            self.resolve_path(path)?
        };
        let node = self.nodes.get(&actual).ok_or(FsError::NotFound)?;
        if node.is_dir() {
            let prefix = format!("{actual}/");
            let has_children = self.nodes.keys().any(|p| p.starts_with(&prefix));
            if has_children && !recursive {
                return Err(FsError::NotEmpty);
            }
            if recursive {
                self.nodes.retain(|p, _| !p.starts_with(&prefix));
            }
        }
        self.nodes.remove(&actual);
        Ok(())
    }

    pub fn copy(&mut self, source: &str, target: &str, now: DateTime<Utc>) -> Result<(), FsError> {
        let data = self.read(source)?.to_vec();
        self.write(target, data, now)
    }

    pub fn rename(
        &mut self,
        source: &str,
        target: &str,
        now: DateTime<Utc>,
    ) -> Result<(), FsError> {
        self.copy(source, target, now)?;
        self.remove(source, false)
    }

    pub fn all_paths(&self) -> impl Iterator<Item = &str> {
        self.nodes.keys().map(String::as_str)
    }
}

#[cfg(test)]
mod snapshot_structure_tests {
    use super::*;

    #[test]
    fn generated_os_profiles_have_complete_directory_parents() {
        let now = Utc::now();
        for distribution in [
            Distribution::Ubuntu,
            Distribution::Debian,
            Distribution::Arch,
        ] {
            let fs =
                VirtualFileSystem::linux_with_profile("srv-app-01", "admin", distribution, now);
            let invalid = fs.nodes.iter().find_map(|(path, _)| {
                if path == "/" {
                    return None;
                }
                let parent = path
                    .rsplit_once('/')
                    .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })?;
                (!fs.nodes.get(parent).is_some_and(Node::is_dir))
                    .then(|| (path.clone(), parent.to_owned()))
            });
            assert!(
                invalid.is_none(),
                "{distribution:?}: invalid parent {invalid:?}"
            );
            assert!(
                fs.validate_snapshot().is_ok(),
                "{distribution:?}: {:?}",
                fs.validate_snapshot().unwrap_err()
            );
        }
    }
}
