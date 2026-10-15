//! Virtual Linux package state. No host package manager or network access is used.
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::filesystem::node::NodeKind;
use crate::{
    config::Distribution,
    filesystem::{FsError, VirtualFileSystem},
};

pub struct Package {
    pub name: &'static str,
    pub version: &'static str,
    pub description: &'static str,
    pub command: Option<&'static str>,
    pub archive_kib: u32,
    pub installed_kib: u32,
}

pub const CATALOG: &[Package] = &[
    Package {
        name: "nginx",
        version: "1.18.0-6ubuntu14.21",
        description: "small, powerful, scalable web/proxy server",
        command: Some("/usr/sbin/nginx"),
        archive_kib: 528,
        installed_kib: 1696,
    },
    Package {
        name: "postgresql",
        version: "14+238",
        description: "object-relational SQL database",
        command: Some("/usr/bin/psql"),
        archive_kib: 3800,
        installed_kib: 15000,
    },
    Package {
        name: "redis-server",
        version: "5:6.0.16-1ubuntu1.2",
        description: "persistent key-value database",
        command: Some("/usr/bin/redis-server"),
        archive_kib: 1100,
        installed_kib: 4300,
    },
    Package {
        name: "mysql-server",
        version: "8.0.36-0ubuntu0.22.04.1",
        description: "MySQL database server binaries and system service",
        command: Some("/usr/sbin/mysqld"),
        archive_kib: 28000,
        installed_kib: 190000,
    },
    Package {
        name: "curl",
        version: "7.81.0-1ubuntu1.29",
        description: "command line tool for transferring data",
        command: Some("/usr/bin/curl"),
        archive_kib: 194,
        installed_kib: 495,
    },
    Package {
        name: "vim",
        version: "2:8.2.3995-1ubuntu2.36",
        description: "Vi IMproved - enhanced vi editor",
        command: Some("/usr/bin/vim"),
        archive_kib: 1750,
        installed_kib: 4500,
    },
];

#[derive(Clone, Copy, Debug)]
pub struct ArchPackageSpec {
    pub name: &'static str,
    pub version: &'static str,
    pub description: &'static str,
    pub repository: &'static str,
    pub files: &'static [&'static str],
    pub dependencies: &'static [&'static str],
    pub installed_by_default: bool,
}

#[derive(Clone, Debug)]
pub struct ArchLocalPackage {
    pub name: String,
    pub version: String,
    pub description: String,
    pub architecture: String,
    pub repository: String,
    pub reason: u8,
    pub install_date: String,
    pub build_date: String,
    pub installed_size: u64,
    pub dependencies: Vec<String>,
    pub files: Vec<String>,
}

const COREUTIL_FILES: &[&str] = &[
    "/usr/bin/ls",
    "/usr/bin/cat",
    "/usr/bin/env",
    "/usr/bin/printenv",
    "/usr/bin/tr",
    "/usr/bin/seq",
    "/usr/bin/wc",
    "/usr/bin/sort",
    "/usr/bin/rmdir",
    "/usr/bin/nproc",
    "/usr/bin/who",
    "/usr/bin/users",
    "/usr/bin/df",
    "/usr/bin/du",
    "/usr/bin/printf",
    "/usr/bin/chmod",
    "/usr/bin/stat",
    "/usr/bin/groups",
    "/usr/bin/readlink",
    "/usr/bin/whoami",
    "/usr/bin/id",
    "/usr/bin/uname",
    "/usr/bin/hostname",
    "/usr/bin/date",
    "/usr/bin/pwd",
    "/usr/bin/mkdir",
    "/usr/bin/touch",
    "/usr/bin/rm",
    "/usr/bin/cp",
    "/usr/bin/mv",
    "/usr/bin/head",
    "/usr/bin/tail",
];

const ARCH_PACKAGES: &[ArchPackageSpec] = &[
    ArchPackageSpec {
        name: "filesystem",
        version: "2025.10.12-1",
        description: "Base filesystem",
        repository: "core",
        files: &[
            "/etc/arch-release",
            "/etc/fstab",
            "/etc/hostname",
            "/etc/hosts",
            "/etc/issue",
            "/etc/ld.so.conf",
            "/etc/machine-id",
            "/etc/nsswitch.conf",
            "/etc/os-release",
            "/etc/profile",
            "/usr/lib/os-release",
            "/etc/passwd",
            "/etc/group",
            "/etc/shadow",
            "/etc/shells",
        ],
        dependencies: &[],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "bash",
        version: "5.3.20-1",
        description: "The GNU Bourne Again shell",
        repository: "core",
        files: &["/usr/bin/bash", "/usr/bin/rbash", "/usr/bin/sh"],
        dependencies: &["glibc"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "glibc",
        version: "2.44+r50+g1848099f063e-1",
        description: "GNU C Library",
        repository: "core",
        files: &[
            "/usr/bin/getent",
            "/etc/locale.gen",
            "/usr/lib/libc.so.6",
            "/usr/lib/ld-linux-x86-64.so.2",
        ],
        dependencies: &["filesystem"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "linux",
        version: "6.17.0.arch1-1",
        description: "The Linux kernel and modules",
        repository: "core",
        files: &[
            "/boot/vmlinuz-linux",
            "/usr/lib/modules/",
            "/usr/lib/modules/6.17.0-arch1-1/",
            "/usr/lib/modules/6.17.0-arch1-1/kernel/",
            "/usr/lib/modules/6.17.0-arch1-1/kernel/drivers/",
            "/usr/lib/modules/6.17.0-arch1-1/kernel/drivers/net/",
            "/usr/lib/modules/6.17.0-arch1-1/kernel/drivers/net/virtio_net.ko.zst",
            "/usr/lib/modules/6.17.0-arch1-1/kernel/fs/",
            "/usr/lib/modules/6.17.0-arch1-1/kernel/fs/ext4/",
            "/usr/lib/modules/6.17.0-arch1-1/kernel/fs/ext4/ext4.ko.zst",
            "/usr/lib/modules/6.17.0-arch1-1/modules.alias",
            "/usr/lib/modules/6.17.0-arch1-1/modules.builtin",
            "/usr/lib/modules/6.17.0-arch1-1/modules.dep",
            "/usr/lib/modules/6.17.0-arch1-1/modules.order",
            "/usr/lib/modules/6.17.0-arch1-1/pkgbase",
        ],
        dependencies: &["coreutils", "kmod", "initramfs"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "kmod",
        version: "34.2-1",
        description: "Linux kernel module management tools and library",
        repository: "core",
        files: &[
            "/usr/bin/depmod",
            "/usr/bin/insmod",
            "/usr/bin/lsmod",
            "/usr/bin/modinfo",
            "/usr/bin/modprobe",
            "/usr/bin/rmmod",
        ],
        dependencies: &["glibc"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "mkinitcpio",
        version: "40-2",
        description: "Modular initramfs image creation utility",
        repository: "core",
        files: &[
            "/usr/bin/mkinitcpio",
            "/etc/mkinitcpio.conf",
            "/usr/lib/initcpio",
        ],
        dependencies: &["bash", "coreutils", "kmod"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "pacman",
        version: "7.1.0.r9.g54d9411-2",
        description: "A library-based package manager with dependency support",
        repository: "core",
        files: &[
            "/usr/bin/pacman",
            "/etc/pacman.conf",
            "/etc/pacman.d/mirrorlist",
            "/etc/makepkg.conf",
        ],
        dependencies: &["bash", "glibc"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "systemd",
        version: "262-1",
        description: "System and service manager",
        repository: "core",
        files: &[
            "/usr/bin/systemd",
            "/usr/bin/systemctl",
            "/usr/bin/hostnamectl",
            "/usr/lib/systemd/systemd",
            "/usr/lib/systemd/systemd-journald",
            "/usr/lib/systemd/systemd-udevd",
            "/usr/lib/systemd/systemd-resolved",
            "/usr/lib/systemd/systemd-timesyncd",
            "/usr/lib/systemd/system/systemd-journald.service",
            "/usr/lib/systemd/system/systemd-journald.socket",
            "/usr/lib/systemd/system/systemd-resolved.service",
            "/etc/resolv.conf",
        ],
        dependencies: &["bash", "glibc"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "dbus-broker",
        version: "36-2",
        description: "Linux implementation of D-Bus message bus",
        repository: "extra",
        files: &[
            "/usr/bin/dbus-broker",
            "/usr/bin/dbus-broker-launch",
            "/usr/lib/systemd/system/dbus-broker.service",
        ],
        dependencies: &["glibc", "systemd"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "openssh",
        version: "10.6p1-1",
        description: "SSH protocol implementation for remote login, command execution and file transfer",
        repository: "core",
        files: &[
            "/usr/bin/ssh",
            "/usr/bin/ssh-keygen",
            "/usr/bin/sshd",
            "/etc/ssh/ssh_config",
            "/etc/ssh/sshd_config",
            "/usr/lib/ssh/sftp-server",
            "/usr/lib/systemd/system/sshd.service",
        ],
        dependencies: &["glibc", "systemd"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "coreutils",
        version: "9.12-2",
        description: "The basic file, shell and text manipulation utilities",
        repository: "core",
        files: COREUTIL_FILES,
        dependencies: &["glibc"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "util-linux",
        version: "2.41.1-1",
        description: "Miscellaneous system utilities for Linux",
        repository: "core",
        files: &[
            "/usr/bin/mount",
            "/usr/bin/findmnt",
            "/usr/bin/lscpu",
            "/usr/bin/lsblk",
        ],
        dependencies: &["glibc", "systemd"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "iputils",
        version: "20240905-1",
        description: "Network monitoring tools, including ping",
        repository: "core",
        files: &["/usr/bin/ping"],
        dependencies: &["glibc"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "file",
        version: "5.46-5",
        description: "File type identification utility",
        repository: "extra",
        files: &["/usr/bin/file"],
        dependencies: &["glibc"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "grep",
        version: "3.12-1",
        description: "A string search utility",
        repository: "core",
        files: &["/usr/bin/grep"],
        dependencies: &["glibc"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "findutils",
        version: "4.10.0-2",
        description: "GNU utilities to locate files",
        repository: "core",
        files: &["/usr/bin/find"],
        dependencies: &["glibc"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "procps-ng",
        version: "4.0.7-1",
        description: "Utilities for monitoring your system and its processes",
        repository: "core",
        files: &[
            "/usr/bin/free",
            "/usr/bin/pgrep",
            "/usr/bin/pidof",
            "/usr/bin/ps",
            "/usr/bin/top",
            "/usr/bin/uptime",
            "/usr/bin/kill",
            "/usr/bin/w",
        ],
        dependencies: &["glibc", "systemd"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "iproute2",
        version: "6.17.0-1",
        description: "IP routing utilities",
        repository: "core",
        files: &["/usr/bin/ip", "/usr/bin/ss"],
        dependencies: &["glibc"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "git",
        version: "2.51.0-1",
        description: "The fast distributed version control system",
        repository: "extra",
        files: &["/usr/bin/git"],
        dependencies: &["bash", "glibc", "openssh"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "tar",
        version: "1.35-2",
        description: "Utility used to store, backup, and transport files",
        repository: "core",
        files: &["/usr/bin/tar"],
        dependencies: &["glibc"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "unzip",
        version: "6.0-22",
        description: "For extracting and viewing files in .zip archives",
        repository: "extra",
        files: &["/usr/bin/unzip"],
        dependencies: &["glibc"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "nano",
        version: "8.6-1",
        description: "Pico editor clone with enhancements",
        repository: "extra",
        files: &["/usr/bin/nano"],
        dependencies: &["glibc"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "which",
        version: "2.23-1",
        description: "A utility to show the full path of commands",
        repository: "extra",
        files: &["/usr/bin/which"],
        dependencies: &["glibc"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "shadow",
        version: "4.18.0-1",
        description: "Password and account management tools",
        repository: "core",
        files: &["/usr/bin/nologin", "/usr/bin/su"],
        dependencies: &["glibc"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "sudo",
        version: "1.9.17.p2-1",
        description: "Give certain users the ability to run some commands as root",
        repository: "extra",
        files: &["/usr/bin/sudo", "/etc/sudoers", "/etc/sudoers.d"],
        dependencies: &["glibc"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "net-tools",
        version: "2.10-3",
        description: "Linux networking tools",
        repository: "extra",
        files: &["/usr/bin/netstat"],
        dependencies: &["glibc"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "cronie",
        version: "1.7.2-2",
        description: "Daemon that runs specified programs at scheduled times",
        repository: "extra",
        files: &[
            "/usr/bin/crond",
            "/usr/bin/crontab",
            "/usr/lib/systemd/system/cronie.service",
        ],
        dependencies: &["glibc"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "docker",
        version: "1:29.0.0-1",
        description: "Pack, ship and run any application as a lightweight container",
        repository: "extra",
        files: &[
            "/usr/bin/docker",
            "/usr/bin/dockerd",
            "/usr/bin/containerd",
            "/usr/bin/containerd-shim-runc-v2",
            "/usr/bin/runc",
            "/usr/lib/systemd/system/docker.service",
        ],
        dependencies: &["glibc"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "docker-compose",
        version: "2.40.3-1",
        description: "Define and run multi-container applications with Docker",
        repository: "extra",
        files: &["/usr/bin/docker-compose"],
        dependencies: &["docker", "glibc"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "postgresql",
        version: "18.6-2",
        description: "Sophisticated object-relational DBMS",
        repository: "extra",
        files: &[
            "/usr/bin/postgres",
            "/usr/bin/psql",
            "/usr/lib/systemd/system/postgresql.service",
            "/var/lib/postgres",
        ],
        dependencies: &["glibc", "systemd"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "nginx",
        version: "1.30.5-1",
        description: "Lightweight HTTP server and IMAP/POP3 proxy server",
        repository: "extra",
        files: &[
            "/etc/nginx/nginx.conf",
            "/etc/nginx/mime.types",
            "/etc/nginx/conf.d",
            "/etc/nginx/fastcgi.conf",
            "/etc/nginx/fastcgi_params",
            "/etc/nginx/koi-utf",
            "/etc/nginx/koi-win",
            "/etc/nginx/scgi_params",
            "/etc/nginx/uwsgi_params",
            "/etc/nginx/win-utf",
            "/usr/bin/nginx",
            "/usr/lib/systemd/system/nginx.service",
            "/usr/share/nginx/html/index.html",
            "/usr/share/nginx/html/50x.html",
            "/var/lib/nginx",
            "/var/log/nginx",
        ],
        dependencies: &["glibc"],
        installed_by_default: false,
    },
    ArchPackageSpec {
        name: "curl",
        version: "8.16.0-1",
        description: "An URL retrieval utility and library",
        repository: "core",
        files: &["/usr/bin/curl"],
        dependencies: &["glibc"],
        installed_by_default: false,
    },
    ArchPackageSpec {
        name: "vim",
        version: "9.1.1780-1",
        description: "Vi Improved, a highly configurable, improved version of the vi text editor",
        repository: "extra",
        files: &["/usr/bin/vim"],
        dependencies: &["glibc"],
        installed_by_default: false,
    },
    ArchPackageSpec {
        name: "valkey",
        version: "9.1.2-1",
        description: "An in-memory database that persists on disk",
        repository: "extra",
        files: &[
            "/usr/bin/valkey-server",
            "/usr/bin/valkey-cli",
            "/usr/lib/systemd/system/valkey.service",
            "/etc/valkey/valkey.conf",
            "/var/lib/valkey",
        ],
        dependencies: &["glibc", "systemd"],
        installed_by_default: true,
    },
    ArchPackageSpec {
        name: "mariadb",
        version: "12.1.2-1",
        description: "Fast, reliable, scalable, and easy to use open-source relational database system",
        repository: "extra",
        files: &[
            "/usr/bin/mariadbd",
            "/usr/bin/mariadb",
            "/usr/bin/mysql",
            "/usr/lib/systemd/system/mariadb.service",
            "/etc/my.cnf",
            "/var/lib/mysql/",
        ],
        dependencies: &["glibc", "systemd"],
        installed_by_default: false,
    },
    ArchPackageSpec {
        name: "company-tools",
        version: "2.8.4-1",
        description: "Internal service management utilities",
        repository: "local",
        files: &["/usr/bin/companyctl"],
        dependencies: &["glibc"],
        installed_by_default: true,
    },
];

pub fn arch_repository() -> &'static [ArchPackageSpec] {
    ARCH_PACKAGES
}

pub fn arch_lookup(name: &str) -> Option<&'static ArchPackageSpec> {
    ARCH_PACKAGES
        .iter()
        .find(|package| package.name == name && package.repository != "local")
}

pub fn seed_arch_base(fs: &mut VirtualFileSystem, now: DateTime<Utc>) -> Result<(), FsError> {
    ensure_dir(fs, "/var/lib/pacman/local", now)?;
    ensure_dir(fs, "/var/lib/pacman/sync", now)?;
    ensure_dir(fs, "/var/cache/pacman/pkg", now)?;
    for package in ARCH_PACKAGES
        .iter()
        .filter(|package| package.installed_by_default)
    {
        if package.name == "valkey" {
            install_arch(fs, package, now)?;
            continue;
        }
        ensure_package_files(fs, package, now)?;
        let depended_on = ARCH_PACKAGES
            .iter()
            .filter(|candidate| candidate.installed_by_default)
            .any(|candidate| {
                candidate.dependencies.contains(&package.name)
                    || (candidate.name == "linux" && package.name == "mkinitcpio")
            });
        write_local_entry(fs, package, u8::from(depended_on), now)?;
    }
    write_sync_database(fs, now)?;
    Ok(())
}

pub fn arch_local_packages(fs: &VirtualFileSystem) -> Vec<ArchLocalPackage> {
    let Ok(entries) = fs.list("/var/lib/pacman/local") else {
        return Vec::new();
    };
    let mut packages = entries
        .into_iter()
        .filter_map(|(directory, node)| {
            if !node.is_dir() {
                return None;
            }
            let base = format!("/var/lib/pacman/local/{directory}");
            let desc = String::from_utf8_lossy(fs.read(&format!("{base}/desc")).ok()?).into_owned();
            let name = alpm_field(&desc, "NAME")?;
            let version = alpm_field(&desc, "VERSION")?;
            let files_data =
                String::from_utf8_lossy(fs.read(&format!("{base}/files")).unwrap_or_default())
                    .into_owned();
            let files = alpm_section(&files_data, "FILES")
                .unwrap_or_default()
                .lines()
                .filter(|path| !path.is_empty())
                .map(|path| {
                    if path.starts_with('/') {
                        path.to_owned()
                    } else {
                        format!("/{path}")
                    }
                })
                .collect();
            let dependencies = alpm_section(&desc, "DEPENDS")
                .unwrap_or_default()
                .lines()
                .filter(|dependency| !dependency.is_empty())
                .map(str::to_owned)
                .collect();
            Some(ArchLocalPackage {
                name,
                version,
                description: alpm_field(&desc, "DESC").unwrap_or_default(),
                architecture: alpm_field(&desc, "ARCH").unwrap_or_else(|| "x86_64".into()),
                repository: arch_lookup(alpm_field(&desc, "NAME").as_deref()?)
                    .map_or_else(|| "local".into(), |package| package.repository.into()),
                reason: alpm_field(&desc, "REASON")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0),
                install_date: alpm_field(&desc, "INSTALLDATE")
                    .and_then(|value| value.parse::<i64>().ok())
                    .and_then(|timestamp| chrono::DateTime::<Utc>::from_timestamp(timestamp, 0))
                    .map(|date| date.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| "unknown".into()),
                build_date: alpm_field(&desc, "BUILDDATE")
                    .and_then(|value| value.parse::<i64>().ok())
                    .and_then(|timestamp| chrono::DateTime::<Utc>::from_timestamp(timestamp, 0))
                    .map(|date| date.format("%Y-%m-%d").to_string())
                    .unwrap_or_else(|| "unknown".into()),
                installed_size: alpm_field(&desc, "ISIZE")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0),
                dependencies,
                files,
            })
        })
        .collect::<Vec<_>>();
    packages.sort_by(|a, b| a.name.cmp(&b.name));
    packages
}

pub fn arch_installed(fs: &VirtualFileSystem, name: &str) -> Option<ArchLocalPackage> {
    arch_local_packages(fs)
        .into_iter()
        .find(|package| package.name == name)
}

pub fn arch_upgrades(fs: &VirtualFileSystem) -> Vec<(ArchLocalPackage, &'static ArchPackageSpec)> {
    arch_local_packages(fs)
        .into_iter()
        .filter_map(|installed| {
            let available = arch_lookup(&installed.name)?;
            (installed.version != available.version).then_some((installed, available))
        })
        .collect()
}

pub fn write_sync_database(fs: &mut VirtualFileSystem, now: DateTime<Utc>) -> Result<(), FsError> {
    ensure_dir(fs, "/var/lib/pacman/sync", now)?;
    for repository in ["core", "extra"] {
        let records = ARCH_PACKAGES
            .iter()
            .filter(|package| package.repository == repository)
            .map(|package| {
                format!(
                    "{} {}\n{}\n",
                    package.name, package.version, package.description
                )
            })
            .collect::<String>();
        fs.write(
            &format!("/var/lib/pacman/sync/{repository}.db"),
            format!("%ARCH REPOSITORY DATABASE%\n{records}").into_bytes(),
            now,
        )?;
    }
    Ok(())
}

/// Bring persisted Arch images forward with files added to packages already in
/// the base image, without resetting package versions or install reasons.
pub fn migrate_arch_base(fs: &mut VirtualFileSystem, now: DateTime<Utc>) -> Result<(), FsError> {
    let linux = arch_lookup("linux").expect("the Arch image includes the linux package");
    if let Some(installed) = arch_installed(fs, "linux") {
        ensure_package_files(fs, linux, now)?;
        write_local_file_manifest(
            fs,
            &format!("/var/lib/pacman/local/linux-{}", installed.version),
            linux,
            now,
        )?;
    } else {
        install_arch(fs, linux, now)?;
    }

    if let Some(installed) = arch_installed(fs, "systemd")
        && let Some(systemd) = arch_lookup("systemd")
    {
        ensure_package_files(fs, systemd, now)?;
        write_local_file_manifest(
            fs,
            &format!("/var/lib/pacman/local/systemd-{}", installed.version),
            systemd,
            now,
        )?;
    }
    write_sync_database(fs, now)
}

pub fn install_arch(
    fs: &mut VirtualFileSystem,
    package: &ArchPackageSpec,
    now: DateTime<Utc>,
) -> Result<(), FsError> {
    ensure_package_files(fs, package, now)?;
    match package.name {
        "nginx" => {
            ensure_dir(fs, "/etc/nginx", now)?;
            ensure_dir(fs, "/usr/share/nginx/html", now)?;
            ensure_dir(fs, "/usr/lib/systemd/system", now)?;
            ensure_dir(fs, "/var/lib/nginx", now)?;
            ensure_dir(fs, "/var/log/nginx", now)?;
            fs.write("/etc/nginx/nginx.conf", b"user http;\nworker_processes auto;\nevents { worker_connections 768; }\nhttp { include /etc/nginx/mime.types; include /etc/nginx/conf.d/*.conf; }\n".to_vec(), now)?;
            fs.write("/etc/nginx/mime.types", b"types {\n    text/html html htm;\n    text/css css;\n    application/javascript js;\n    application/json json;\n    image/png png;\n    image/jpeg jpeg jpg;\n}\n".to_vec(), now)?;
            fs.write(
                "/usr/bin/nginx",
                b"ELF virtual Arch nginx executable\n".to_vec(),
                now,
            )?;
            set_executable(fs, "/usr/bin/nginx");
            if let Ok(node) = fs.node_mut("/usr/bin/nginx") {
                node.reported_size = Some(1_217_920);
            }
            fs.write("/usr/lib/systemd/system/nginx.service", b"[Unit]\nDescription=A high performance web server and a reverse proxy server\nAfter=network.target\n[Service]\nExecStart=/usr/bin/nginx -g 'daemon off;'\nExecReload=/usr/bin/nginx -s reload\n[Install]\nWantedBy=multi-user.target\n".to_vec(), now)?;
            ensure_dir(fs, "/etc/systemd/system/multi-user.target.wants", now)?;
            fs.put_symlink(
                "/etc/systemd/system/multi-user.target.wants/nginx.service",
                "/usr/lib/systemd/system/nginx.service",
                now,
            );
            fs.write(
                "/usr/share/nginx/html/index.html",
                b"<html><body><h1>Welcome to nginx!</h1></body></html>\n".to_vec(),
                now,
            )?;
            fs.write(
                "/usr/share/nginx/html/50x.html",
                b"<html><body><h1>50x</h1></body></html>\n".to_vec(),
                now,
            )?;
        }
        "postgresql" => {
            ensure_dir(fs, "/var/lib/postgres/data", now)?;
            ensure_dir(fs, "/usr/lib/systemd/system", now)?;
            fs.write(
                "/usr/bin/postgres",
                b"ELF virtual PostgreSQL server\n".to_vec(),
                now,
            )?;
            fs.write(
                "/usr/bin/psql",
                b"ELF virtual PostgreSQL client\n".to_vec(),
                now,
            )?;
            set_executable(fs, "/usr/bin/postgres");
            set_executable(fs, "/usr/bin/psql");
            fs.write("/usr/lib/systemd/system/postgresql.service", b"[Unit]\nDescription=PostgreSQL database server\n[Service]\nUser=postgres\nExecStart=/usr/bin/postgres -D /var/lib/postgres/data\n[Install]\nWantedBy=multi-user.target\n".to_vec(), now)?;
        }
        "openssh" => {
            ensure_dir(fs, "/etc/ssh/sshd_config.d", now)?;
            ensure_dir(fs, "/usr/lib/systemd/system", now)?;
            ensure_dir(fs, "/usr/lib/ssh", now)?;
            for path in ["/usr/bin/ssh", "/usr/bin/ssh-keygen", "/usr/bin/sshd"] {
                if !fs.exists(path) {
                    fs.write(
                        path,
                        format!("ELF virtual OpenSSH executable {path}\n").into_bytes(),
                        now,
                    )?;
                }
                set_executable(fs, path);
            }
            if !fs.exists("/etc/ssh/sshd_config")
                || fs
                    .read("/etc/ssh/sshd_config")
                    .ok()
                    .is_some_and(|contents| {
                        String::from_utf8_lossy(contents).starts_with("virtual Arch package file")
                    })
            {
                fs.write("/etc/ssh/sshd_config", b"Port 22\nPermitRootLogin prohibit-password\nPubkeyAuthentication yes\nPasswordAuthentication yes\nAuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2\nSubsystem sftp /usr/lib/ssh/sftp-server\n".to_vec(), now)?;
            }
            if let Ok(contents) = fs.read("/etc/ssh/ssh_config") {
                if String::from_utf8_lossy(contents).starts_with("virtual Arch package file") {
                    fs.write(
                        "/etc/ssh/ssh_config",
                        b"Host *\n    SendEnv LANG LC_*\n    HashKnownHosts yes\n".to_vec(),
                        now,
                    )?;
                }
            }
            fs.write("/usr/lib/systemd/system/sshd.service", b"[Unit]\nDescription=OpenSSH Daemon\nAfter=network.target\n[Service]\nExecStart=/usr/bin/sshd -D\n[Install]\nWantedBy=multi-user.target\n".to_vec(), now)?;
        }
        "valkey" => {
            ensure_dir(fs, "/etc/valkey", now)?;
            ensure_dir(fs, "/var/lib/valkey", now)?;
            if let Ok(node) = fs.node_mut("/var/lib/valkey") {
                node.owner = "valkey".into();
                node.group = "valkey".into();
                node.permissions = crate::filesystem::permissions::Permissions(0o750);
            }
            ensure_dir(fs, "/usr/lib/systemd/system", now)?;
            for path in ["/usr/bin/valkey-server", "/usr/bin/valkey-cli"] {
                fs.write(
                    path,
                    format!("ELF virtual Valkey executable {path}\n").into_bytes(),
                    now,
                )?;
                set_executable(fs, path);
            }
            fs.write(
                "/etc/valkey/valkey.conf",
                b"bind 127.0.0.1\nport 6379\ndir /var/lib/valkey\n".to_vec(),
                now,
            )?;
            fs.write("/usr/lib/systemd/system/valkey.service", b"[Unit]\nDescription=In-memory data structure store\n[Service]\nUser=valkey\nExecStart=/usr/bin/valkey-server /etc/valkey/valkey.conf\n[Install]\nWantedBy=multi-user.target\n".to_vec(), now)?;
        }
        "mariadb" => {
            ensure_dir(fs, "/var/lib/mysql", now)?;
            ensure_dir(fs, "/etc/my.cnf.d", now)?;
            fs.write(
                "/etc/my.cnf",
                b"!includedir /etc/my.cnf.d\n[mysqld]\nport=13306\nbind-address=0.0.0.0\n".to_vec(),
                now,
            )?;
            fs.write(
                "/etc/my.cnf.d/server.cnf",
                b"[mysqld]\nport=13306\nbind-address=0.0.0.0\n".to_vec(),
                now,
            )?;
            for (path, content) in [
                ("/usr/bin/mysql", "ELF virtual MariaDB-compatible client\n"),
                ("/usr/bin/mariadb", "ELF virtual MariaDB client\n"),
                (
                    "/usr/lib/systemd/system/mariadb.service",
                    "[Unit]\nDescription=MariaDB database server\n[Service]\nExecStart=/usr/bin/mariadbd --defaults-file=/etc/my.cnf\n[Install]\nWantedBy=multi-user.target\n",
                ),
            ] {
                fs.write(path, content.as_bytes().to_vec(), now)?;
                if path.starts_with("/usr/bin/") {
                    set_executable(fs, path);
                }
            }
        }
        _ => {}
    }
    write_local_entry(fs, package, 0, now)
}

pub fn remove_arch(
    fs: &mut VirtualFileSystem,
    package: &ArchLocalPackage,
    now: DateTime<Utc>,
) -> Result<(), FsError> {
    let remaining = arch_local_packages(fs)
        .into_iter()
        .filter(|installed| installed.name != package.name)
        .collect::<Vec<_>>();
    for path in &package.files {
        let clean = path.trim_end_matches('/');
        if clean.is_empty()
            || remaining.iter().any(|other| {
                other
                    .files
                    .iter()
                    .any(|owned| owned.trim_end_matches('/') == clean)
            })
        {
            continue;
        }
        if fs.node(clean).is_ok_and(|node| node.is_dir()) {
            continue;
        }
        if fs.exists(clean) {
            let _ = fs.remove(clean, false);
        }
    }
    if package.name == "nginx" {
        for path in [
            "/etc/systemd/system/multi-user.target.wants/nginx.service",
            "/run/nginx.pid",
        ] {
            if fs.exists(path) {
                let _ = fs.remove(path, false);
            }
        }
    }
    let directory = format!("/var/lib/pacman/local/{}-{}", package.name, package.version);
    if fs.exists(&directory) {
        fs.remove(&directory, true)?;
    }
    let _ = now;
    Ok(())
}

pub fn upgrade_arch(
    fs: &mut VirtualFileSystem,
    package: &ArchLocalPackage,
    available: &'static ArchPackageSpec,
    now: DateTime<Utc>,
) -> Result<(), FsError> {
    let old_directory = format!("/var/lib/pacman/local/{}-{}", package.name, package.version);
    if fs.exists(&old_directory) {
        fs.remove(&old_directory, true)?;
    }
    ensure_package_files(fs, available, now)?;
    write_local_entry(fs, available, package.reason, now)
}

pub fn check_arch_files(
    fs: &VirtualFileSystem,
    package: &ArchLocalPackage,
    detailed: bool,
) -> (usize, usize) {
    let directory = format!("/var/lib/pacman/local/{}-{}", package.name, package.version);
    let mtree = fs
        .read(&format!("{directory}/mtree"))
        .ok()
        .map(String::from_utf8_lossy)
        .map(|value| value.into_owned())
        .unwrap_or_default();
    let expected = mtree
        .lines()
        .filter_map(|line| {
            let mut fields = line.splitn(4, '\t');
            Some((
                fields.next()?.to_owned(),
                fields.next()?.parse::<u16>().ok()?,
                fields.next()?.parse::<usize>().ok()?,
                fields.next()?.to_owned(),
            ))
        })
        .map(|(path, mode, size, digest)| (path, (mode, size, digest)))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut missing = 0;
    let mut altered = 0;
    for listed in &package.files {
        let path = listed.trim_end_matches('/');
        if !fs.exists(path) {
            missing += 1;
            continue;
        }
        if !detailed {
            continue;
        }
        let Some((mode, size, digest)) = expected.get(path.trim_start_matches('/')) else {
            continue;
        };
        let Ok(node) = fs.lstat(path) else {
            altered += 1;
            continue;
        };
        let actual = match &node.kind {
            NodeKind::Directory => "directory".to_owned(),
            NodeKind::Symlink(_) => fs
                .readlink(path)
                .map(|target| format!("link:{target}"))
                .unwrap_or_default(),
            NodeKind::File(_) => fs
                .read(path)
                .map(|bytes| {
                    let hash = Sha256::digest(bytes);
                    let hash = hash
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>();
                    format!("sha256:{hash}")
                })
                .unwrap_or_default(),
        };
        let actual_size = node.len();
        if *mode != node.permissions.0 || *size != actual_size || *digest != actual {
            altered += 1;
        }
    }
    (missing, altered)
}

pub fn arch_file_owner(fs: &VirtualFileSystem, target: &str) -> Option<String> {
    let target = fs
        .canonicalize(target)
        .unwrap_or_else(|_| target.to_owned());
    arch_local_packages(fs)
        .into_iter()
        .find(|package| {
            package.files.iter().any(|path| {
                fs.canonicalize(path.trim_end_matches('/'))
                    .unwrap_or_else(|_| path.trim_end_matches('/').to_owned())
                    == target
            })
        })
        .map(|package| package.name)
}

fn ensure_package_files(
    fs: &mut VirtualFileSystem,
    package: &ArchPackageSpec,
    now: DateTime<Utc>,
) -> Result<(), FsError> {
    for listed in package.files {
        let path = listed.trim_end_matches('/');
        if path.is_empty() || path == "/" {
            continue;
        }
        if listed.ends_with('/') || fs.node(path).is_ok_and(|node| node.is_dir()) {
            ensure_dir(fs, path, now)?;
            continue;
        }
        if !fs.exists(path) {
            let parent =
                path.rsplit_once('/').map_or(
                    "/",
                    |(parent, _)| if parent.is_empty() { "/" } else { parent },
                );
            ensure_dir(fs, parent, now)?;
            fs.write(
                path,
                format!("virtual Arch package file: {}\n", package.name).into_bytes(),
                now,
            )?;
        }
        if package.name == "linux"
            && path == "/boot/vmlinuz-linux"
            && let Ok(node) = fs.node_mut(path)
        {
            // Keep the virtual image small while reporting a plausible
            // compressed x86_64 kernel image size to ls/stat and pacman -Qk.
            node.reported_size = Some(15 * 1024 * 1024);
        }
        if (path.starts_with("/usr/bin/")
            || path.starts_with("/usr/lib/systemd/systemd")
            || path.starts_with("/usr/lib/ssh/"))
            && fs
                .node(path)
                .is_ok_and(|node| matches!(&node.kind, NodeKind::File(_)))
        {
            set_executable(fs, path);
        }
    }
    Ok(())
}

fn write_local_entry(
    fs: &mut VirtualFileSystem,
    package: &ArchPackageSpec,
    reason: u8,
    now: DateTime<Utc>,
) -> Result<(), FsError> {
    let directory = format!("/var/lib/pacman/local/{}-{}", package.name, package.version);
    ensure_dir(fs, &directory, now)?;
    let install_date = now.timestamp();
    let (archive_size, installed_size) = arch_package_sizes(package);
    let mut desc = String::new();
    for (field, value) in [
        ("NAME", package.name.to_owned()),
        ("BASE", package.name.to_owned()),
        ("VERSION", package.version.to_owned()),
        ("DESC", package.description.to_owned()),
        ("CSIZE", archive_size.to_string()),
        ("ISIZE", installed_size.to_string()),
        ("URL", "https://archlinux.org/packages/".to_owned()),
        ("ARCH", "x86_64".to_owned()),
        ("BUILDDATE", arch_build_date(package.name).to_string()),
        ("INSTALLDATE", install_date.to_string()),
        (
            "PACKAGER",
            "Arch Linux Package Maintainer <packages@archlinux.org>".to_owned(),
        ),
        ("REASON", reason.to_string()),
        ("VALIDATION", "pgp".to_owned()),
    ] {
        desc.push_str(&format!("%{field}%\n{value}\n\n"));
    }
    if !package.dependencies.is_empty() {
        desc.push_str("%DEPENDS%\n");
        for dependency in package.dependencies {
            desc.push_str(&format!("{dependency}\n"));
        }
        desc.push('\n');
    }
    fs.write(&format!("{directory}/desc"), desc.into_bytes(), now)?;

    write_local_file_manifest(fs, &directory, package, now)
}

fn write_local_file_manifest(
    fs: &mut VirtualFileSystem,
    directory: &str,
    package: &ArchPackageSpec,
    now: DateTime<Utc>,
) -> Result<(), FsError> {
    let mut file_list = String::from("%FILES%\n");
    let mut mtree = String::from("#mtree\n");
    for listed in package.files {
        let clean = listed.trim_end_matches('/');
        let relative = clean.trim_start_matches('/');
        file_list.push_str(relative);
        if listed.ends_with('/') {
            file_list.push('/');
        }
        file_list.push('\n');
        let node = fs.lstat(clean).map_err(|_| FsError::NotFound)?;
        let value = match &node.kind {
            NodeKind::Directory => "directory".to_owned(),
            NodeKind::Symlink(_) => fs
                .readlink(clean)
                .map(|target| format!("link:{target}"))
                .unwrap_or_default(),
            NodeKind::File(_) => {
                let hash = Sha256::digest(fs.read(clean)?);
                let hash = hash
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                format!("sha256:{hash}")
            }
        };
        mtree.push_str(&format!(
            "{relative}\t{}\t{}\t{value}\n",
            node.permissions.0,
            node.len()
        ));
    }
    fs.write(&format!("{directory}/files"), file_list.into_bytes(), now)?;
    fs.write(&format!("{directory}/mtree"), mtree.into_bytes(), now)?;
    Ok(())
}

/// Sizes are tracked in bytes, as in pacman's local ALPM database. Values for
/// the packages used by the Arch profile match the official package catalog
/// snapshot represented by this virtual image; unknown entries retain a
/// conservative estimate until they get explicit catalog metadata.
pub fn arch_package_sizes(package: &ArchPackageSpec) -> (u64, u64) {
    let explicit = match package.name {
        "bash" => (1_900 * 1024, 9_600 * 1024),
        "linux" => (155_000 * 1024, 190_000 * 1024),
        "systemd" => (10_700 * 1024, 40_500 * 1024),
        "openssh" => (1_400 * 1024, 6_800 * 1024),
        "coreutils" => (2_900 * 1024, 17_700 * 1024),
        "procps-ng" => (1_000 * 1024, 2_600 * 1024),
        "nginx" => (658 * 1024, 1_700 * 1024),
        _ => {
            return (
                (package.files.len() as u64).saturating_mul(256 * 1024),
                (package.files.len() as u64).saturating_mul(1024 * 1024),
            );
        }
    };
    explicit
}

fn arch_build_date(package: &str) -> i64 {
    // Epoch seconds for the current Arch package catalog snapshot (UTC).
    match package {
        "bash" => 1_789_430_400,      // 2026-09-15
        "systemd" => 1_790_035_200,   // 2026-09-22
        "openssh" => 1_791_244_800,   // 2026-10-06
        "coreutils" => 1_789_603_200, // 2026-09-17
        "procps-ng" => 1_786_492_800, // 2026-08-12
        "nginx" => 1_789_516_800,     // 2026-09-16
        _ => 1_759_276_800,           // 2025-10-01
    }
}

pub fn arch_build_date_text(package: &str) -> &'static str {
    match package {
        "bash" => "2026-09-15",
        "systemd" => "2026-09-22",
        "openssh" => "2026-10-06",
        "coreutils" => "2026-09-17",
        "procps-ng" => "2026-08-12",
        "nginx" => "2026-09-16",
        _ => "2025-10-01",
    }
}

fn alpm_section<'a>(contents: &'a str, field: &str) -> Option<&'a str> {
    let marker = format!("%{field}%\n");
    let value = contents.split_once(&marker)?.1;
    Some(
        value
            .split_once("\n\n")
            .map_or(value, |(value, _)| value)
            .trim_end(),
    )
}

fn alpm_field(contents: &str, field: &str) -> Option<String> {
    alpm_section(contents, field)?
        .lines()
        .next()
        .map(str::to_owned)
}

fn set_executable(fs: &mut VirtualFileSystem, path: &str) {
    if let Ok(node) = fs.node_mut(path) {
        node.permissions = crate::filesystem::permissions::Permissions(0o755);
    }
}

pub fn lookup(name: &str) -> Option<&'static Package> {
    CATALOG.iter().find(|package| package.name == name)
}

pub fn version_for(package: &Package, distribution: Distribution) -> &'static str {
    if distribution == Distribution::Arch {
        let name = match package.name {
            "redis-server" => "valkey",
            "mysql-server" => "mariadb",
            name => name,
        };
        return arch_lookup(name).map_or(package.version, |arch_package| arch_package.version);
    }
    match (distribution, package.name) {
        (Distribution::Ubuntu, _) => package.version,
        (Distribution::Debian, "nginx") => "1.26.3-3+deb13u9",
        (Distribution::Debian, "postgresql") => "17+276",
        (Distribution::Debian, "redis-server") => "5:7.0.15-5",
        (Distribution::Debian, "mysql-server") => "8.0.43-1~deb13u1",
        (Distribution::Debian, "curl") => "8.14.1-2+deb13u5",
        (Distribution::Debian, "vim") => "2:9.1.1230-2",
        _ => package.version,
    }
}

pub fn registry_path(distribution: Distribution) -> &'static str {
    if distribution == Distribution::Arch {
        "/var/lib/pacman/local"
    } else {
        "/var/lib/dpkg/status"
    }
}

fn debian_package_files(fs: &VirtualFileSystem, package: &str) -> Vec<String> {
    let paths: &[&str] = match package {
        "base-files" => &[
            "/etc/debian_version",
            "/etc/dpkg/origins/debian",
            "/etc/issue",
            "/etc/os-release",
            "/usr/lib/os-release",
            "/etc/hostname",
            "/etc/hosts",
            "/bin",
            "/sbin",
            "/lib",
            "/lib64",
        ],
        "bash" => &["/usr/bin/bash", "/usr/bin/rbash"],
        "coreutils" => &[
            "/usr/bin/ls",
            "/usr/bin/cat",
            "/usr/bin/env",
            "/usr/bin/printenv",
            "/usr/bin/tr",
            "/usr/bin/seq",
            "/usr/bin/wc",
            "/usr/bin/sort",
            "/usr/bin/rmdir",
            "/usr/bin/nproc",
            "/usr/bin/who",
            "/usr/bin/users",
            "/usr/bin/du",
            "/usr/bin/printf",
            "/usr/bin/chmod",
            "/usr/bin/stat",
            "/usr/bin/groups",
            "/usr/bin/readlink",
            "/usr/bin/whoami",
            "/usr/bin/id",
            "/usr/bin/uname",
            "/usr/bin/hostname",
            "/usr/bin/date",
            "/usr/bin/df",
            "/usr/bin/pwd",
            "/usr/bin/mkdir",
            "/usr/bin/touch",
            "/usr/bin/rm",
            "/usr/bin/cp",
            "/usr/bin/mv",
            "/usr/bin/head",
            "/usr/bin/tail",
        ],
        "dash" => &["/usr/bin/dash", "/usr/bin/sh"],
        "dpkg" => &[
            "/usr/bin/dpkg",
            "/usr/bin/dpkg-query",
            "/usr/bin/update-alternatives",
            "/etc/dpkg/dpkg.cfg",
        ],
        "apt" => &[
            "/usr/bin/apt",
            "/usr/bin/apt-get",
            "/usr/bin/apt-cache",
            "/etc/apt/apt.conf.d/01autoremove",
        ],
        "libc6" => &["/usr/bin/getent"],
        "systemd" => &[
            "/usr/bin/systemctl",
            "/usr/bin/hostnamectl",
            "/usr/bin/systemd",
            "/usr/lib/systemd/systemd-journald",
            "/usr/lib/systemd/system/systemd-journald.service",
            "/usr/lib/systemd/systemd-resolved",
            "/usr/lib/systemd/system/systemd-resolved.service",
        ],
        "procps" => &[
            "/usr/bin/uptime",
            "/usr/bin/free",
            "/usr/bin/pgrep",
            "/usr/bin/pidof",
            "/usr/bin/ps",
            "/usr/bin/top",
            "/usr/bin/kill",
            "/usr/bin/w",
        ],
        "iproute2" => &["/usr/bin/ip", "/usr/bin/ss"],
        "net-tools" => &["/usr/bin/netstat"],
        "cron" => &[
            "/usr/bin/crontab",
            "/usr/sbin/cron",
            "/usr/lib/systemd/system/cron.service",
        ],
        "grep" => &["/usr/bin/grep"],
        "findutils" => &["/usr/bin/find"],
        "util-linux" => &[
            "/usr/bin/su",
            "/usr/bin/mount",
            "/usr/bin/findmnt",
            "/usr/bin/lscpu",
            "/usr/bin/lsblk",
        ],
        "sysvinit-utils" => &["/usr/sbin/service"],
        "iputils-ping" => &["/usr/bin/ping"],
        "lsb-release" => &["/usr/bin/lsb_release"],
        "file" => &["/usr/bin/file"],
        "sudo" => &["/usr/bin/sudo", "/etc/sudoers"],
        "debianutils" => &["/usr/bin/run-parts"],
        "login" => &["/usr/sbin/nologin"],
        "git" => &["/usr/bin/git"],
        "tar" => &["/usr/bin/tar"],
        "unzip" => &["/usr/bin/unzip"],
        "nano" => &[
            "/usr/bin/nano",
            "/usr/bin/editor",
            "/etc/alternatives/editor",
        ],
        "which" => &["/usr/bin/which"],
        "openssh-client" => &[
            "/usr/bin/ssh",
            "/usr/bin/ssh-add",
            "/usr/bin/ssh-agent",
            "/usr/bin/ssh-keygen",
            "/usr/bin/ssh-keyscan",
            "/usr/bin/scp",
            "/usr/bin/sftp",
            "/etc/ssh/ssh_config",
        ],
        "openssh-server" => &[
            "/usr/sbin/sshd",
            "/etc/ssh/sshd_config",
            "/usr/lib/systemd/system/ssh.service",
        ],
        "openssh-sftp-server" => &["/usr/lib/openssh/sftp-server"],
        "postgresql" => &[
            "/usr/bin/psql",
            "/usr/lib/postgresql/17/bin/postgres",
            "/etc/postgresql/17/main/postgresql.conf",
            "/usr/lib/systemd/system/postgresql.service",
        ],
        "docker.io" => &[
            "/usr/bin/docker",
            "/usr/bin/dockerd",
            "/usr/lib/systemd/system/docker.service",
        ],
        "containerd" => &["/usr/bin/containerd"],
        "docker-compose" => &["/usr/bin/docker-compose"],
        "dbus" => &["/usr/bin/dbus-daemon"],
        "nginx" => &[
            "/usr/sbin/nginx",
            "/etc/nginx/nginx.conf",
            "/etc/nginx/sites-available/default",
            "/usr/lib/systemd/system/nginx.service",
        ],
        "redis-server" => &[
            "/usr/bin/redis-server",
            "/etc/redis/redis.conf",
            "/usr/lib/systemd/system/redis-server.service",
        ],
        "mysql-server" => &[
            "/usr/sbin/mysqld",
            "/usr/bin/mysql",
            "/usr/bin/mariadb",
            "/etc/mysql/mysql.conf.d/mysqld.cnf",
            "/usr/lib/systemd/system/mysql.service",
        ],
        "curl" => &["/usr/bin/curl"],
        "vim" => &["/usr/bin/vim"],
        _ => &[],
    };
    paths
        .iter()
        .filter(|path| fs.exists(path))
        .map(|path| (*path).to_owned())
        .collect()
}

pub fn sync_dpkg_file_lists(fs: &mut VirtualFileSystem, now: DateTime<Utc>) {
    if !fs.distribution().is_apt() {
        return;
    }
    let _ = ensure_dir(fs, "/var/lib/dpkg/info", now);
    let status =
        String::from_utf8_lossy(fs.read("/var/lib/dpkg/status").unwrap_or_default()).into_owned();
    let installed = status
        .split("\n\n")
        .filter_map(|record| {
            let name = record
                .lines()
                .find_map(|line| line.strip_prefix("Package: "))?;
            record
                .lines()
                .any(|line| line == "Status: install ok installed")
                .then_some(name.to_owned())
        })
        .collect::<std::collections::BTreeSet<_>>();
    let stale_lists = fs
        .list("/var/lib/dpkg/info")
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(name, node)| {
            (!node.is_dir()
                && name.ends_with(".list")
                && !installed.contains(name.trim_end_matches(".list")))
            .then_some(name)
        })
        .collect::<Vec<_>>();
    for name in stale_lists {
        let _ = fs.remove(&format!("/var/lib/dpkg/info/{name}"), false);
    }
    for package in installed {
        let files = debian_package_files(fs, &package);
        let _ = fs.put_file(
            &format!("/var/lib/dpkg/info/{package}.list"),
            format!("{}\n", files.join("\n")),
            now,
        );
    }
}

pub fn installed(fs: &VirtualFileSystem, name: &str) -> bool {
    if fs.distribution() == Distribution::Arch {
        let name = match name {
            "redis-server" => "valkey",
            "mysql-server" => "mariadb",
            name => name,
        };
        return arch_installed(fs, name).is_some();
    }
    fs.read("/var/lib/dpkg/status").ok().is_some_and(|bytes| {
        String::from_utf8_lossy(bytes).split("\n\n").any(|entry| {
            entry.lines().any(|line| line == format!("Package: {name}"))
                && entry
                    .lines()
                    .any(|line| line == "Status: install ok installed")
        })
    })
}

/// Read an installed package's version from the virtual package database.
/// Command handlers should use this instead of maintaining a parallel version
/// table whenever the virtual package database is authoritative.
pub fn installed_version(fs: &VirtualFileSystem, name: &str) -> Option<String> {
    if fs.distribution() == Distribution::Arch {
        let name = match name {
            "redis-server" => "valkey",
            "mysql-server" => "mariadb",
            name => name,
        };
        return arch_installed(fs, name).map(|package| package.version);
    }

    let status = String::from_utf8_lossy(fs.read("/var/lib/dpkg/status").ok()?).into_owned();
    status.split("\n\n").find_map(|entry| {
        let is_installed = entry
            .lines()
            .any(|line| line == "Status: install ok installed");
        let matches_name = entry.lines().any(|line| line == format!("Package: {name}"));
        (is_installed && matches_name)
            .then(|| {
                entry
                    .lines()
                    .find_map(|line| line.strip_prefix("Version: "))
            })
            .flatten()
            .map(str::to_owned)
    })
}

/// Bash's upstream version as reported by `bash --version`, derived from the
/// installed package record where its package version carries that detail.
pub fn installed_bash_version(
    fs: &VirtualFileSystem,
    profile: &crate::config::LinuxProfile,
) -> Option<String> {
    let package_version = installed_version(fs, "bash")?;
    let version = match profile.distribution {
        Distribution::Arch | Distribution::Debian => package_version
            .split_once(':')
            .map_or(package_version.as_str(), |(_, version)| version)
            .split('-')
            .next()
            .unwrap_or(profile.bash_version),
        // Ubuntu's dpkg version omits the upstream patch component. The
        // profile supplies it for the pinned base image while still requiring
        // Bash to exist in the mutable package database.
        Distribution::Ubuntu => profile.bash_version,
        Distribution::Windows => return None,
    };
    Some(version.to_owned())
}

pub fn configured(fs: &VirtualFileSystem, name: &str) -> bool {
    fs.read("/var/lib/dpkg/status").ok().is_some_and(|bytes| {
        String::from_utf8_lossy(bytes).split("\n\n").any(|entry| {
            entry.lines().any(|line| line == format!("Package: {name}"))
                && entry
                    .lines()
                    .any(|line| line == "Status: deinstall ok config-files")
        })
    })
}

pub fn installed_names(fs: &VirtualFileSystem) -> Vec<&'static Package> {
    CATALOG
        .iter()
        .filter(|package| installed(fs, package.name))
        .collect()
}

pub fn install(
    fs: &mut VirtualFileSystem,
    package: &Package,
    now: DateTime<Utc>,
) -> Result<(), FsError> {
    if fs.distribution() == Distribution::Arch {
        let name = match package.name {
            "redis-server" => "valkey",
            "mysql-server" => "mariadb",
            name => name,
        };
        let arch_package = arch_lookup(name).ok_or(FsError::NotFound)?;
        return install_arch(fs, arch_package, now);
    }
    if installed(fs, package.name) {
        return Ok(());
    }
    if fs.distribution() == Distribution::Arch {
        let directory = format!(
            "/var/lib/pacman/local/{}-{}",
            package.name,
            version_for(package, Distribution::Arch)
        );
        ensure_dir(fs, &directory, now)?;
        fs.write(
            &format!("{directory}/desc"),
            format!(
                "%NAME%\n{}\n%VERSION%\n{}\n%DESC%\n{}\n",
                package.name,
                version_for(package, Distribution::Arch),
                package.description
            )
            .into_bytes(),
            now,
        )?;
    } else {
        ensure_dir(fs, "/var/lib/dpkg", now)?;
        let current = String::from_utf8_lossy(fs.read("/var/lib/dpkg/status").unwrap_or_default())
            .into_owned();
        let retained = current
            .split("\n\n")
            .filter(|entry| {
                !entry
                    .lines()
                    .any(|line| line == format!("Package: {}", package.name))
                    && !entry.trim().is_empty()
            })
            .collect::<Vec<_>>()
            .join("\n\n");
        let mut status = format!("{retained}\n\n").into_bytes();
        status.extend_from_slice(format!("Package: {}\nStatus: install ok installed\nVersion: {}\nArchitecture: amd64\nDescription: {}\n\n", package.name, version_for(package, fs.distribution()), package.description).as_bytes());
        fs.write("/var/lib/dpkg/status", status, now)?;
    }
    match package.name {
        "nginx" => {
            for path in [
                "/etc/nginx",
                "/etc/nginx/sites-available",
                "/etc/nginx/sites-enabled",
                "/usr/sbin",
                "/lib",
                "/lib/systemd",
                "/lib/systemd/system",
            ] {
                ensure_dir(fs, path, now)?;
            }
            fs.write("/etc/nginx/nginx.conf", b"user www-data;\nworker_processes auto;\nevents { worker_connections 768; }\nhttp { include /etc/nginx/sites-enabled/*; }\n".to_vec(), now)?;
            fs.write(
                "/etc/nginx/sites-available/default",
                b"server { listen 80 default_server; root /var/www/html; }\n".to_vec(),
                now,
            )?;
            fs.write(
                "/usr/sbin/nginx",
                b"ELF virtual nginx executable\n".to_vec(),
                now,
            )?;
            if let Ok(node) = fs.node_mut("/usr/sbin/nginx") {
                node.permissions = crate::filesystem::permissions::Permissions(0o755);
                node.reported_size = Some(1_217_920);
            }
            fs.write("/lib/systemd/system/nginx.service", b"[Unit]\nDescription=A high performance web server and a reverse proxy server\n[Service]\nExecStart=/usr/sbin/nginx\n".to_vec(), now)?;
            ensure_dir(fs, "/etc/systemd/system/multi-user.target.wants", now)?;
            fs.put_symlink(
                "/etc/systemd/system/multi-user.target.wants/nginx.service",
                "/lib/systemd/system/nginx.service",
                now,
            );
        }
        "postgresql" => {
            fs.write(
                "/usr/bin/psql",
                b"ELF virtual PostgreSQL client\n".to_vec(),
                now,
            )?;
            if let Ok(node) = fs.node_mut("/usr/bin/psql") {
                node.permissions = crate::filesystem::permissions::Permissions(0o755);
            }
            let pg_config = if fs.distribution() == Distribution::Ubuntu {
                "/etc/postgresql/14/main"
            } else {
                "/etc/postgresql/17/main"
            };
            ensure_dir(fs, pg_config, now)?;
            fs.write(
                &format!("{pg_config}/postgresql.conf"),
                b"listen_addresses = 'localhost'\nport = 5432\n".to_vec(),
                now,
            )?;
            let server_binary = if fs.distribution() == Distribution::Ubuntu {
                "/usr/lib/postgresql/14/bin/postgres"
            } else {
                "/usr/lib/postgresql/17/bin/postgres"
            };
            ensure_dir(fs, "/usr/lib/postgresql", now)?;
            ensure_dir(
                fs,
                &server_binary
                    .rsplit_once('/')
                    .map_or("/usr/lib/postgresql", |(path, _)| path),
                now,
            )?;
            fs.write(
                server_binary,
                b"ELF virtual PostgreSQL server\n".to_vec(),
                now,
            )?;
            set_executable(fs, server_binary);
            ensure_dir(fs, "/lib/systemd/system", now)?;
            fs.write(
                "/lib/systemd/system/postgresql.service",
                b"[Unit]\nDescription=PostgreSQL RDBMS\nAfter=network.target\n[Service]\nType=oneshot\nExecStart=/bin/true\nRemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target\n".to_vec(),
                now,
            )?;
        }
        "mysql-server" => {
            ensure_dir(fs, "/etc/mysql/mysql.conf.d", now)?;
            ensure_dir(fs, "/var/lib/mysql", now)?;
            ensure_dir(fs, "/run/mysqld", now)?;
            for (path, content) in [
                ("/usr/sbin/mysqld", "ELF virtual MySQL database server\n"),
                ("/usr/bin/mysql", "ELF virtual MySQL client\n"),
                ("/usr/bin/mariadb", "ELF virtual MySQL-compatible client\n"),
                (
                    "/etc/mysql/mysql.conf.d/mysqld.cnf",
                    "[mysqld]\nport=13306\nbind-address=0.0.0.0\n",
                ),
                (
                    "/lib/systemd/system/mysql.service",
                    "[Unit]\nDescription=MySQL Community Server\nAfter=network.target\n[Service]\nExecStart=/usr/sbin/mysqld --defaults-file=/etc/mysql/mysql.conf.d/mysqld.cnf\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n",
                ),
            ] {
                fs.write(path, content.as_bytes().to_vec(), now)?;
                if path.starts_with("/usr/bin/") || path.starts_with("/usr/sbin/") {
                    set_executable(fs, path);
                }
            }
        }
        "curl" | "vim" | "redis-server" => {
            if let Some(command) = package.command {
                fs.write(
                    command,
                    format!("ELF virtual {} executable\n", package.name).into_bytes(),
                    now,
                )?;
                if let Ok(node) = fs.node_mut(command) {
                    node.permissions = crate::filesystem::permissions::Permissions(0o755);
                }
            }
            if package.name == "redis-server" {
                ensure_dir(fs, "/etc/redis", now)?;
                fs.write(
                    "/etc/redis/redis.conf",
                    b"bind 127.0.0.1\nport 6379\n".to_vec(),
                    now,
                )?;
                ensure_dir(fs, "/lib/systemd/system", now)?;
                fs.write("/lib/systemd/system/redis-server.service", b"[Unit]\nDescription=Advanced key-value store\n[Service]\nExecStart=/usr/bin/redis-server /etc/redis/redis.conf\n".to_vec(), now)?;
            }
        }
        _ => {}
    }
    sync_dpkg_file_lists(fs, now);
    Ok(())
}

pub fn remove(
    fs: &mut VirtualFileSystem,
    package: &Package,
    now: DateTime<Utc>,
) -> Result<(), FsError> {
    if fs.distribution() == Distribution::Arch {
        let name = match package.name {
            "redis-server" => "valkey",
            "mysql-server" => "mariadb",
            name => name,
        };
        if let Some(installed) = arch_installed(fs, name) {
            return remove_arch(fs, &installed, now);
        }
        return Ok(());
    }
    remove_inner(fs, package, now, false)
}

pub fn purge(
    fs: &mut VirtualFileSystem,
    package: &Package,
    now: DateTime<Utc>,
) -> Result<(), FsError> {
    if fs.distribution() == Distribution::Arch {
        return remove(fs, package, now);
    }
    remove_inner(fs, package, now, true)
}

fn remove_inner(
    fs: &mut VirtualFileSystem,
    package: &Package,
    now: DateTime<Utc>,
    purge: bool,
) -> Result<(), FsError> {
    if fs.distribution() == Distribution::Arch {
        let directory = format!(
            "/var/lib/pacman/local/{}-{}",
            package.name,
            version_for(package, Distribution::Arch)
        );
        if fs.exists(&directory) {
            fs.remove(&directory, true)?;
        }
    } else {
        let status = String::from_utf8_lossy(fs.read("/var/lib/dpkg/status").unwrap_or_default())
            .into_owned();
        let mut retained = Vec::new();
        for entry in status
            .split("\n\n")
            .filter(|entry| !entry.trim().is_empty())
        {
            if !entry
                .lines()
                .any(|line| line == format!("Package: {}", package.name))
            {
                retained.push(entry.to_owned());
            } else if !purge {
                let mut fields = entry
                    .lines()
                    .filter(|line| !line.starts_with("Status:"))
                    .collect::<Vec<_>>();
                fields.insert(1.min(fields.len()), "Status: deinstall ok config-files");
                retained.push(fields.join("\n"));
            }
        }
        fs.write(
            "/var/lib/dpkg/status",
            format!("{}\n\n", retained.join("\n\n")).into_bytes(),
            now,
        )?;
    }
    if let Some(command) = package.command {
        if fs.exists(command) {
            let _ = fs.remove(command, false);
        }
    }
    if package.name == "redis-server" {
        for path in [
            "/run/redis-server.pid",
            "/lib/systemd/system/redis-server.service",
        ] {
            if fs.exists(path) {
                let _ = fs.remove(path, false);
            }
        }
        if purge && fs.exists("/etc/redis/redis.conf") {
            let _ = fs.remove("/etc/redis/redis.conf", false);
        }
    }
    if package.name == "nginx" {
        for path in [
            "/run/nginx.pid",
            "/lib/systemd/system/nginx.service",
            "/etc/systemd/system/multi-user.target.wants/nginx.service",
        ] {
            if fs.exists(path) {
                let _ = fs.remove(path, false);
            }
        }
        if purge {
            for path in [
                "/etc/nginx/nginx.conf",
                "/etc/nginx/sites-available/default",
            ] {
                if fs.exists(path) {
                    let _ = fs.remove(path, false);
                }
            }
        }
    }
    if package.name == "postgresql" && fs.exists("/lib/systemd/system/postgresql.service") {
        let _ = fs.remove("/lib/systemd/system/postgresql.service", false);
        let server_binary = if fs.distribution() == Distribution::Ubuntu {
            "/usr/lib/postgresql/14/bin/postgres"
        } else {
            "/usr/lib/postgresql/17/bin/postgres"
        };
        if fs.exists(server_binary) {
            let _ = fs.remove(server_binary, false);
        }
    }
    if package.name == "postgresql" && fs.exists("/usr/bin/psql") {
        let _ = fs.remove("/usr/bin/psql", false);
    }
    if package.name == "postgresql" && purge {
        for path in [
            "/etc/postgresql/14/main/postgresql.conf",
            "/etc/postgresql/17/main/postgresql.conf",
        ] {
            if fs.exists(path) {
                let _ = fs.remove(path, false);
            }
        }
    }
    sync_dpkg_file_lists(fs, now);
    Ok(())
}

fn ensure_dir(fs: &mut VirtualFileSystem, path: &str, now: DateTime<Utc>) -> Result<(), FsError> {
    if fs.exists(path) {
        return Ok(());
    }
    let parent = path.rsplit_once('/').map_or(
        "/",
        |(parent, _)| if parent.is_empty() { "/" } else { parent },
    );
    ensure_dir(fs, parent, now)?;
    fs.mkdir(path, now)
}
