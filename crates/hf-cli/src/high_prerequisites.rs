use std::{env, fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

use anyhow::{Context, ensure};

use crate::{HighArgs, HighOs};

const LIBVIRT_UNITS: [&str; 3] = [
    "/lib/systemd/system/libvirtd.service",
    "/usr/lib/systemd/system/libvirtd.service",
    "/etc/systemd/system/libvirtd.service",
];

pub(super) fn ensure(args: &HighArgs) -> anyhow::Result<()> {
    ensure!(is_root(), "High deployment needs root; rerun it with sudo");
    let device = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .context("High traps require readable and writable /dev/kvm")?;
    drop(device);

    let (required_tools, mut packages) = requirements(args);
    let missing = missing_tools(&required_tools);
    let libvirt_unit_missing = !LIBVIRT_UNITS.iter().any(|unit| Path::new(unit).exists());
    if !missing.is_empty() || libvirt_unit_missing {
        anyhow::ensure!(
            executable_on_path("apt-get"),
            "High is missing host tools ({}). Automatic prerequisite installation currently supports Debian/Ubuntu hosts with apt-get; install the High runtime packages for this OS and retry",
            missing.join(", ")
        );
        eprintln!(
            "High: installing missing host prerequisites{}",
            if missing.is_empty() {
                String::new()
            } else {
                format!(": {}", missing.join(", "))
            }
        );
        packages.sort_unstable();
        packages.dedup();
        run_apt(&["update"])?;
        let mut install_args = vec!["install", "-y", "--no-install-recommends"];
        install_args.extend(packages.iter().copied());
        run_apt(&install_args)?;

        let still_missing = missing_tools(&required_tools);
        ensure!(
            still_missing.is_empty(),
            "High prerequisite installation completed, but these commands are still unavailable: {}",
            still_missing.join(", ")
        );
        ensure!(
            LIBVIRT_UNITS.iter().any(|unit| Path::new(unit).exists()),
            "High prerequisite installation completed, but libvirtd.service was not installed"
        );
    }

    let active = Command::new("systemctl")
        .args(["is-active", "--quiet", "libvirtd.service"])
        .status()
        .context("cannot check libvirt service; High requires systemd and libvirt")?
        .success();
    if !active {
        eprintln!("High: starting the libvirt service");
        let status = Command::new("systemctl")
            .args(["enable", "--now", "libvirtd.service"])
            .status()
            .context("cannot start libvirtd.service")?;
        ensure!(
            status.success(),
            "could not enable and start libvirtd.service"
        );
    }
    eprintln!("High: libvirt service is ready");

    Ok(())
}

fn requirements(args: &HighArgs) -> (Vec<&'static str>, Vec<&'static str>) {
    let mut tools = vec![
        "virsh",
        "qemu-img",
        "qemu-system-x86_64",
        "virt-install",
        "setfacl",
        "iptables",
        "iptables-restore",
        "ip6tables",
        "sha256sum",
        "sha512sum",
        "python3",
        "getent",
        "curl",
        "openssl",
        "systemctl",
        "timeout",
        "realpath",
    ];
    let mut packages = vec![
        "libvirt-daemon-system",
        "libvirt-clients",
        "qemu-system-x86",
        "qemu-utils",
        "virtinst",
        "acl",
        "iptables",
        "coreutils",
        "libc-bin",
        "python3",
        "curl",
        "openssl",
    ];

    if args.iso.is_some() || args.os == HighOs::Windows {
        tools.push("xorriso");
        packages.push("xorriso");
    }

    match (args.iso.is_some(), args.os) {
        (false, HighOs::Ubuntu | HighOs::Debian) => {
            tools.extend(["cloud-localds", "virt-customize", "dhcpcd"]);
            packages.extend(["cloud-image-utils", "libguestfs-tools", "dhcpcd-base"]);
            tools.extend(["virt-cat", "apt-get"]);
            if args.os == HighOs::Ubuntu {
                tools.push("dpkg-deb");
                packages.push("dpkg");
            }
        }
        (false, HighOs::Arch) => {
            tools.extend(["cloud-localds", "virt-customize"]);
            packages.extend(["cloud-image-utils", "libguestfs-tools"]);
        }
        (false, HighOs::Windows) => {}
        (true, HighOs::Ubuntu | HighOs::Debian) => {
            tools.push("virt-cat");
            packages.push("libguestfs-tools");
        }
        (true, HighOs::Arch) => {
            tools.extend(["virt-cat", "expect"]);
            packages.extend(["libguestfs-tools", "expect"]);
        }
        (true, HighOs::Windows) => {
            tools.push("wimlib-imagex");
            packages.push("wimtools");
        }
    }

    (tools, packages)
}

fn missing_tools(tools: &[&str]) -> Vec<String> {
    tools
        .iter()
        .filter(|tool| !executable_on_path(tool))
        .map(|tool| (*tool).to_owned())
        .collect()
}

fn executable_on_path(name: &str) -> bool {
    let Some(path) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&path).any(|directory| is_executable(&directory.join(name)))
}

fn is_executable(path: &Path) -> bool {
    fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

fn is_root() -> bool {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                let value = line.strip_prefix("Uid:")?.split_whitespace().next()?;
                value.parse::<u32>().ok()
            })
        })
        == Some(0)
}

fn run_apt(arguments: &[&str]) -> anyhow::Result<()> {
    let status = Command::new("apt-get")
        .env("DEBIAN_FRONTEND", "noninteractive")
        .args(arguments)
        .status()
        .with_context(|| format!("could not run apt-get {}", arguments.join(" ")))?;
    ensure!(
        status.success(),
        "apt-get {} failed while preparing the High host runtime",
        arguments.join(" ")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::requirements;
    use crate::{HighArgs, HighOs};
    use std::path::PathBuf;

    fn high_args(os: HighOs, iso: Option<PathBuf>) -> HighArgs {
        HighArgs {
            os,
            image: None,
            iso,
            port: 22,
            hostname: None,
            username: None,
            shell: None,
            password_file: None,
            vulnerabilities: Vec::new(),
            baits: Vec::new(),
            shared: crate::SharedArgs {
                shared: false,
                weight: None,
            },
        }
    }

    #[test]
    fn prepared_linux_images_require_libguestfs_dhcp_support() {
        for os in [HighOs::Ubuntu, HighOs::Debian] {
            let (tools, packages) = requirements(&high_args(os, None));
            assert!(tools.contains(&"virt-customize"));
            assert!(tools.contains(&"dhcpcd"));
            assert!(packages.contains(&"libguestfs-tools"));
            assert!(packages.contains(&"dhcpcd-base"));
        }

        let (arch_tools, arch_packages) = requirements(&high_args(HighOs::Arch, None));
        assert!(arch_tools.contains(&"virt-customize"));
        assert!(!arch_tools.contains(&"dhcpcd"));
        assert!(!arch_packages.contains(&"dhcpcd-base"));
    }

    #[test]
    fn iso_and_windows_paths_do_not_require_online_image_preparation_tools() {
        let (iso_tools, iso_packages) =
            requirements(&high_args(HighOs::Debian, Some("test.iso".into())));
        assert!(!iso_tools.contains(&"dhcpcd"));
        assert!(!iso_packages.contains(&"dhcpcd-base"));

        let (windows_tools, windows_packages) = requirements(&high_args(HighOs::Windows, None));
        assert!(!windows_tools.contains(&"dhcpcd"));
        assert!(!windows_packages.contains(&"dhcpcd-base"));
    }
}
