use std::{
    fs,
    io::Read,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, bail};
use serde_json::Value;

use crate::{
    HighArgs, HighOs, State, atomic_write, guest, hash_password, validate_hostname,
    validate_username,
};

const HIGH_LINUX_NETWORK_CONFIG: &[u8] = b"version: 2\nrenderer: networkd\nethernets:\n  all:\n    match:\n      name: \"*\"\n    dhcp4: true\n    dhcp-identifier: mac\n";

pub(super) fn ensure_prepared_image(state: &State, os: HighOs) -> anyhow::Result<PathBuf> {
    let path = PathBuf::from(os.prepared_path());
    if path.is_file() {
        if os == HighOs::Windows {
            verify_windows_manifest(&path)?;
        }
        return Ok(path);
    }
    require_free_space(
        &state.root,
        if os == HighOs::Windows {
            20_u64 << 30
        } else {
            2_u64 << 30
        },
    )?;
    let script = match os {
        HighOs::Ubuntu => include_str!("../recipes/high-images/ubuntu.sh"),
        HighOs::Debian => include_str!("../recipes/high-images/debian.sh"),
        HighOs::Arch => include_str!("../recipes/high-images/arch.sh"),
        HighOs::Windows => {
            let builder = Path::new("/usr/local/lib/honeyforge/hf-image-builder/hf-image-builder");
            let catalog = Path::new("/etc/honeyforge/image-sources/windows-server-2022.json");
            anyhow::ensure!(
                builder.is_file() && catalog.is_file(),
                "prepared Windows image is missing at {}; copy the ready QCOW2 and .sha256 there, pass --image, or install the local hf-image-builder with an approved Windows source catalog",
                path.display()
            );
            let status = Command::new(builder)
                .arg("--catalog")
                .arg(catalog)
                .arg("build")
                .status()
                .context("could not run the local Windows image builder")?;
            anyhow::ensure!(status.success(), "local Windows image builder failed");
            verify_windows_manifest(&path)?;
            return Ok(path);
        }
    };
    let scripts = state.root.join("recipes/high-images");
    fs::create_dir_all(&scripts)?;
    if os == HighOs::Ubuntu {
        let bundle_script = scripts.join("build-package-bundle.sh");
        atomic_write(
            &bundle_script,
            include_str!("../recipes/high-ubuntu-ssh/offline/build-package-bundle.sh").as_bytes(),
            0o700,
        )?;
    }
    let script_path = scripts.join(format!("{}.sh", os_name(os)));
    atomic_write(&script_path, script.as_bytes(), 0o700)?;
    let status = Command::new("sh")
        .arg(&script_path)
        .arg(&path)
        .status()
        .with_context(|| format!("could not fetch prepared {os:?} image"))?;
    anyhow::ensure!(status.success(), "could not fetch prepared {os:?} image");
    Ok(path)
}

pub(super) fn validate_qcow2(path: &Path) -> anyhow::Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("prepared image does not exist: {}", path.display()))?;
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "High image must be a regular file"
    );
    let output = Command::new("qemu-img")
        .args(["info", "--output=json"])
        .arg(path)
        .output()
        .context("qemu-img is required for High images")?;
    anyhow::ensure!(
        output.status.success(),
        "qemu-img could not inspect High image"
    );
    let info: Value = serde_json::from_slice(&output.stdout)?;
    anyhow::ensure!(
        info["format"] == "qcow2",
        "prepared High image must be QCOW2"
    );
    anyhow::ensure!(
        info["backing-filename"].is_null() && info["full-backing-filename"].is_null(),
        "prepared High image must not depend on another backing file"
    );
    let status = Command::new("qemu-img")
        .args(["check", "-q", "-f", "qcow2"])
        .arg(path)
        .status()
        .context("could not check High image integrity")?;
    anyhow::ensure!(status.success(), "High QCOW2 image integrity check failed");
    Ok(path.to_owned())
}

fn verify_windows_manifest(path: &Path) -> anyhow::Result<()> {
    let manifest = PathBuf::from(format!("{}.sha256", path.display()));
    let expected = fs::read_to_string(&manifest).with_context(|| {
        format!(
            "prepared Windows image needs checksum manifest {}",
            manifest.display()
        )
    })?;
    let expected = expected.split_whitespace().next().unwrap_or_default();
    anyhow::ensure!(
        expected.len() == 64 && expected.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid prepared Windows checksum manifest"
    );
    let output = Command::new("sha256sum")
        .arg(path)
        .output()
        .context("sha256sum is required to verify prepared Windows image")?;
    anyhow::ensure!(
        output.status.success(),
        "could not hash prepared Windows image"
    );
    let actual = String::from_utf8_lossy(&output.stdout);
    anyhow::ensure!(
        actual
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .eq_ignore_ascii_case(expected),
        "prepared Windows image checksum mismatch"
    );
    Ok(())
}

pub(super) fn validate_iso(path: &Path, os: HighOs) -> anyhow::Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("ISO does not exist: {}", path.display()))?;
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "ISO must be a regular local file"
    );
    let output = Command::new("xorriso")
        .arg("-indev")
        .arg(path)
        .args(["-find", "/", "-type", "f", "-exec", "echo"])
        .output()
        .context("xorriso is required to inspect High installation ISO")?;
    anyhow::ensure!(
        output.status.success(),
        "xorriso could not inspect installation ISO"
    );
    let listing = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
    anyhow::ensure!(
        listing.contains("/efi/boot/bootx64.efi") || listing.contains("/install.amd/"),
        "High installation ISO must contain x86_64 boot media"
    );
    let matches_os = match os {
        HighOs::Ubuntu => {
            listing.contains("/casper/") && listing.contains("/casper/install-sources.yaml")
        }
        HighOs::Debian => listing.contains("/install.amd/"),
        HighOs::Arch => listing.contains("/arch/boot/x86_64/"),
        HighOs::Windows => {
            listing.contains("/sources/boot.wim")
                && (listing.contains("/sources/install.wim")
                    || listing.contains("/sources/install.esd"))
        }
    };
    anyhow::ensure!(matches_os, "ISO does not match --os {os:?}");
    Ok(path.to_owned())
}

pub(super) fn prepare_prepared(state: &State, id: &str, args: &HighArgs) -> anyhow::Result<()> {
    require_free_space(
        &state.root,
        if args.os == HighOs::Windows {
            5_u64 << 30
        } else {
            1_u64 << 30
        },
    )?;
    let instance = state.root.join("high").join(id);
    fs::create_dir_all(&instance)?;
    fs::set_permissions(&instance, fs::Permissions::from_mode(0o700))?;
    let hostname = args
        .hostname
        .clone()
        .unwrap_or_else(|| format!("hf-{}", &id[..12]));
    validate_hostname(&hostname)?;
    if args.os == HighOs::Windows {
        anyhow::ensure!(
            hostname.len() <= 15,
            "Windows High hostname must have at most 15 characters"
        );
    }
    let username = args.username.clone().unwrap_or_else(|| {
        if args.os == HighOs::Windows {
            "hfadmin"
        } else {
            "analyst"
        }
        .to_owned()
    });
    validate_username(&username)?;
    let password_path = match &args.password_file {
        Some(path) => path.clone(),
        None => {
            let output = Command::new("openssl")
                .args(["rand", "-base64", "24"])
                .output()?;
            anyhow::ensure!(
                output.status.success(),
                "could not generate High guest password"
            );
            let path = instance.join(if args.os == HighOs::Windows {
                "rdp-password"
            } else {
                "ssh-password"
            });
            atomic_write(&path, &output.stdout, 0o600)?;
            println!("Пароль гостя High сохранён в {}", path.display());
            path
        }
    };
    if args.os == HighOs::Windows {
        let password = crate::read_password_file(&password_path)?;
        let drive = instance.join("config-drive/openstack/latest");
        fs::create_dir_all(&drive)?;
        let metadata = serde_json::json!({
            "uuid": id,
            "hostname": hostname,
            "name": hostname,
            "meta": {"admin_username": username, "admin_pass": password},
        });
        atomic_write(
            &drive.join("meta_data.json"),
            &serde_json::to_vec(&metadata)?,
            0o600,
        )?;
        let output = Command::new("xorriso")
            .args(["-as", "mkisofs", "-V", "config-2", "-J", "-r", "-o"])
            .arg(instance.join("seed.iso"))
            .arg(instance.join("config-drive"))
            .output()
            .context("xorriso is required for the Windows config drive")?;
        anyhow::ensure!(
            output.status.success(),
            "could not create Windows config drive: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    } else {
        let hash = hash_password(&password_path)?;
        let ssh_service = if args.os == HighOs::Arch {
            "sshd"
        } else {
            "ssh"
        };
        let user_data = format!(
            "#cloud-config\nusers:\n  - name: {username}\n    shell: /bin/bash\n    lock_passwd: false\n    passwd: '{hash}'\nssh_pwauth: true\ndisable_root: false\nruncmd:\n  - systemctl enable --now {ssh_service}\n  - systemctl enable --now qemu-guest-agent\n"
        );
        atomic_write(&instance.join("user-data"), user_data.as_bytes(), 0o600)?;
        atomic_write(
            &instance.join("meta-data"),
            format!("instance-id: {id}\nlocal-hostname: {hostname}\n").as_bytes(),
            0o600,
        )?;
        atomic_write(
            &instance.join("network-config"),
            HIGH_LINUX_NETWORK_CONFIG,
            0o600,
        )?;
        let output = Command::new("cloud-localds")
            .arg(format!(
                "--network-config={}",
                instance.join("network-config").display()
            ))
            .arg(instance.join("seed.iso"))
            .arg(instance.join("user-data"))
            .arg(instance.join("meta-data"))
            .output()
            .context("cloud-localds is required for prepared Linux cloud images")?;
        anyhow::ensure!(
            output.status.success(),
            "could not prepare Linux cloud-init seed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if args.os == HighOs::Arch {
            atomic_write(
                &instance.join("05-honeyforge-high.network"),
                b"[Match]\nName=*\n\n[Network]\nDHCP=yes\n",
                0o600,
            )?;
        }
    }
    Ok(())
}

pub(super) fn run_launch(
    _state: &State,
    recipe: &Path,
    high_root: &Path,
    image: &str,
    id: &str,
    port: &str,
    os: &str,
) -> anyhow::Result<()> {
    let output = Command::new("sh")
        .arg(recipe.join("scripts/launch-local.sh"))
        .args([image, id, port])
        .env("HF_HIGH_ROOT", high_root)
        .env("HF_HIGH_NETWORK_SCOPE", "local")
        .env("HF_HIGH_GUEST_OS", os)
        .env("LIBVIRT_DEFAULT_URI", "qemu:///system")
        .env("LC_ALL", "C")
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "High VM launch failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

pub(super) fn wait_guest_service(id: &str, port: u16) -> anyhow::Result<IpAddr> {
    let domain = format!("hf-high-{id}");
    let timeout = Duration::from_secs(if port == 3389 { 300 } else { 180 });
    let started = Instant::now();
    let deadline = started + timeout;
    let mut next_report = started + Duration::from_secs(15);
    let mut last_addresses = String::new();
    let mut reported_diagnostics = false;
    eprintln!("High: waiting for guest service on port {port} inside the isolated network");
    while Instant::now() < deadline {
        let addresses = Command::new("virsh")
            .env("LIBVIRT_DEFAULT_URI", "qemu:///system")
            .args(["domifaddr", &domain, "--source", "agent"])
            .output()
            .context("cannot inspect High guest network interfaces")?;
        last_addresses = String::from_utf8_lossy(&addresses.stdout).into_owned();
        if addresses.status.success() {
            for token in String::from_utf8_lossy(&addresses.stdout).split_whitespace() {
                if let Some((address, _prefix)) = token.split_once('/') {
                    if let Ok(ip) = address.parse::<Ipv4Addr>() {
                        let octets = ip.octets();
                        if octets[..3] != [192, 168, 252] || !(100..=200).contains(&octets[3]) {
                            continue;
                        }
                        let endpoint = SocketAddr::new(IpAddr::V4(ip), port);
                        if let Ok(mut stream) =
                            TcpStream::connect_timeout(&endpoint, Duration::from_secs(2))
                        {
                            if port != 22 {
                                return Ok(IpAddr::V4(ip));
                            }
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                            let mut banner = [0_u8; 128];
                            if let Ok(count) = stream.read(&mut banner) {
                                if is_ssh_banner(&banner[..count]) {
                                    return Ok(IpAddr::V4(ip));
                                }
                            }
                        }
                    }
                }
            }
        }
        let now = Instant::now();
        if port == 22
            && !reported_diagnostics
            && now.duration_since(started) >= Duration::from_secs(45)
        {
            reported_diagnostics = true;
            let diagnostics = guest::diagnose_ssh(id)
                .unwrap_or_else(|error| format!("guest SSH diagnostics unavailable: {error:#}"));
            eprintln!(
                "High: SSH is still unavailable; guest interfaces: {last_addresses}; {diagnostics}"
            );
        }
        if now >= next_report {
            eprintln!(
                "High: guest service on port {port} is not ready yet ({}/{} seconds)",
                now.duration_since(started).as_secs(),
                timeout.as_secs()
            );
            next_report = now + Duration::from_secs(15);
        }
        thread::sleep(Duration::from_secs(5));
    }
    if port == 22 {
        let diagnostics = guest::diagnose_ssh(id)
            .unwrap_or_else(|error| format!("guest SSH diagnostics unavailable: {error:#}"));
        bail!(
            "High guest SSH on port 22 did not return an SSH protocol banner inside the isolated network; guest interfaces: {last_addresses}; {diagnostics}"
        )
    }
    bail!("High guest service on port {port} did not become reachable inside the isolated network")
}

fn is_ssh_banner(banner: &[u8]) -> bool {
    banner.starts_with(b"SSH-2.0-") || banner.starts_with(b"SSH-1.99-")
}

#[cfg(test)]
mod tests {
    use super::{HIGH_LINUX_NETWORK_CONFIG, is_ssh_banner};

    #[test]
    fn ssh_readiness_requires_an_ssh_protocol_banner() {
        assert!(is_ssh_banner(b"SSH-2.0-OpenSSH_9.6\r\n"));
        assert!(is_ssh_banner(b"SSH-1.99-server\r\n"));
        assert!(!is_ssh_banner(b"HTTP/1.1 200 OK\r\n"));
        assert!(!is_ssh_banner(b""));
    }

    #[test]
    fn cloud_guests_identify_dhcp_by_unique_interface_mac() {
        let network_config = std::str::from_utf8(HIGH_LINUX_NETWORK_CONFIG).unwrap();
        assert!(network_config.contains("dhcp-identifier: mac"));
    }
}

fn os_name(os: HighOs) -> &'static str {
    match os {
        HighOs::Ubuntu => "ubuntu",
        HighOs::Debian => "debian",
        HighOs::Arch => "arch",
        HighOs::Windows => "windows",
    }
}

pub(super) fn install_iso(
    state: &State,
    _recipe: &Path,
    iso: &str,
    id: &str,
    args: &HighArgs,
) -> anyhow::Result<()> {
    if args.os == HighOs::Windows {
        anyhow::ensure!(
            args.username.is_none(),
            "Windows ISO installer creates Administrator; --username is available with a prepared Windows image"
        );
    }
    let iso_bytes = fs::metadata(iso)?.len();
    let extra_bytes = match args.os {
        HighOs::Ubuntu | HighOs::Debian => 6_u64 << 30,
        HighOs::Arch => 10_u64 << 30,
        HighOs::Windows => 20_u64 << 30,
    };
    let required = iso_bytes.saturating_add(extra_bytes);
    require_free_space(&state.root, required)?;
    let instance = state.root.join("high").join(id);
    fs::create_dir_all(&instance)?;
    fs::set_permissions(&instance, fs::Permissions::from_mode(0o700))?;
    if let Some(password_file) = &args.password_file {
        let password = crate::read_password_file(password_file)?;
        let name = if args.os == HighOs::Windows {
            "rdp-password"
        } else {
            "ssh-password"
        };
        atomic_write(
            &instance.join(name),
            format!("{password}\n").as_bytes(),
            0o600,
        )?;
    }
    let script = if args.os == HighOs::Windows {
        state
            .root
            .join("recipes/high-windows-rdp/scripts/launch.sh")
    } else {
        state
            .root
            .join("recipes/high-custom-iso/scripts/launch-iso.sh")
    };
    let mut command = Command::new("sh");
    command
        .arg(&script)
        .args([iso, id, &args.port.to_string()])
        .env("HF_HIGH_ROOT", state.root.join("high"))
        .env("HF_HIGH_NETWORK_SCOPE", "local")
        .env("HF_HIGH_VIRT_TYPE", "kvm")
        .env("HF_HIGH_ISO_INSTALLER", os_name(args.os))
        .env("LIBVIRT_DEFAULT_URI", "qemu:///system")
        .env("LC_ALL", "C");
    if let Some(hostname) = &args.hostname {
        validate_hostname(hostname)?;
        if args.os == HighOs::Windows {
            anyhow::ensure!(
                hostname.len() <= 15,
                "Windows High hostname must have at most 15 characters"
            );
        }
        command.env("HF_HIGH_ISO_HOSTNAME", hostname);
    }
    eprintln!(
        "High: устанавливаю {:?} из ISO {}; порт {} откроется после готовности гостя",
        args.os, iso, args.port
    );
    let status = command
        .status()
        .with_context(|| format!("could not run ISO installer {}", script.display()))?;
    anyhow::ensure!(
        status.success(),
        "High ISO installation failed for --os {:?}; see installer output",
        args.os
    );
    atomic_write(
        &instance.join("external-ssh-port"),
        format!("{}\n", args.port).as_bytes(),
        0o600,
    )?;
    atomic_write(
        &instance.join("guest-service-port"),
        format!("{}\n", args.os.service_port()).as_bytes(),
        0o600,
    )?;
    let password_name = if args.os == HighOs::Windows {
        "rdp-password"
    } else {
        "ssh-password"
    };
    println!(
        "Пароль гостя High сохранён в {}",
        instance.join(password_name).display()
    );
    Ok(())
}

fn require_free_space(path: &Path, required: u64) -> anyhow::Result<()> {
    let free = Command::new("df")
        .args(["-B1", "--output=avail"])
        .arg(path)
        .output()
        .context("could not inspect free disk space for High")?;
    anyhow::ensure!(
        free.status.success(),
        "could not inspect free disk space for High"
    );
    let available: u64 = String::from_utf8_lossy(&free.stdout)
        .split_whitespace()
        .last()
        .context("df returned no free-space figure")?
        .parse()
        .context("df returned invalid free-space figure")?;
    anyhow::ensure!(
        available >= required,
        "High needs at least {} GiB free in {}; available {} GiB",
        required.div_ceil(1_u64 << 30),
        path.display(),
        available / (1_u64 << 30)
    );
    Ok(())
}
