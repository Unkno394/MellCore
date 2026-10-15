use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use hf_core::{
    HighGuestOs, HighImageArchitecture, HighImageFormat, HighImageKind, HighImageSource,
    HighOsProfile,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

const MAX_DOWNLOAD_BYTES: u64 = 20 * 1024 * 1024 * 1024;
const MAX_VIRTUAL_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const MIN_CUSTOM_QCOW2_DOWNLOAD_FREE_BYTES: u64 = 1024 * 1024 * 1024;
const MIN_CUSTOM_ISO_DOWNLOAD_FREE_BYTES: u64 = 6 * 1024 * 1024 * 1024;
const DOWNLOAD_HEADROOM_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ApprovedIso {
    pub source: HighImageSource,
    pub expected_size_bytes: u64,
}

/// Versioned, reviewed installation media. Updating an entry requires reviewing the upstream
/// checksum again; mutable `latest` URLs are intentionally not accepted here.
pub fn approved_iso(profile: HighOsProfile) -> Result<ApprovedIso, HighImageError> {
    let (url, sha256, expected_size_bytes) = if profile == HighOsProfile::ubuntu_iso_ssh() {
        (
            "https://releases.ubuntu.com/24.04.5/ubuntu-24.04.5-live-server-amd64.iso",
            "97f3d7ffb032c3eb3b23d2c8be9cc76e60c2c1f2c0146ba5ba9fe01cafae0fd8",
            4_080_486_400,
        )
    } else if profile == HighOsProfile::debian_iso_ssh() {
        (
            "https://chuangtzu.ftp.acc.umu.se/cdimage/archive/12.12.0/amd64/iso-dvd/debian-12.12.0-amd64-DVD-1.iso",
            "84aae16b26c8d2802d1e327eb84ab8f053f0aa68b0b1679f5e6aaffd4fe549cc",
            3_992_977_408,
        )
    } else if profile == HighOsProfile::arch_linux_iso_ssh() {
        (
            "https://archive.archlinux.org/iso/2025.08.01/archlinux-2025.08.01-x86_64.iso",
            "4b1af44dbeed97acec0204a95f6393818bb8fd903b423a20b7ea141f80b27e59",
            1_378_795_520,
        )
    } else if profile == HighOsProfile::windows_rdp_legacy_iso() {
        return Err(error(
            "WINDOWS_ISO_ADMIN_REQUIRED",
            "licensing",
            "Microsoft does not provide a stable license-neutral direct URL for Windows Server Evaluation media; an administrator must accept the Microsoft terms and provide image_source with the approved HTTPS URL and SHA-256",
        ));
    } else {
        return Err(error(
            "APPROVED_ISO_UNAVAILABLE",
            "catalog",
            "the selected profile has no agent-managed installation ISO",
        ));
    };
    Ok(ApprovedIso {
        source: HighImageSource {
            url: url.into(),
            sha256: sha256.into(),
            format: HighImageFormat::Iso,
            architecture: HighImageArchitecture::X86_64,
        },
        expected_size_bytes,
    })
}

fn windows_admin_iso_from_values(
    url: Option<std::ffi::OsString>,
    sha256: Option<std::ffi::OsString>,
) -> Result<Option<HighImageSource>, HighImageError> {
    let (url, sha256) = match (url, sha256) {
        (None, None) => return Ok(None),
        (Some(url), Some(sha256)) => (url, sha256),
        _ => {
            return Err(error(
                "WINDOWS_ISO_CONFIG_INCOMPLETE",
                "licensing",
                "HF_HIGH_WINDOWS_ISO_URL and HF_HIGH_WINDOWS_ISO_SHA256 must be provided together after an administrator accepts the Microsoft terms",
            ));
        }
    };
    let source = HighImageSource {
        url: url.to_string_lossy().into_owned(),
        sha256: sha256.to_string_lossy().into_owned(),
        format: HighImageFormat::Iso,
        architecture: HighImageArchitecture::X86_64,
    };
    validate_source_metadata(&source, HighOsProfile::windows_rdp_legacy_iso())?;
    Ok(Some(source))
}

pub fn windows_admin_iso_source() -> Result<Option<HighImageSource>, HighImageError> {
    windows_admin_iso_from_values(
        std::env::var_os("HF_HIGH_WINDOWS_ISO_URL"),
        std::env::var_os("HF_HIGH_WINDOWS_ISO_SHA256"),
    )
}

#[derive(Debug, Error)]
#[error("HF_HIGH_ERROR code={code} stage={stage}: {message}")]
pub struct HighImageError {
    pub code: &'static str,
    pub stage: &'static str,
    pub message: String,
}

fn error(code: &'static str, stage: &'static str, message: impl Into<String>) -> HighImageError {
    HighImageError {
        code,
        stage,
        message: message.into(),
    }
}

pub fn materialize_image(
    source: &HighImageSource,
    profile: HighOsProfile,
    cache_dir: &Path,
) -> Result<PathBuf, HighImageError> {
    let required_free_bytes = match source.format {
        HighImageFormat::Qcow2 => MIN_CUSTOM_QCOW2_DOWNLOAD_FREE_BYTES,
        HighImageFormat::Iso => MIN_CUSTOM_ISO_DOWNLOAD_FREE_BYTES,
    };
    materialize_image_with_space(source, profile, cache_dir, required_free_bytes)
}

pub fn materialize_approved_iso(
    approved: &ApprovedIso,
    profile: HighOsProfile,
    cache_dir: &Path,
) -> Result<PathBuf, HighImageError> {
    materialize_image_with_space(
        &approved.source,
        profile,
        cache_dir,
        approved
            .expected_size_bytes
            .saturating_add(DOWNLOAD_HEADROOM_BYTES),
    )
}

fn materialize_image_with_space(
    source: &HighImageSource,
    profile: HighOsProfile,
    cache_dir: &Path,
    required_free_bytes: u64,
) -> Result<PathBuf, HighImageError> {
    validate_source_metadata(source, profile)?;
    fs::create_dir_all(cache_dir).map_err(|failure| {
        error(
            "IMAGE_CACHE_IO",
            "download",
            format!("cannot create custom image cache: {failure}"),
        )
    })?;
    fs::set_permissions(cache_dir, fs::Permissions::from_mode(0o700)).map_err(|failure| {
        error(
            "IMAGE_CACHE_IO",
            "download",
            format!("cannot protect custom image cache: {failure}"),
        )
    })?;
    let extension = match source.format {
        HighImageFormat::Qcow2 => "qcow2",
        HighImageFormat::Iso => "iso",
    };
    let digest = source.sha256.to_ascii_lowercase();
    let destination = cache_dir.join(format!("{digest}.{extension}"));
    if destination.exists() || destination.is_symlink() {
        verify_cached_image(source, profile, &destination)?;
        return Ok(destination);
    }
    ensure_free_space(cache_dir, required_free_bytes)?;

    let temporary = cache_dir.join(format!(".{digest}.{}.part", Uuid::new_v4()));
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .and_then(|file| file.sync_all())
        .map_err(|failure| {
            error(
                "IMAGE_CACHE_IO",
                "download",
                format!("cannot create temporary image file: {failure}"),
            )
        })?;
    let result = (|| {
        download_https(source, &temporary)?;
        verify_cached_image(source, profile, &temporary)?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).map_err(|failure| {
            error(
                "IMAGE_CACHE_IO",
                "download",
                format!("cannot protect downloaded image: {failure}"),
            )
        })?;
        File::open(&temporary)
            .and_then(|file| file.sync_all())
            .map_err(|failure| {
                error(
                    "IMAGE_CACHE_IO",
                    "download",
                    format!("cannot sync downloaded image: {failure}"),
                )
            })?;
        match fs::hard_link(&temporary, &destination) {
            Ok(()) => {}
            Err(failure) if failure.kind() == std::io::ErrorKind::AlreadyExists => {
                verify_cached_image(source, profile, &destination)?;
            }
            Err(failure) => {
                return Err(error(
                    "IMAGE_CACHE_IO",
                    "download",
                    format!("cannot publish downloaded image: {failure}"),
                ));
            }
        }
        Ok(destination.clone())
    })();
    let _ = fs::remove_file(&temporary);
    result
}

fn ensure_free_space(path: &Path, required_bytes: u64) -> Result<(), HighImageError> {
    let output = Command::new("df")
        .args(["-Pk", "--"])
        .arg(path)
        .output()
        .map_err(|failure| {
            error(
                "IMAGE_SPACE_CHECK_FAILED",
                "download",
                format!("could not inspect image cache free space: {failure}"),
            )
        })?;
    if !output.status.success() {
        return Err(error(
            "IMAGE_SPACE_CHECK_FAILED",
            "download",
            format!("df exited with {}", output.status),
        ));
    }
    let available =
        parse_df_available_bytes(&String::from_utf8_lossy(&output.stdout)).ok_or_else(|| {
            error(
                "IMAGE_SPACE_CHECK_FAILED",
                "download",
                "df returned an unrecognized result",
            )
        })?;
    if available < required_bytes {
        return Err(error(
            "IMAGE_DISK_SPACE_INSUFFICIENT",
            "download",
            format!(
                "image cache has {available} bytes available but {required_bytes} bytes are required"
            ),
        ));
    }
    Ok(())
}

fn parse_df_available_bytes(output: &str) -> Option<u64> {
    let line = output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .last()?;
    let kibibytes = line.split_whitespace().nth(3)?.parse::<u64>().ok()?;
    kibibytes.checked_mul(1024)
}

pub fn verify_cached_image(
    source: &HighImageSource,
    profile: HighOsProfile,
    path: &Path,
) -> Result<(), HighImageError> {
    validate_source_metadata(source, profile)?;
    let metadata = fs::symlink_metadata(path).map_err(|failure| {
        error(
            "IMAGE_CACHE_MISSING",
            "verification",
            format!("cached image is unavailable: {failure}"),
        )
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(error(
            "IMAGE_CACHE_UNSAFE",
            "verification",
            "cached image must be a regular non-symlink file",
        ));
    }
    if metadata.len() == 0 || metadata.len() > MAX_DOWNLOAD_BYTES {
        return Err(error(
            "IMAGE_SIZE_INVALID",
            "verification",
            format!(
                "image size {} is outside the accepted range",
                metadata.len()
            ),
        ));
    }
    let actual = sha256(path)?;
    if actual != source.sha256.to_ascii_lowercase() {
        return Err(error(
            "IMAGE_INTEGRITY_MISMATCH",
            "verification",
            "image bytes do not match the trusted SHA-256",
        ));
    }
    match source.format {
        HighImageFormat::Qcow2 => verify_qcow2(path, profile),
        HighImageFormat::Iso => verify_iso(path, profile),
    }
}

fn validate_source_metadata(
    source: &HighImageSource,
    profile: HighOsProfile,
) -> Result<Url, HighImageError> {
    let url = Url::parse(&source.url).map_err(|_| {
        error(
            "IMAGE_SOURCE_INVALID",
            "validation",
            "custom image URL is not valid",
        )
    })?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(error(
            "IMAGE_SOURCE_INVALID",
            "validation",
            "custom image source must be credential-free HTTPS without a fragment",
        ));
    }
    if !source.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) || source.sha256.len() != 64 {
        return Err(error(
            "IMAGE_CHECKSUM_INVALID",
            "validation",
            "custom image SHA-256 must contain exactly 64 hexadecimal characters",
        ));
    }
    if source.architecture != HighImageArchitecture::X86_64 {
        return Err(error(
            "IMAGE_ARCHITECTURE_UNSUPPORTED",
            "validation",
            "this agent supports only x86_64 High guests",
        ));
    }
    let compatible = matches!(
        (source.format, profile.image_kind),
        (
            HighImageFormat::Qcow2,
            HighImageKind::CloudImage | HighImageKind::PreparedQcow2
        ) | (HighImageFormat::Iso, HighImageKind::InstallMediaAndDisk)
    );
    if !compatible {
        return Err(error(
            "IMAGE_FORMAT_PROFILE_MISMATCH",
            "validation",
            "image format does not match the selected OS profile",
        ));
    }
    Ok(url)
}

fn download_https(source: &HighImageSource, destination: &Path) -> Result<(), HighImageError> {
    let url = validate_source_metadata(
        source,
        match source.format {
            HighImageFormat::Qcow2 => HighOsProfile::custom_linux_qcow2_ssh(),
            HighImageFormat::Iso => HighOsProfile::custom_linux_iso_ssh(),
        },
    )?;
    let host = url.host_str().expect("validated URL host");
    if host.parse::<IpAddr>().is_ok() {
        return Err(error(
            "IMAGE_SOURCE_NETWORK_FORBIDDEN",
            "download",
            "literal IP image sources are forbidden",
        ));
    }
    let port = url.port_or_known_default().unwrap_or(443);
    let addresses: BTreeSet<IpAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|failure| {
            error(
                "IMAGE_DOWNLOAD_DNS_FAILED",
                "download",
                format!("cannot resolve image source host: {failure}"),
            )
        })?
        .map(|address| address.ip())
        .collect();
    if addresses.is_empty() || addresses.iter().any(|address| !is_public_ip(*address)) {
        return Err(error(
            "IMAGE_SOURCE_NETWORK_FORBIDDEN",
            "download",
            "image source resolves to a local, private, reserved, or documentation address",
        ));
    }
    let mut command = Command::new("curl");
    command.args([
        "--fail",
        "--silent",
        "--show-error",
        "--location",
        "--max-redirs",
        "0",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--tlsv1.2",
        "--connect-timeout",
        "15",
        "--max-time",
        "7200",
        "--speed-limit",
        "1024",
        "--speed-time",
        "60",
        "--max-filesize",
        &MAX_DOWNLOAD_BYTES.to_string(),
        "--output",
    ]);
    command.arg(destination);
    for address in addresses {
        let rendered = match address {
            IpAddr::V4(value) => value.to_string(),
            IpAddr::V6(value) => format!("[{value}]"),
        };
        command.args(["--resolve", &format!("{host}:{port}:{rendered}")]);
    }
    command.arg(url.as_str());
    let status = command.status().map_err(|failure| {
        error(
            "IMAGE_DOWNLOAD_FAILED",
            "download",
            format!("could not start HTTPS download: {failure}"),
        )
    })?;
    if !status.success() {
        return Err(error(
            "IMAGE_DOWNLOAD_FAILED",
            "download",
            format!("HTTPS download exited with {status}"),
        ));
    }
    Ok(())
}

fn sha256(path: &Path) -> Result<String, HighImageError> {
    let mut file = File::open(path).map_err(|failure| {
        error(
            "IMAGE_CACHE_IO",
            "verification",
            format!("cannot open image: {failure}"),
        )
    })?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|failure| {
            error(
                "IMAGE_CACHE_IO",
                "verification",
                format!("cannot read image: {failure}"),
            )
        })?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn verify_qcow2(path: &Path, profile: HighOsProfile) -> Result<(), HighImageError> {
    let info = output(
        Command::new("qemu-img")
            .args(["info", "--output=json", "-f", "qcow2"])
            .arg(path),
        "IMAGE_FORMAT_UNREADABLE",
        "format",
        "qemu-img could not read the declared QCOW2",
    )?;
    let info: Value = serde_json::from_slice(&info.stdout).map_err(|_| {
        error(
            "IMAGE_FORMAT_UNREADABLE",
            "format",
            "qemu-img returned invalid metadata",
        )
    })?;
    if info["format"] != "qcow2" {
        return Err(error(
            "IMAGE_FORMAT_MISMATCH",
            "format",
            "image is not QCOW2",
        ));
    }
    let has_backing = |key: &str| info.get(key).is_some_and(|value| !value.is_null());
    if has_backing("backing-filename") || has_backing("full-backing-filename") {
        return Err(error(
            "IMAGE_UNSAFE_BACKING_FILE",
            "format",
            "custom QCOW2 must be self-contained and have no backing file",
        ));
    }
    let virtual_size = info["virtual-size"].as_u64().unwrap_or_default();
    if virtual_size < 1024 * 1024 * 1024 || virtual_size > MAX_VIRTUAL_BYTES {
        return Err(error(
            "IMAGE_VIRTUAL_SIZE_INVALID",
            "format",
            "QCOW2 virtual size is outside 1 GiB..1 TiB",
        ));
    }
    let check = Command::new("qemu-img")
        .args(["check", "-q", "-f", "qcow2"])
        .arg(path)
        .status()
        .map_err(|failure| {
            error(
                "IMAGE_CHECK_FAILED",
                "integrity",
                format!("could not start qemu-img check: {failure}"),
            )
        })?;
    if !check.success() {
        return Err(error(
            "IMAGE_CORRUPT",
            "integrity",
            "qemu-img check proved that the QCOW2 metadata is inconsistent",
        ));
    }
    let inspection = Command::new("virt-inspector")
        .env("LIBGUESTFS_BACKEND", "direct")
        .args(["--no-applications", "-a"])
        .arg(path)
        .output()
        .map_err(|failure| {
            error(
                "IMAGE_ARCHITECTURE_UNVERIFIED",
                "inspection",
                format!("could not start offline guest inspection: {failure}"),
            )
        })?;
    if !inspection.status.success() {
        return Err(error(
            "IMAGE_ARCHITECTURE_UNVERIFIED",
            "inspection",
            "offline guest inspection could not identify the installed operating system",
        ));
    }
    let report = String::from_utf8_lossy(&inspection.stdout).to_ascii_lowercase();
    if !(report.contains("<arch>x86_64</arch>") || report.contains("<arch>amd64</arch>")) {
        return Err(error(
            "IMAGE_ARCHITECTURE_UNSUPPORTED",
            "inspection",
            "offline inspection did not identify an x86_64 guest",
        ));
    }
    let expected = match profile.guest_os {
        HighGuestOs::Ubuntu => Some("ubuntu"),
        HighGuestOs::Debian => Some("debian"),
        HighGuestOs::ArchLinux => Some("arch"),
        HighGuestOs::Windows => Some("windows"),
        HighGuestOs::CustomLinux => None,
    };
    if expected.is_some_and(|name| !report.contains(name)) {
        return Err(error(
            "IMAGE_OS_PROFILE_MISMATCH",
            "inspection",
            "offline guest identity does not match the selected OS profile",
        ));
    }
    Ok(())
}

fn verify_iso(path: &Path, profile: HighOsProfile) -> Result<(), HighImageError> {
    let volume = output(
        Command::new("xorriso")
            .args(["-indev"])
            .arg(path)
            .arg("-pvd_info"),
        "IMAGE_STRUCTURE_INVALID",
        "format",
        "xorriso could not read the ISO9660 structure",
    )?;
    let listing = output(
        Command::new("xorriso")
            .args(["-indev"])
            .arg(path)
            .args(["-find", "/", "-type", "f", "-print"]),
        "IMAGE_STRUCTURE_INVALID",
        "inspection",
        "xorriso could not enumerate installation media",
    )?;
    let inspection = format!(
        "{}\n{}",
        String::from_utf8_lossy(&volume.stdout),
        String::from_utf8_lossy(&listing.stdout)
    )
    .to_ascii_lowercase();
    let (detected, architecture) = inspect_iso_text(&inspection);
    if architecture == Some(HighImageArchitecture::Aarch64) {
        return Err(error(
            "IMAGE_ARCHITECTURE_UNSUPPORTED",
            "inspection",
            "installation media is ARM64, while this agent supports x86_64",
        ));
    }
    if architecture != Some(HighImageArchitecture::X86_64) {
        return Err(error(
            "IMAGE_ARCHITECTURE_UNVERIFIED",
            "inspection",
            "installation media does not expose verifiable x86_64 boot artefacts",
        ));
    }
    if profile.guest_os != HighGuestOs::CustomLinux && detected != Some(profile.guest_os) {
        return Err(error(
            "IMAGE_OS_PROFILE_MISMATCH",
            "inspection",
            "installation media identity does not match the selected OS profile",
        ));
    }
    Ok(())
}

fn inspect_iso_text(inspection: &str) -> (Option<HighGuestOs>, Option<HighImageArchitecture>) {
    let x86 = ["amd64", "x86_64", "bootx64.efi", "/install.amd/"]
        .iter()
        .any(|marker| inspection.contains(marker));
    let arm = ["arm64", "aarch64", "bootaa64.efi"]
        .iter()
        .any(|marker| inspection.contains(marker));
    let architecture = if x86 {
        Some(HighImageArchitecture::X86_64)
    } else if arm {
        Some(HighImageArchitecture::Aarch64)
    } else {
        None
    };
    let detected = if inspection.contains("/sources/boot.wim")
        && (inspection.contains("/sources/install.wim")
            || inspection.contains("/sources/install.esd"))
    {
        Some(HighGuestOs::Windows)
    } else if inspection.contains("/arch/boot/x86_64/") {
        Some(HighGuestOs::ArchLinux)
    } else if inspection.contains("/casper/") {
        Some(HighGuestOs::Ubuntu)
    } else if inspection.contains("/install.amd/") {
        Some(HighGuestOs::Debian)
    } else {
        None
    };
    (detected, architecture)
}

pub fn automatic_install_profile(path: &Path) -> Result<HighOsProfile, HighImageError> {
    let volume = output(
        Command::new("xorriso")
            .args(["-indev"])
            .arg(path)
            .arg("-pvd_info"),
        "IMAGE_STRUCTURE_INVALID",
        "inspection",
        "xorriso could not read the ISO9660 structure",
    )?;
    let listing = output(
        Command::new("xorriso")
            .args(["-indev"])
            .arg(path)
            .args(["-find", "/", "-type", "f", "-print"]),
        "IMAGE_STRUCTURE_INVALID",
        "inspection",
        "xorriso could not enumerate installation media",
    )?;
    let inspection = format!(
        "{}\n{}",
        String::from_utf8_lossy(&volume.stdout),
        String::from_utf8_lossy(&listing.stdout)
    )
    .to_ascii_lowercase();
    let (guest_os, architecture) = inspect_iso_text(&inspection);
    if guest_os == Some(HighGuestOs::Ubuntu) && !inspection.contains("/casper/install-sources.yaml")
    {
        return Err(error(
            "INSTALL_MEDIA_VARIANT_UNSUPPORTED",
            "inspection",
            "Ubuntu media lacks casper/install-sources.yaml and is not a verified Subiquity server autoinstall ISO",
        ));
    }
    automatic_profile_for_detected(guest_os, architecture)
}

fn automatic_profile_for_detected(
    guest_os: Option<HighGuestOs>,
    architecture: Option<HighImageArchitecture>,
) -> Result<HighOsProfile, HighImageError> {
    if architecture != Some(HighImageArchitecture::X86_64) {
        return Err(error(
            "IMAGE_ARCHITECTURE_UNSUPPORTED",
            "inspection",
            "automatic ISO installation requires verified x86_64 media",
        ));
    }
    match guest_os {
        Some(HighGuestOs::Windows) => Ok(HighOsProfile::windows_rdp_legacy_iso()),
        Some(HighGuestOs::Ubuntu) => Ok(HighOsProfile::ubuntu_iso_ssh()),
        Some(HighGuestOs::Debian) => Ok(HighOsProfile::debian_iso_ssh()),
        Some(HighGuestOs::ArchLinux) => Ok(HighOsProfile::arch_linux_iso_ssh()),
        _ => Err(error(
            "AUTOMATED_INSTALL_UNSUPPORTED",
            "installation",
            "the ISO operating system is unknown or has no verified unattended adapter; interactive installation is required",
        )),
    }
}

fn output(
    command: &mut Command,
    code: &'static str,
    stage: &'static str,
    message: &'static str,
) -> Result<Output, HighImageError> {
    let result = command.output().map_err(|failure| {
        error(
            code,
            stage,
            format!("{message}: could not start checker: {failure}"),
        )
    })?;
    if !result.status.success() {
        return Err(error(
            code,
            stage,
            format!("{message} (exit {})", result.status),
        ));
    }
    Ok(result)
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    !(address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_broadcast()
        || address.is_unspecified()
        || octets[0] == 0
        || octets[0] >= 224
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113))
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    !address.is_loopback()
        && !address.is_unspecified()
        && !address.is_multicast()
        && (segments[0] & 0xe000) == 0x2000
        && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(format: HighImageFormat) -> HighImageSource {
        HighImageSource {
            url: "https://images.example.test/custom.qcow2".into(),
            sha256: "a".repeat(64),
            format,
            architecture: HighImageArchitecture::X86_64,
        }
    }

    #[test]
    fn source_requires_https_digest_and_matching_profile() {
        for profile in [
            HighOsProfile::ubuntu_ssh(),
            HighOsProfile::debian_ssh(),
            HighOsProfile::arch_linux_ssh(),
            HighOsProfile::windows_rdp(),
            HighOsProfile::custom_linux_qcow2_ssh(),
        ] {
            validate_source_metadata(&source(HighImageFormat::Qcow2), profile).unwrap();
        }
        for profile in [
            HighOsProfile::windows_rdp_legacy_iso(),
            HighOsProfile::ubuntu_iso_ssh(),
            HighOsProfile::debian_iso_ssh(),
            HighOsProfile::arch_linux_iso_ssh(),
            HighOsProfile::custom_linux_iso_ssh(),
        ] {
            validate_source_metadata(&source(HighImageFormat::Iso), profile).unwrap();
        }
        let mut invalid = source(HighImageFormat::Qcow2);
        invalid.url = "http://images.example.test/custom.qcow2".into();
        assert_eq!(
            validate_source_metadata(&invalid, HighOsProfile::debian_ssh())
                .unwrap_err()
                .code,
            "IMAGE_SOURCE_INVALID"
        );
        assert_eq!(
            validate_source_metadata(&source(HighImageFormat::Iso), HighOsProfile::debian_ssh())
                .unwrap_err()
                .code,
            "IMAGE_FORMAT_PROFILE_MISMATCH"
        );

        let mut unsupported = source(HighImageFormat::Qcow2);
        unsupported.architecture = HighImageArchitecture::Aarch64;
        assert_eq!(
            validate_source_metadata(&unsupported, HighOsProfile::debian_ssh())
                .unwrap_err()
                .code,
            "IMAGE_ARCHITECTURE_UNSUPPORTED"
        );
    }

    #[test]
    fn approved_linux_iso_catalog_is_versioned_and_windows_requires_admin_media() {
        for profile in [
            HighOsProfile::ubuntu_iso_ssh(),
            HighOsProfile::debian_iso_ssh(),
            HighOsProfile::arch_linux_iso_ssh(),
        ] {
            let approved = approved_iso(profile).unwrap();
            assert!(approved.source.url.starts_with("https://"));
            let parsed = Url::parse(&approved.source.url).unwrap();
            assert_eq!(parsed.scheme(), "https");
            assert!(parsed.host_str().is_some());
            assert!(!approved.source.url.contains(['[', ']', '(', ')']));
            assert!(!approved.source.url.contains("latest"));
            assert_eq!(approved.source.sha256.len(), 64);
            assert!(
                approved
                    .source
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            );
            assert_eq!(approved.source.format, HighImageFormat::Iso);
            assert_eq!(approved.source.architecture, HighImageArchitecture::X86_64);
            assert!(approved.expected_size_bytes > 600 * 1024 * 1024);
            validate_source_metadata(&approved.source, profile).unwrap();
        }
        let failure = approved_iso(HighOsProfile::windows_rdp_legacy_iso()).unwrap_err();
        assert_eq!(failure.code, "WINDOWS_ISO_ADMIN_REQUIRED");
        assert_eq!(failure.stage, "licensing");

        assert!(windows_admin_iso_from_values(None, None).unwrap().is_none());
        assert!(
            windows_admin_iso_from_values(
                Some("https://example.test/windows.iso".into()),
                Some("a".repeat(64).into()),
            )
            .unwrap()
            .is_some()
        );
        assert_eq!(
            windows_admin_iso_from_values(Some("https://example.test/windows.iso".into()), None)
                .unwrap_err()
                .code,
            "WINDOWS_ISO_CONFIG_INCOMPLETE"
        );
    }

    #[test]
    fn parses_df_space_and_rejects_malformed_results() {
        let report = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 10000 2000 8000 20% /var/lib/honeyforge\n";
        assert_eq!(parse_df_available_bytes(report), Some(8_192_000));
        assert_eq!(parse_df_available_bytes("not df output\n"), None);
    }

    #[test]
    fn ssrf_filter_rejects_non_public_ranges() {
        for address in [
            "127.0.0.1",
            "10.2.3.4",
            "169.254.169.254",
            "192.0.2.1",
            "100.64.0.1",
            "::1",
            "fc00::1",
            "2001:db8::1",
        ] {
            assert!(!is_public_ip(address.parse().unwrap()), "{address}");
        }
        assert!(is_public_ip("1.1.1.1".parse().unwrap()));
        assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn checksum_mismatch_is_not_reported_as_corruption() {
        let directory = std::env::temp_dir().join(format!("hf-image-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("image.qcow2");
        fs::write(&path, b"not the reviewed bytes").unwrap();
        let failure = verify_cached_image(
            &source(HighImageFormat::Qcow2),
            HighOsProfile::debian_ssh(),
            &path,
        )
        .unwrap_err();
        assert_eq!(failure.code, "IMAGE_INTEGRITY_MISMATCH");
        assert!(!failure.to_string().contains("CORRUPT"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn iso_inspection_detects_supported_operating_systems_and_architecture() {
        let cases = [
            ("/casper/vmlinuz /efi/boot/bootx64.efi", HighGuestOs::Ubuntu),
            ("/install.amd/vmlinuz", HighGuestOs::Debian),
            ("/arch/boot/x86_64/vmlinuz-linux", HighGuestOs::ArchLinux),
            (
                "/sources/boot.wim /sources/install.wim /efi/boot/bootx64.efi",
                HighGuestOs::Windows,
            ),
        ];
        for (listing, expected) in cases {
            assert_eq!(
                inspect_iso_text(&listing.to_ascii_lowercase()),
                (Some(expected), Some(HighImageArchitecture::X86_64))
            );
        }
    }

    #[test]
    fn iso_inspection_does_not_guess_unknown_or_arm_media() {
        assert_eq!(inspect_iso_text("/readme.txt"), (None, None));
        assert_eq!(
            inspect_iso_text(
                "volume id: NIXOS_ISO /nix-store.squashfs /boot/bzImage /efi/boot/bootx64.efi"
            ),
            (None, Some(HighImageArchitecture::X86_64))
        );
        assert_eq!(
            inspect_iso_text("/efi/boot/bootaa64.efi /casper/vmlinuz"),
            (
                Some(HighGuestOs::Ubuntu),
                Some(HighImageArchitecture::Aarch64)
            )
        );
    }

    #[test]
    fn automatic_iso_routing_selects_only_explicit_installers() {
        assert_eq!(
            automatic_profile_for_detected(
                Some(HighGuestOs::Windows),
                Some(HighImageArchitecture::X86_64)
            )
            .unwrap(),
            HighOsProfile::windows_rdp_legacy_iso()
        );
        assert_eq!(
            automatic_profile_for_detected(
                Some(HighGuestOs::Ubuntu),
                Some(HighImageArchitecture::X86_64)
            )
            .unwrap(),
            HighOsProfile::ubuntu_iso_ssh()
        );
        assert_eq!(
            automatic_profile_for_detected(
                Some(HighGuestOs::Debian),
                Some(HighImageArchitecture::X86_64)
            )
            .unwrap(),
            HighOsProfile::debian_iso_ssh()
        );
        assert_eq!(
            automatic_profile_for_detected(
                Some(HighGuestOs::ArchLinux),
                Some(HighImageArchitecture::X86_64)
            )
            .unwrap(),
            HighOsProfile::arch_linux_iso_ssh()
        );
        assert_eq!(
            automatic_profile_for_detected(None, Some(HighImageArchitecture::X86_64))
                .unwrap_err()
                .code,
            "AUTOMATED_INSTALL_UNSUPPORTED"
        );
    }
}
