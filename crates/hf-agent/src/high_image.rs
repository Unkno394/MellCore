use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs},
    os::{
        fd::AsRawFd,
        unix::fs::{OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Command, Output},
};

use hf_core::{
    HighGuestOs, HighImageArchitecture, HighImageFormat, HighImageKind, HighImageSource,
    HighOsProfile,
};
use serde::{Deserialize, Serialize};
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
    materialize_image_with_space(source, profile, cache_dir, required_free_bytes, None)
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
        Some(approved.expected_size_bytes),
    )
}

pub fn cached_image_path(
    source: &HighImageSource,
    profile: HighOsProfile,
    cache_dir: &Path,
) -> Result<PathBuf, HighImageError> {
    validate_source_metadata(source, profile)?;
    let extension = match source.format {
        HighImageFormat::Qcow2 => "qcow2",
        HighImageFormat::Iso => "iso",
    };
    Ok(cache_dir.join(format!(
        "{}.{}",
        source.sha256.to_ascii_lowercase(),
        extension
    )))
}

pub fn cache_has_download(
    source: &HighImageSource,
    profile: HighOsProfile,
    cache_dir: &Path,
) -> Result<bool, HighImageError> {
    let destination = cached_image_path(source, profile, cache_dir)?;
    let extension = destination
        .extension()
        .and_then(|value| value.to_str())
        .expect("cache image extension");
    let partial = cache_dir.join(format!(
        ".{}.{}.part",
        source.sha256.to_ascii_lowercase(),
        extension
    ));
    Ok(
        destination.exists()
            || destination.is_symlink()
            || partial.exists()
            || partial.is_symlink(),
    )
}

fn materialize_image_with_space(
    source: &HighImageSource,
    profile: HighOsProfile,
    cache_dir: &Path,
    required_free_bytes: u64,
    expected_size_bytes: Option<u64>,
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
    let digest = source.sha256.to_ascii_lowercase();
    let destination = cached_image_path(source, profile, cache_dir)?;
    let extension = destination
        .extension()
        .and_then(|value| value.to_str())
        .expect("cache image extension");
    let partial = cache_dir.join(format!(".{digest}.{extension}.part"));
    let metadata = cache_dir.join(format!(".{digest}.{extension}.part.json"));
    let lock_path = cache_dir.join(format!(".{digest}.{extension}.lock"));
    let _lock = DownloadLock::acquire(&lock_path)?;
    if destination.exists() || destination.is_symlink() {
        verify_downloaded_image(source, profile, &destination, expected_size_bytes)?;
        return Ok(destination);
    }
    if partial.exists() || partial.is_symlink() {
        match verify_downloaded_image(source, profile, &partial, expected_size_bytes) {
            Ok(()) => {
                publish_download(&partial, &metadata, &destination, cache_dir)?;
                return Ok(destination);
            }
            Err(failure) if failure.code == "IMAGE_CACHE_UNSAFE" => return Err(failure),
            Err(_) => {}
        }
    } else {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&partial)
            .and_then(|file| file.sync_all())
            .map_err(|failure| {
                error(
                    "IMAGE_CACHE_IO",
                    "download",
                    format!("cannot create persistent partial image: {failure}"),
                )
            })?;
    }
    let partial_size = fs::metadata(&partial).map(|value| value.len()).unwrap_or(0);
    ensure_free_space(cache_dir, required_free_bytes.saturating_sub(partial_size))?;
    let result = (|| {
        download_https(source, &partial)?;
        if let Err(failure) =
            verify_downloaded_image(source, profile, &partial, expected_size_bytes)
        {
            let _ = fs::remove_file(&partial);
            let _ = fs::remove_file(&metadata);
            return Err(failure);
        }
        publish_download(&partial, &metadata, &destination, cache_dir)?;
        Ok(destination.clone())
    })();
    result
}

struct DownloadLock(File);

impl DownloadLock {
    fn acquire(path: &Path) -> Result<Self, HighImageError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
            .map_err(|failure| {
                error(
                    "IMAGE_CACHE_LOCK_FAILED",
                    "download",
                    format!("cannot open image download lock: {failure}"),
                )
            })?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|failure| {
            error(
                "IMAGE_CACHE_LOCK_FAILED",
                "download",
                format!("cannot protect image download lock: {failure}"),
            )
        })?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(error(
                "IMAGE_CACHE_LOCK_FAILED",
                "download",
                format!(
                    "cannot lock image download: {}",
                    std::io::Error::last_os_error()
                ),
            ));
        }
        Ok(Self(file))
    }
}

impl Drop for DownloadLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn verify_downloaded_image(
    source: &HighImageSource,
    profile: HighOsProfile,
    path: &Path,
    expected_size_bytes: Option<u64>,
) -> Result<(), HighImageError> {
    if let Some(expected) = expected_size_bytes {
        let actual = fs::metadata(path)
            .map(|value| value.len())
            .map_err(|failure| {
                error(
                    "IMAGE_CACHE_MISSING",
                    "verification",
                    format!("downloaded image metadata is unavailable: {failure}"),
                )
            })?;
        if actual != expected {
            return Err(error(
                "IMAGE_SIZE_INVALID",
                "verification",
                format!("downloaded image has {actual} bytes; expected {expected}"),
            ));
        }
    }
    verify_cached_image(source, profile, path)
}

fn publish_download(
    partial: &Path,
    metadata: &Path,
    destination: &Path,
    cache_dir: &Path,
) -> Result<(), HighImageError> {
    fs::set_permissions(partial, fs::Permissions::from_mode(0o600)).map_err(|failure| {
        error(
            "IMAGE_CACHE_IO",
            "download",
            format!("cannot protect downloaded image: {failure}"),
        )
    })?;
    File::open(partial)
        .and_then(|file| file.sync_all())
        .map_err(|failure| {
            error(
                "IMAGE_CACHE_IO",
                "download",
                format!("cannot sync downloaded image: {failure}"),
            )
        })?;
    match fs::hard_link(partial, destination) {
        Ok(()) => {}
        Err(failure) => {
            return Err(error(
                "IMAGE_CACHE_IO",
                "download",
                format!("cannot atomically publish downloaded image: {failure}"),
            ));
        }
    }
    File::open(cache_dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|failure| {
            error(
                "IMAGE_CACHE_IO",
                "download",
                format!("cannot sync image cache directory: {failure}"),
            )
        })?;
    let _ = fs::remove_file(partial);
    let _ = fs::remove_file(metadata);
    let _ = fs::remove_file(path_with_suffix(partial, ".headers"));
    Ok(())
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
    let addresses = validated_download_addresses(addresses)?;
    download_https_from_addresses(&url, destination, host, port, &addresses, Path::new("curl"))
}

fn validated_download_addresses(
    addresses: impl IntoIterator<Item = IpAddr>,
) -> Result<Vec<IpAddr>, HighImageError> {
    let addresses: BTreeSet<_> = addresses.into_iter().collect();
    if addresses.is_empty() || addresses.iter().any(|address| !is_public_ip(*address)) {
        return Err(error(
            "IMAGE_SOURCE_NETWORK_FORBIDDEN",
            "download",
            "image source resolves to a local, private, reserved, or documentation address",
        ));
    }
    let mut addresses: Vec<_> = addresses.into_iter().collect();
    addresses.sort_by_key(|address| match address {
        IpAddr::V4(_) => 0,
        IpAddr::V6(_) => 1,
    });
    Ok(addresses)
}

fn try_download_addresses(
    addresses: &[IpAddr],
    mut attempt: impl FnMut(IpAddr) -> Result<(), String>,
) -> Result<(), HighImageError> {
    let mut failures = Vec::new();
    for address in addresses {
        match attempt(*address) {
            Ok(()) => return Ok(()),
            Err(failure) => failures.push(format!("{address}: {failure}")),
        }
    }
    Err(error(
        "IMAGE_DOWNLOAD_FAILED",
        "download",
        format!(
            "HTTPS connection failed for every validated address: {}",
            failures.join("; ")
        ),
    ))
}

fn download_https_from_addresses(
    url: &Url,
    destination: &Path,
    host: &str,
    port: u16,
    addresses: &[IpAddr],
    curl: &Path,
) -> Result<(), HighImageError> {
    try_download_addresses(addresses, |address| {
        run_curl_download_attempt(url, destination, host, port, address, curl)
    })
}

fn run_curl_download_attempt(
    url: &Url,
    destination: &Path,
    host: &str,
    port: u16,
    address: IpAddr,
    curl: &Path,
) -> Result<(), String> {
    let metadata_path = path_with_suffix(destination, ".json");
    let mut downloaded = file_size(destination)?;
    if downloaded > MAX_DOWNLOAD_BYTES {
        reset_partial_download(destination, &metadata_path)?;
        downloaded = 0;
    }
    let stored = read_partial_metadata(&metadata_path).or_else(|| {
        recover_partial_metadata_from_headers(destination).and_then(|metadata| {
            write_partial_metadata(&metadata_path, &metadata)
                .ok()
                .map(|()| metadata)
        })
    });
    if let Some(stored) = stored.as_ref() {
        if downloaded > 0
            && stored.total_size.is_some_and(|total| downloaded < total)
            && resume_validator(stored).is_some()
        {
            let validator = resume_validator(stored).expect("checked above");
            let result = execute_curl(
                url,
                destination,
                host,
                port,
                address,
                curl,
                Some((downloaded, validator.clone())),
            )?;
            let current = file_size(destination)?;
            if valid_resumed_response(&result.response, stored, &validator, downloaded, current) {
                let refreshed =
                    metadata_from_response(&result.response).unwrap_or_else(|| stored.clone());
                write_partial_metadata(&metadata_path, &refreshed)?;
                if result.success && current == refreshed.total_size.unwrap_or(current) {
                    return Ok(());
                }
                return Err(result.diagnostic());
            }

            truncate_to(destination, downloaded)?;
            if result.response.status != Some(200) {
                return Err(format!(
                    "server rejected a safe resume; {}",
                    result.diagnostic()
                ));
            }
            // A 200 response to a range request means the representation changed or the server
            // ignored Range. Start clean; never concatenate that response with the old prefix.
            reset_partial_download(destination, &metadata_path)?;
        } else if downloaded > 0 {
            reset_partial_download(destination, &metadata_path)?;
        }
    } else if downloaded > 0 {
        // Without a trusted validator an old prefix cannot safely be joined to new bytes.
        reset_partial_download(destination, &metadata_path)?;
    }

    let result = execute_curl(url, destination, host, port, address, curl, None)?;
    let current = file_size(destination)?;
    if current > MAX_DOWNLOAD_BYTES {
        reset_partial_download(destination, &metadata_path)?;
        return Err("download exceeded the configured size limit".into());
    }
    let response_metadata = metadata_from_response(&result.response);
    if let Some(metadata) = response_metadata.as_ref() {
        if current > 0 && current <= metadata.total_size.unwrap_or(MAX_DOWNLOAD_BYTES) {
            write_partial_metadata(&metadata_path, metadata)?;
        }
    }
    if !result.success {
        return Err(result.diagnostic());
    }
    if result.response.status != Some(200) {
        return Err(format!(
            "HTTPS source returned HTTP status {}; expected 200",
            result
                .response
                .status
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".into())
        ));
    }
    if let Some(expected) = result.response.content_length {
        if current != expected {
            return Err(format!(
                "HTTPS response declared {expected} bytes but wrote {current}"
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PartialDownloadMetadata {
    etag: Option<String>,
    last_modified: Option<String>,
    total_size: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ContentRange {
    start: u64,
    end: u64,
    total: u64,
}

#[derive(Debug, Default)]
struct HttpResponseMetadata {
    status: Option<u16>,
    etag: Option<String>,
    last_modified: Option<String>,
    content_length: Option<u64>,
    content_range: Option<ContentRange>,
}

struct CurlAttempt {
    success: bool,
    status: String,
    stderr: String,
    response: HttpResponseMetadata,
}

impl CurlAttempt {
    fn diagnostic(&self) -> String {
        if self.stderr.is_empty() {
            format!("curl exited with {}", self.status)
        } else {
            format!("curl exited with {}: {}", self.status, self.stderr)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ResumeValidator {
    Etag(String),
    LastModified(String),
}

impl ResumeValidator {
    fn value(&self) -> &str {
        match self {
            Self::Etag(value) | Self::LastModified(value) => value,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn execute_curl(
    url: &Url,
    destination: &Path,
    host: &str,
    port: u16,
    address: IpAddr,
    curl: &Path,
    resume: Option<(u64, ResumeValidator)>,
) -> Result<CurlAttempt, String> {
    if resume.is_none() {
        truncate_to(destination, 0)?;
    }
    let header_path = path_with_suffix(destination, ".headers");
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&header_path)
        .map_err(|failure| format!("cannot create HTTPS response header file: {failure}"))?;
    let mut command = Command::new(curl);
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
        "--noproxy",
        "*",
        "--proxy",
        "",
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
        "--dump-header",
    ]);
    command.arg(&header_path);
    command.arg("--output");
    command.arg(destination);
    if let Some((_offset, validator)) = resume.as_ref() {
        command.args(["--continue-at", "-", "--header"]);
        command.arg(format!("If-Range: {}", validator.value()));
    }
    command.args(["--resolve", &curl_resolve_entry(host, port, address)]);
    command.arg(url.as_str());
    for variable in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    ] {
        command.env_remove(variable);
    }
    let output = command.output().map_err(|failure| {
        let _ = fs::remove_file(&header_path);
        format!("could not start curl: {failure}")
    })?;
    let response = read_response_headers(&header_path);
    if output.status.success() {
        let _ = fs::remove_file(&header_path);
    }
    let response = response?;
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    let diagnostic: String = diagnostic.trim().chars().take(1024).collect();
    let diagnostic = diagnostic.replace(url.as_str(), "<image-url>");
    Ok(CurlAttempt {
        success: output.status.success(),
        status: output.status.to_string(),
        stderr: diagnostic,
        response,
    })
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn file_size(path: &Path) -> Result<u64, String> {
    fs::metadata(path)
        .map(|metadata| metadata.len())
        .map_err(|failure| format!("cannot inspect partial download: {failure}"))
}

fn truncate_to(path: &Path, length: u64) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|failure| format!("cannot open partial download: {failure}"))?;
    file.set_len(length)
        .map_err(|failure| format!("cannot reset partial download: {failure}"))?;
    file.seek(SeekFrom::Start(length))
        .map_err(|failure| format!("cannot seek partial download: {failure}"))?;
    Ok(())
}

fn reset_partial_download(path: &Path, metadata_path: &Path) -> Result<(), String> {
    truncate_to(path, 0)?;
    if let Err(failure) = fs::remove_file(metadata_path) {
        if failure.kind() != std::io::ErrorKind::NotFound {
            return Err(format!("cannot remove obsolete resume metadata: {failure}"));
        }
    }
    match fs::remove_file(path_with_suffix(path, ".headers")) {
        Ok(()) => Ok(()),
        Err(failure) if failure.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(failure) => Err(format!(
            "cannot remove obsolete response headers: {failure}"
        )),
    }
}

fn recover_partial_metadata_from_headers(path: &Path) -> Option<PartialDownloadMetadata> {
    let response = read_response_headers(&path_with_suffix(path, ".headers")).ok()?;
    matches!(response.status, Some(200 | 206))
        .then(|| metadata_from_response(&response))
        .flatten()
}

fn read_partial_metadata(path: &Path) -> Option<PartialDownloadMetadata> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() || metadata.len() > 4096
    {
        return None;
    }
    let parsed: PartialDownloadMetadata = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
    if parsed
        .total_size
        .is_some_and(|size| size == 0 || size > MAX_DOWNLOAD_BYTES)
        || parsed
            .etag
            .iter()
            .chain(parsed.last_modified.iter())
            .any(|value| !safe_header_value(value))
    {
        return None;
    }
    Some(parsed)
}

fn write_partial_metadata(path: &Path, metadata: &PartialDownloadMetadata) -> Result<(), String> {
    let encoded = serde_json::to_vec(metadata)
        .map_err(|failure| format!("cannot encode resume metadata: {failure}"))?;
    let temporary = path_with_suffix(path, &format!(".tmp-{}", Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|failure| format!("cannot create resume metadata: {failure}"))?;
        file.write_all(&encoded)
            .map_err(|failure| format!("cannot write resume metadata: {failure}"))?;
        file.sync_all()
            .map_err(|failure| format!("cannot sync resume metadata: {failure}"))?;
        fs::rename(&temporary, path)
            .map_err(|failure| format!("cannot publish resume metadata: {failure}"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn resume_validator(metadata: &PartialDownloadMetadata) -> Option<ResumeValidator> {
    metadata
        .etag
        .as_ref()
        .filter(|etag| !etag.starts_with("W/"))
        .cloned()
        .map(ResumeValidator::Etag)
        .or_else(|| {
            metadata
                .last_modified
                .as_ref()
                .cloned()
                .map(ResumeValidator::LastModified)
        })
}

fn metadata_from_response(response: &HttpResponseMetadata) -> Option<PartialDownloadMetadata> {
    let total_size = response
        .content_range
        .map(|range| range.total)
        .or(response.content_length);
    if total_size.is_some_and(|size| size == 0 || size > MAX_DOWNLOAD_BYTES) {
        return None;
    }
    Some(PartialDownloadMetadata {
        etag: response.etag.clone(),
        last_modified: response.last_modified.clone(),
        total_size,
    })
}

fn valid_resumed_response(
    response: &HttpResponseMetadata,
    stored: &PartialDownloadMetadata,
    validator: &ResumeValidator,
    offset: u64,
    current: u64,
) -> bool {
    let Some(range) = response.content_range else {
        return false;
    };
    let validator_matches = match validator {
        ResumeValidator::Etag(value) => response.etag.as_ref() == Some(value),
        ResumeValidator::LastModified(value) => response.last_modified.as_ref() == Some(value),
    };
    response.status == Some(206)
        && validator_matches
        && range.start == offset
        && range.end >= range.start
        && current > offset
        && current <= range.end.saturating_add(1)
        && range.total == stored.total_size.unwrap_or(range.total)
        && range.total <= MAX_DOWNLOAD_BYTES
        && response
            .content_length
            .is_none_or(|length| length == range.end - range.start + 1)
}

fn read_response_headers(path: &Path) -> Result<HttpResponseMetadata, String> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(failure) if failure.kind() == std::io::ErrorKind::NotFound => {
            return Ok(HttpResponseMetadata::default());
        }
        Err(failure) => return Err(format!("cannot inspect HTTPS response headers: {failure}")),
    };
    if metadata.len() > 64 * 1024 {
        return Err("HTTPS response headers exceed the accepted limit".into());
    }
    parse_response_headers(
        &fs::read_to_string(path)
            .map_err(|failure| format!("cannot read HTTPS response headers: {failure}"))?,
    )
}

fn parse_response_headers(headers: &str) -> Result<HttpResponseMetadata, String> {
    let mut response = HttpResponseMetadata::default();
    for raw_line in headers.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.starts_with("HTTP/") {
            response = HttpResponseMetadata::default();
            response.status = line
                .split_whitespace()
                .nth(1)
                .and_then(|status| status.parse().ok());
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("etag") {
            if !safe_header_value(value) {
                return Err("HTTPS response contains an unsafe ETag".into());
            }
            response.etag = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("last-modified") {
            if !safe_header_value(value) {
                return Err("HTTPS response contains an unsafe Last-Modified value".into());
            }
            response.last_modified = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("content-length") {
            response.content_length = value.parse().ok();
        } else if name.eq_ignore_ascii_case("content-range") {
            response.content_range = parse_content_range(value);
        }
    }
    Ok(response)
}

fn safe_header_value(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && !value.chars().any(|value| value.is_control())
}

fn parse_content_range(value: &str) -> Option<ContentRange> {
    let value = value.strip_prefix("bytes ")?;
    let (range, total) = value.split_once('/')?;
    let (start, end) = range.split_once('-')?;
    let parsed = ContentRange {
        start: start.parse().ok()?,
        end: end.parse().ok()?,
        total: total.parse().ok()?,
    };
    (parsed.start <= parsed.end && parsed.end < parsed.total).then_some(parsed)
}

fn curl_resolve_entry(host: &str, port: u16, address: IpAddr) -> String {
    let rendered = match address {
        IpAddr::V4(value) => value.to_string(),
        IpAddr::V6(value) => format!("[{value}]"),
    };
    format!("{host}:{port}:{rendered}")
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
        &mut xorriso_file_listing_command(path),
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

fn xorriso_file_listing_command(path: &Path) -> Command {
    let mut command = Command::new("xorriso");
    command
        .arg("-indev")
        .arg(path)
        .args(["-find", "/", "-type", "f", "-exec", "echo"]);
    command
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
        &mut xorriso_file_listing_command(path),
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
    fn download_addresses_are_all_validated_and_ipv4_is_tried_first() {
        let addresses = validated_download_addresses([
            "2606:4700:4700::1111".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
        ])
        .unwrap();
        assert_eq!(addresses.len(), 3);
        assert!(matches!(addresses[0], IpAddr::V4(_)));
        assert!(matches!(addresses[1], IpAddr::V4(_)));
        assert!(matches!(addresses[2], IpAddr::V6(_)));

        let failure = validated_download_addresses([
            "1.1.1.1".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
        ])
        .unwrap_err();
        assert_eq!(failure.code, "IMAGE_SOURCE_NETWORK_FORBIDDEN");
    }

    #[test]
    fn https_download_retries_one_validated_address_at_a_time() {
        let addresses = validated_download_addresses([
            "2606:4700:4700::1111".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
        ])
        .unwrap();
        let mut attempted = Vec::new();
        try_download_addresses(&addresses, |address| {
            attempted.push(address);
            if address == "2606:4700:4700::1111".parse::<IpAddr>().unwrap() {
                Ok(())
            } else {
                Err("connection refused".into())
            }
        })
        .unwrap();

        assert_eq!(attempted, addresses);
        assert_eq!(
            curl_resolve_entry("releases.ubuntu.com", 443, addresses[0]),
            "releases.ubuntu.com:443:1.1.1.1"
        );
        assert_eq!(
            curl_resolve_entry("releases.ubuntu.com", 443, addresses[2]),
            "releases.ubuntu.com:443:[2606:4700:4700::1111]"
        );
    }

    #[test]
    fn curl_download_path_pins_one_ip_per_process_and_ignores_service_proxy() {
        let directory = std::env::temp_dir().join(format!("hf-curl-path-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let curl = directory.join("curl");
        let destination = directory.join("image.part");
        fs::write(&destination, b"stale partial bytes").unwrap();
        fs::write(
            &curl,
            r###"#!/bin/sh
set -eu
[ -z "${HTTP_PROXY+x}${HTTPS_PROXY+x}${ALL_PROXY+x}${http_proxy+x}${https_proxy+x}${all_proxy+x}" ]
log="$(dirname "$0")/calls"
printf '%s\n' '---' "$@" >> "$log"
resolve= output= headers= resolve_count=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --resolve) shift; resolve=$1; resolve_count=$((resolve_count + 1)) ;;
    --output) shift; output=$1 ;;
    --dump-header) shift; headers=$1 ;;
  esac
  shift
done
[ "$resolve_count" -eq 1 ] && [ -n "$output" ] && [ -n "$headers" ]
case "$resolve" in
  *:1.1.1.1) echo 'curl: (7) simulated connection failure' >&2; exit 7 ;;
esac
printf 'HTTP/1.1 200 OK\r\nContent-Length: 22\r\nETag: "fixture-v1"\r\n\r\n' > "$headers"
printf 'small download fixture' > "$output"
"###,
        )
        .unwrap();
        fs::set_permissions(&curl, fs::Permissions::from_mode(0o700)).unwrap();

        let url = Url::parse("https://releases.ubuntu.com/test.iso").unwrap();
        let addresses =
            validated_download_addresses(["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()])
                .unwrap();
        download_https_from_addresses(
            &url,
            &destination,
            "releases.ubuntu.com",
            443,
            &addresses,
            &curl,
        )
        .unwrap();

        assert_eq!(fs::read(&destination).unwrap(), b"small download fixture");
        let calls = fs::read_to_string(directory.join("calls")).unwrap();
        assert_eq!(calls.matches("--resolve").count(), 2);
        assert!(calls.contains("releases.ubuntu.com:443:1.1.1.1"));
        assert!(calls.contains("releases.ubuntu.com:443:8.8.8.8"));
        assert!(calls.contains("--noproxy\n*\n"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn interrupted_download_resumes_after_restart_with_matching_validator() {
        let directory = std::env::temp_dir().join(format!("hf-curl-resume-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let curl = directory.join("curl");
        let destination = directory.join("image.part");
        fs::write(&destination, b"").unwrap();
        fs::write(
            &curl,
            r###"#!/bin/sh
set -eu
output= headers= resume=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) shift; output=$1 ;;
    --dump-header) shift; headers=$1 ;;
    --continue-at) shift; [ "$1" = - ]; resume=1 ;;
  esac
  shift
done
printf '%s\n' "$resume" >> "$(dirname "$0")/resume-calls"
if [ "$resume" -eq 0 ] && [ ! -e "$(dirname "$0")/interrupted" ]; then
  : > "$(dirname "$0")/interrupted"
  printf 'HTTP/1.1 200 OK\r\nContent-Length: 10\r\nETag: "image-v1"\r\n\r\n' > "$headers"
  printf '01234' > "$output"
  echo 'curl: (18) simulated interrupted transfer' >&2
  exit 18
fi
[ "$resume" -eq 1 ]
printf 'HTTP/1.1 206 Partial Content\r\nContent-Length: 5\r\nContent-Range: bytes 5-9/10\r\nETag: "image-v1"\r\n\r\n' > "$headers"
printf '56789' >> "$output"
"###,
        )
        .unwrap();
        fs::set_permissions(&curl, fs::Permissions::from_mode(0o700)).unwrap();
        let url = Url::parse("https://releases.ubuntu.com/test.iso").unwrap();
        let addresses = ["1.1.1.1".parse().unwrap()];

        let interrupted = download_https_from_addresses(
            &url,
            &destination,
            "releases.ubuntu.com",
            443,
            &addresses,
            &curl,
        )
        .unwrap_err();
        assert_eq!(interrupted.code, "IMAGE_DOWNLOAD_FAILED");
        assert_eq!(fs::read(&destination).unwrap(), b"01234");
        let metadata = path_with_suffix(&destination, ".json");
        assert!(metadata.is_file());
        assert!(path_with_suffix(&destination, ".headers").is_file());
        // Simulate a hard agent stop after curl wrote headers and body bytes but before the
        // resume sidecar could be published. Restart recovery must reconstruct it from headers.
        fs::remove_file(metadata).unwrap();

        download_https_from_addresses(
            &url,
            &destination,
            "releases.ubuntu.com",
            443,
            &addresses,
            &curl,
        )
        .unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"0123456789");
        assert_eq!(
            fs::read_to_string(directory.join("resume-calls")).unwrap(),
            "0\n1\n"
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn ignored_range_restarts_cleanly_without_concatenating_representations() {
        let directory = std::env::temp_dir().join(format!("hf-curl-restart-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let curl = directory.join("curl");
        let destination = directory.join("image.part");
        fs::write(&destination, b"old12").unwrap();
        write_partial_metadata(
            &path_with_suffix(&destination, ".json"),
            &PartialDownloadMetadata {
                etag: Some("\"old-image\"".into()),
                last_modified: None,
                total_size: Some(10),
            },
        )
        .unwrap();
        fs::write(
            &curl,
            r###"#!/bin/sh
set -eu
output= headers= resume=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) shift; output=$1 ;;
    --dump-header) shift; headers=$1 ;;
    --continue-at) shift; resume=1 ;;
  esac
  shift
done
printf '%s\n' "$resume" >> "$(dirname "$0")/resume-calls"
printf 'HTTP/1.1 200 OK\r\nContent-Length: 11\r\nETag: "new-image"\r\n\r\n' > "$headers"
if [ "$resume" -eq 1 ]; then
  printf 'new-content' >> "$output"
else
  printf 'new-content' > "$output"
fi
"###,
        )
        .unwrap();
        fs::set_permissions(&curl, fs::Permissions::from_mode(0o700)).unwrap();
        let url = Url::parse("https://releases.ubuntu.com/test.iso").unwrap();

        run_curl_download_attempt(
            &url,
            &destination,
            "releases.ubuntu.com",
            443,
            "1.1.1.1".parse().unwrap(),
            &curl,
        )
        .unwrap();

        assert_eq!(fs::read(&destination).unwrap(), b"new-content");
        assert_eq!(
            fs::read_to_string(directory.join("resume-calls")).unwrap(),
            "1\n0\n"
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn complete_partial_is_published_atomically_and_resume_state_is_removed() {
        let directory = std::env::temp_dir().join(format!("hf-publish-part-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let partial = directory.join(".digest.iso.part");
        let metadata = directory.join(".digest.iso.part.json");
        let destination = directory.join("digest.iso");
        fs::write(&partial, b"complete reviewed image").unwrap();
        fs::write(&metadata, b"{}").unwrap();

        publish_download(&partial, &metadata, &destination, &directory).unwrap();

        assert_eq!(fs::read(&destination).unwrap(), b"complete reviewed image");
        assert!(!partial.exists());
        assert!(!metadata.exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn download_lock_rejects_a_concurrent_writer_until_released() {
        let directory = std::env::temp_dir().join(format!("hf-download-lock-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("image.lock");
        let lock = DownloadLock::acquire(&path).unwrap();
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();

        assert_ne!(
            unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        drop(lock);
        assert_eq!(
            unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        unsafe {
            libc::flock(contender.as_raw_fd(), libc::LOCK_UN);
        }
        drop(contender);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn corrupt_completed_iso_is_rejected_by_checksum_before_iso_inspection() {
        let directory = std::env::temp_dir().join(format!("hf-corrupt-iso-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("image.iso");
        fs::write(&path, b"not the trusted installation media").unwrap();

        let failure = verify_downloaded_image(
            &source(HighImageFormat::Iso),
            HighOsProfile::ubuntu_iso_ssh(),
            &path,
            None,
        )
        .unwrap_err();
        assert_eq!(failure.code, "IMAGE_INTEGRITY_MISMATCH");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn resume_requires_206_matching_range_and_validator() {
        let stored = PartialDownloadMetadata {
            etag: Some("\"v1\"".into()),
            last_modified: None,
            total_size: Some(10),
        };
        let response = parse_response_headers(
            "HTTP/1.1 206 Partial Content\r\nContent-Length: 5\r\nContent-Range: bytes 5-9/10\r\nETag: \"v1\"\r\n\r\n",
        )
        .unwrap();
        assert!(valid_resumed_response(
            &response,
            &stored,
            &ResumeValidator::Etag("\"v1\"".into()),
            5,
            10,
        ));
        assert!(!valid_resumed_response(
            &response,
            &stored,
            &ResumeValidator::Etag("\"different\"".into()),
            5,
            10,
        ));
    }

    #[test]
    fn https_download_reports_each_failed_address() {
        let addresses = [
            "1.1.1.1".parse().unwrap(),
            "2606:4700:4700::1111".parse().unwrap(),
        ];
        let failure = try_download_addresses(&addresses, |address| {
            Err(format!("simulated failure for {address}"))
        })
        .unwrap_err();
        assert_eq!(failure.code, "IMAGE_DOWNLOAD_FAILED");
        assert!(failure.message.contains("1.1.1.1"));
        assert!(failure.message.contains("2606:4700:4700::1111"));
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
    fn xorriso_listing_uses_supported_find_exec_echo_syntax() {
        let command = xorriso_file_listing_command(Path::new("/tmp/installer image.iso"));
        let arguments: Vec<_> = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            arguments,
            [
                "-indev",
                "/tmp/installer image.iso",
                "-find",
                "/",
                "-type",
                "f",
                "-exec",
                "echo",
            ]
        );
        assert!(!arguments.iter().any(|argument| argument == "-print"));
    }

    #[test]
    fn parses_xorriso_exec_echo_listing_for_supported_and_custom_media() {
        let cases = [
            (
                "xorriso : UPDATE : 42 nodes read\n'/casper/vmlinuz'\n'/casper/install-sources.yaml'\n'/EFI/BOOT/BOOTX64.EFI'\n",
                Some(HighGuestOs::Ubuntu),
            ),
            (
                "xorriso : NOTE : File objects found\n'/install.amd/vmlinuz'\n",
                Some(HighGuestOs::Debian),
            ),
            (
                "xorriso : NOTE : File objects found\n'/arch/boot/x86_64/vmlinuz-linux'\n",
                Some(HighGuestOs::ArchLinux),
            ),
            (
                "xorriso : NOTE : File objects found\n'/EFI/BOOT/BOOTX64.EFI'\n'/payload/custom.img'\n",
                None,
            ),
        ];
        for &(listing, expected_os) in &cases {
            let listing = listing.to_ascii_lowercase();
            assert_eq!(
                inspect_iso_text(&listing),
                (expected_os, Some(HighImageArchitecture::X86_64))
            );
        }
        assert!(cases[0].0.contains("/casper/install-sources.yaml"));
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
