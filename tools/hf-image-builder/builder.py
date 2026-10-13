#!/usr/bin/env python3
"""Build and atomically publish a generalized Windows High base image."""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import fcntl
import hashlib
import json
import logging
import os
import pathlib
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET
from typing import Optional


MIB = 1024 * 1024
GIB = 1024 * MIB
MIN_AVAILABLE_MEMORY = 5 * GIB
MIN_FREE_DISK = 55 * GIB
EXPECTED_BUILD = "20348"
ALLOWED_EDITIONS = {"ServerStandardEval", "ServerDatacenterEval"}
OUTPUT_NAME = "windows-server-prepared.qcow2"
REQUIRED_TOOLS = (
    "curl",
    "packer",
    "qemu-img",
    "qemu-system-x86_64",
    "virt-inspector",
    "virt-cat",
    "virt-ls",
    "wimlib-imagex",
    "xorriso",
)
DEFAULT_WINDOWS_HOSTS = (
    "download.microsoft.com",
    "go.microsoft.com",
    "software-download.microsoft.com",
    "software-static.download.prss.microsoft.com",
)


class BuildError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class ArtifactSource:
    name: str
    url: str
    sha256: str
    allowed_hosts: tuple[str, ...]
    cache_name: str

    def validate(self) -> None:
        parsed = urllib.parse.urlsplit(self.url)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            raise BuildError(f"{self.name}: source must be an HTTPS URL")
        if parsed.username or parsed.password or parsed.fragment:
            raise BuildError(f"{self.name}: credentials and fragments are forbidden in source URL")
        host = parsed.hostname.lower().rstrip(".")
        allowed = {item.lower().rstrip(".") for item in self.allowed_hosts if item}
        if host not in allowed:
            raise BuildError(f"{self.name}: HTTPS host {host!r} is not in its approved host list")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", self.sha256):
            raise BuildError(f"{self.name}: trusted SHA-256 must contain exactly 64 hex characters")
        if pathlib.PurePath(self.cache_name).name != self.cache_name:
            raise BuildError(f"{self.name}: unsafe cache name")


@dataclasses.dataclass(frozen=True)
class Config:
    windows_iso: ArtifactSource
    virtio_iso: ArtifactSource
    cloudbase_msi: ArtifactSource
    image_index: int
    image_name: str
    edition_id: str
    cache_dir: pathlib.Path
    image_dir: pathlib.Path
    work_dir: pathlib.Path
    log_dir: pathlib.Path
    cleanup_sources: bool

    @property
    def output_path(self) -> pathlib.Path:
        return self.image_dir / OUTPUT_NAME

    @classmethod
    def from_env(cls, env: Optional[dict[str, str]] = None) -> "Config":
        values = dict(os.environ if env is None else env)

        def required(name: str) -> str:
            value = values.get(name, "").strip()
            if not value:
                raise BuildError(f"required environment variable is missing: {name}")
            return value

        if values.get("HF_WINDOWS_EVALUATION_LICENSE_ACCEPTED", "").strip().lower() not in {
            "1",
            "yes",
            "true",
        }:
            raise BuildError(
                "set HF_WINDOWS_EVALUATION_LICENSE_ACCEPTED=yes after reviewing the Microsoft "
                "Evaluation license"
            )
        try:
            image_index = int(required("HF_WINDOWS_IMAGE_INDEX"))
        except ValueError as exc:
            raise BuildError("HF_WINDOWS_IMAGE_INDEX must be a positive integer") from exc
        if image_index <= 0:
            raise BuildError("HF_WINDOWS_IMAGE_INDEX must be a positive integer")
        edition_id = required("HF_WINDOWS_IMAGE_EDITION_ID")
        if edition_id not in ALLOWED_EDITIONS:
            raise BuildError(
                "HF_WINDOWS_IMAGE_EDITION_ID must be ServerStandardEval or ServerDatacenterEval"
            )

        def hosts(name: str, default: tuple[str, ...] = ()) -> tuple[str, ...]:
            raw = values.get(name, "")
            result = tuple(part.strip() for part in raw.split(",") if part.strip()) or default
            if not result:
                raise BuildError(f"required approved host list is missing: {name}")
            return result

        iso_sha = required("HF_WINDOWS_ISO_SHA256").lower()
        virtio_sha = required("HF_VIRTIO_ISO_SHA256").lower()
        cloudbase_sha = required("HF_CLOUDBASE_MSI_SHA256").lower()
        config = cls(
            windows_iso=ArtifactSource(
                "Windows Server ISO",
                required("HF_WINDOWS_ISO_URL"),
                iso_sha,
                hosts("HF_WINDOWS_ISO_ALLOWED_HOSTS", DEFAULT_WINDOWS_HOSTS),
                f"windows-server-2022-{iso_sha[:12]}.iso",
            ),
            virtio_iso=ArtifactSource(
                "VirtIO driver ISO",
                required("HF_VIRTIO_ISO_URL"),
                virtio_sha,
                hosts("HF_VIRTIO_ISO_ALLOWED_HOSTS"),
                f"virtio-win-{virtio_sha[:12]}.iso",
            ),
            cloudbase_msi=ArtifactSource(
                "Cloudbase-Init MSI",
                required("HF_CLOUDBASE_MSI_URL"),
                cloudbase_sha,
                hosts("HF_CLOUDBASE_MSI_ALLOWED_HOSTS"),
                f"cloudbase-init-{cloudbase_sha[:12]}.msi",
            ),
            image_index=image_index,
            image_name=required("HF_WINDOWS_IMAGE_NAME"),
            edition_id=edition_id,
            cache_dir=pathlib.Path(
                values.get("HF_IMAGE_BUILDER_CACHE_DIR", "/var/cache/honeyforge/hf-image-builder")
            ),
            image_dir=pathlib.Path(
                values.get("HF_IMAGE_BUILDER_IMAGE_DIR", "/var/lib/honeyforge/images")
            ),
            work_dir=pathlib.Path(
                values.get("HF_IMAGE_BUILDER_WORK_DIR", "/var/lib/honeyforge/image-builder")
            ),
            log_dir=pathlib.Path(
                values.get("HF_IMAGE_BUILDER_LOG_DIR", "/var/log/honeyforge")
            ),
            cleanup_sources=values.get("HF_IMAGE_BUILDER_CLEANUP_SOURCES", "").lower()
            in {"1", "yes", "true"},
        )
        for source in (config.windows_iso, config.virtio_iso, config.cloudbase_msi):
            source.validate()
        for directory in (config.cache_dir, config.image_dir, config.work_dir, config.log_dir):
            if not directory.is_absolute():
                raise BuildError(f"builder directory must be absolute: {directory}")
        return config


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * MIB), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_regular_file(path: pathlib.Path, description: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise BuildError(f"{description} is missing: {path}") from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise BuildError(f"{description} is not a safe regular file: {path}")


def verify_checksum(path: pathlib.Path, expected: str, description: str) -> None:
    require_regular_file(path, description)
    actual = sha256_file(path)
    if actual != expected.lower():
        raise BuildError(f"{description} SHA-256 mismatch: {path}")


def run(
    command: list[str],
    *,
    description: str,
    env: Optional[dict[str, str]] = None,
    capture: bool = False,
    check: bool = True,
    cwd: Optional[pathlib.Path] = None,
) -> subprocess.CompletedProcess[str]:
    logging.info("stage: %s", description)
    try:
        result = subprocess.run(
            command,
            env=env,
            cwd=str(cwd) if cwd is not None else None,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            check=False,
        )
    except OSError as exc:
        raise BuildError(f"{description} could not start: {exc}") from exc
    if check and result.returncode != 0:
        detail = (result.stderr or "").strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        raise BuildError(f"{description} failed (exit {result.returncode}){suffix}")
    return result


def available_memory_bytes(meminfo: pathlib.Path = pathlib.Path("/proc/meminfo")) -> int:
    for line in meminfo.read_text(encoding="ascii").splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) * 1024
    raise BuildError("cannot determine MemAvailable from /proc/meminfo")


def validate_resource_limits(available_memory: int, free_disk: int) -> None:
    if available_memory < MIN_AVAILABLE_MEMORY:
        raise BuildError(
            f"insufficient available RAM: {available_memory // MIB} MiB; at least "
            f"{MIN_AVAILABLE_MEMORY // MIB} MiB is required"
        )
    if free_disk < MIN_FREE_DISK:
        raise BuildError(
            f"insufficient free disk space: {free_disk // GIB} GiB; at least "
            f"{MIN_FREE_DISK // GIB} GiB is required"
        )


def preflight(config: Config) -> None:
    if sys.platform != "linux":
        raise BuildError("hf-image-builder must run on Linux with KVM")
    missing = [tool for tool in REQUIRED_TOOLS if shutil.which(tool) is None]
    if missing:
        raise BuildError("missing required commands: " + ", ".join(missing))
    kvm = pathlib.Path("/dev/kvm")
    if not kvm.exists() or not os.access(kvm, os.R_OK | os.W_OK):
        raise BuildError("/dev/kvm is unavailable or not readable/writable")
    config.work_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    validate_resource_limits(available_memory_bytes(), shutil.disk_usage(config.work_dir).free)
    output = config.output_path
    manifest = output.with_suffix(output.suffix + ".sha256")
    if output.exists() or manifest.exists():
        raise BuildError(
            f"published image or readiness manifest already exists; refusing overwrite: {output}"
        )


def download_to_cache(source: ArtifactSource, cache_dir: pathlib.Path) -> pathlib.Path:
    source.validate()
    cache_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
    target = cache_dir / source.cache_name
    if target.exists() or target.is_symlink():
        verify_checksum(target, source.sha256, f"cached {source.name}")
        logging.info("cache hit verified: %s", source.name)
        return target
    fd, tmp_name = tempfile.mkstemp(prefix=f".{source.cache_name}.", dir=cache_dir)
    os.close(fd)
    temporary = pathlib.Path(tmp_name)
    try:
        os.chmod(temporary, 0o600)
        logging.info("downloading %s from approved HTTPS host %s", source.name, urllib.parse.urlsplit(source.url).hostname)
        run(
            [
                "curl",
                "--fail",
                "--location",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--tlsv1.2",
                "--retry",
                "3",
                "--silent",
                "--show-error",
                "--output",
                str(temporary),
                source.url,
            ],
            description=f"download {source.name}",
        )
        verify_checksum(temporary, source.sha256, source.name)
        try:
            os.link(temporary, target)
        except FileExistsError:
            verify_checksum(target, source.sha256, f"concurrent cached {source.name}")
        with target.open("rb") as stream:
            os.fsync(stream.fileno())
        _fsync_dir(cache_dir)
        return target
    finally:
        temporary.unlink(missing_ok=True)


def extract_iso_path(iso: pathlib.Path, iso_path: str, target: pathlib.Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    result = run(
        ["xorriso", "-osirrox", "on", "-indev", str(iso), "-extract", iso_path, str(target)],
        description=f"extract {iso_path}",
        capture=True,
        check=False,
    )
    if result.returncode != 0:
        raise BuildError(f"required ISO path is missing: {iso_path}")


def extract_install_wim(iso: pathlib.Path, destination: pathlib.Path) -> None:
    for candidate in ("/sources/install.wim", "/SOURCES/INSTALL.WIM"):
        result = run(
            ["xorriso", "-osirrox", "on", "-indev", str(iso), "-extract", candidate, str(destination)],
            description="extract Windows install.wim",
            capture=True,
            check=False,
        )
        if result.returncode == 0:
            return
    raise BuildError("approved Windows ISO has no sources/install.wim; ESD media is unsupported")


def _xml_text(element: ET.Element, name: str) -> str:
    child = element.find(name)
    return "" if child is None or child.text is None else child.text.strip()


def validate_wim_metadata(xml_path: pathlib.Path, config: Config) -> None:
    try:
        root = ET.parse(xml_path).getroot()
    except (ET.ParseError, OSError) as exc:
        raise BuildError("cannot parse install.wim metadata") from exc
    image = next(
        (item for item in root.findall("IMAGE") if item.get("INDEX") == str(config.image_index)),
        None,
    )
    if image is None:
        raise BuildError(f"install.wim does not contain requested index {config.image_index}")
    windows = image.find("WINDOWS")
    if windows is None:
        raise BuildError("selected install.wim image has no WINDOWS metadata")
    version = windows.find("VERSION")
    checks = {
        "name": (_xml_text(image, "NAME"), config.image_name),
        "edition": (_xml_text(windows, "EDITIONID"), config.edition_id),
        "product type": (_xml_text(windows, "PRODUCTTYPE"), "ServerNT"),
        "installation type": (_xml_text(windows, "INSTALLATIONTYPE"), "Server"),
        "build": (_xml_text(version if version is not None else ET.Element("VERSION"), "BUILD"), EXPECTED_BUILD),
    }
    for label, (actual, expected) in checks.items():
        if actual != expected:
            raise BuildError(
                f"selected install.wim {label} mismatch: expected {expected!r}, got {actual!r}"
            )
    architecture = _xml_text(windows, "ARCH").lower()
    if architecture not in {"9", "amd64", "x86_64"}:
        raise BuildError(f"selected install.wim architecture is not x64: {architecture!r}")


def inspect_windows_iso(iso: pathlib.Path, config: Config, work: pathlib.Path) -> None:
    wim = work / "install.wim"
    metadata = work / "install-wim.xml"
    extract_install_wim(iso, wim)
    run(
        ["wimlib-imagex", "info", str(wim), f"--extract-xml={metadata}"],
        description="read install.wim metadata",
    )
    validate_wim_metadata(metadata, config)
    wim.unlink(missing_ok=True)


def prepare_payload(
    config: Config,
    virtio_iso: pathlib.Path,
    cloudbase_msi: pathlib.Path,
    payload: pathlib.Path,
    password: str,
) -> None:
    payload.mkdir(mode=0o700)
    paths = {
        "/viostor/2k22/amd64": payload / "drivers" / "viostor",
        "/NetKVM/2k22/amd64": payload / "drivers" / "netkvm",
        "/vioserial/2k22/amd64": payload / "drivers" / "vioserial",
        "/Balloon/2k22/amd64": payload / "drivers" / "balloon",
        "/guest-agent/qemu-ga-x86_64.msi": payload / "qemu-ga-x86_64.msi",
        "/virtio-win-gt-x64.msi": payload / "virtio-win-gt-x64.msi",
    }
    for source, destination in paths.items():
        extract_iso_path(virtio_iso, source, destination)
    winpe = payload / "winpe"
    winpe.mkdir()
    for suffix in (".inf", ".sys", ".cat"):
        matches = list((payload / "drivers" / "viostor").glob(f"*{suffix}"))
        if not matches:
            raise BuildError(f"VirtIO ISO lacks the viostor {suffix} file required by Windows Setup")
        for item in matches:
            shutil.copy2(item, winpe / item.name)
    shutil.copy2(cloudbase_msi, payload / "CloudbaseInitSetup.msi")
    root = pathlib.Path(__file__).resolve().parent
    for name in ("bootstrap.ps1", "configure.ps1", "verify.ps1"):
        shutil.copy2(root / "windows" / name, payload / name)
    render_autounattend(root / "templates" / "Autounattend.xml", payload / "Autounattend.xml", config.image_index, password)
    render_finalizer(root / "windows" / "finalize.ps1", payload / "finalize.ps1")
    floppy_size = sum(item.stat().st_size for item in winpe.iterdir()) + (payload / "Autounattend.xml").stat().st_size
    if floppy_size > 1_400_000:
        raise BuildError("viostor WinPE driver and Autounattend do not fit on the Packer floppy")


def render_autounattend(
    template: pathlib.Path,
    output: pathlib.Path,
    image_index: int,
    password: str,
) -> None:
    text = template.read_text(encoding="utf-8")
    replacements = {"@@IMAGE_INDEX@@": str(image_index), "@@BUILD_PASSWORD@@": password}
    for marker, value in replacements.items():
        text = text.replace(marker, value)
    if "@@" in text:
        raise BuildError("Autounattend.xml contains unresolved template markers")
    ET.fromstring(text)
    output.write_text(text, encoding="utf-8")
    os.chmod(output, 0o600)


def render_finalizer(template: pathlib.Path, output: pathlib.Path) -> None:
    text = template.read_text(encoding="utf-8")
    if "@@" in text:
        raise BuildError("finalize.ps1 contains unresolved template markers")
    output.write_text(text, encoding="utf-8")
    os.chmod(output, 0o600)


def run_packer(config: Config, iso: pathlib.Path, payload: pathlib.Path, output: pathlib.Path, password: str) -> pathlib.Path:
    template = pathlib.Path(__file__).resolve().parent / "windows-server-2022.pkr.hcl"
    packer_workspace = output.parent / "packer"
    packer_workspace.mkdir(mode=0o700)
    shutil.copy2(template, packer_workspace / template.name)
    env = os.environ.copy()
    env.update(
        {
            "CHECKPOINT_DISABLE": "1",
            "PACKER_LOG": "0",
            "PKR_VAR_windows_iso_path": str(iso),
            "PKR_VAR_windows_iso_sha256": config.windows_iso.sha256,
            "PKR_VAR_payload_directory": str(payload),
            "PKR_VAR_output_directory": str(output),
            "PKR_VAR_build_password": password,
        }
    )
    run(["packer", "init", "."], description="initialize pinned Packer QEMU plugin", env=env, cwd=packer_workspace)
    run(["packer", "validate", "."], description="validate Packer template", env=env, cwd=packer_workspace)
    run(["packer", "build", "-color=false", "."], description="build Windows Server image", env=env, cwd=packer_workspace)
    result = output / OUTPUT_NAME
    require_regular_file(result, "Packer output")
    return result


def qemu_info(path: pathlib.Path) -> dict[str, object]:
    result = run(
        ["qemu-img", "info", "--output=json", str(path)],
        description="inspect QCOW2",
        capture=True,
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise BuildError("qemu-img returned invalid JSON") from exc


def verify_output(path: pathlib.Path, *, guest_tools: bool = True) -> None:
    require_regular_file(path, "prepared image")
    info = qemu_info(path)
    if info.get("format") != "qcow2":
        raise BuildError("prepared image format is not QCOW2")
    if info.get("backing-filename") or info.get("full-backing-filename"):
        raise BuildError("prepared base image unexpectedly has a backing file")
    try:
        virtual_size = int(info.get("virtual-size", 0))
    except (TypeError, ValueError) as exc:
        raise BuildError("qemu-img did not report a valid virtual size") from exc
    if virtual_size < 40 * GIB:
        raise BuildError("prepared image virtual size is unexpectedly small")
    run(["qemu-img", "check", "-q", str(path)], description="check QCOW2 integrity")
    if not guest_tools:
        return
    inspection = run(
        ["virt-inspector", "--no-applications", "-a", str(path)],
        description="inspect Windows guest",
        capture=True,
    ).stdout.lower()
    if "windows server 2022" not in inspection or "x86_64" not in inspection:
        raise BuildError("offline inspection does not identify Windows Server 2022 x64")
    program_files = run(
        ["virt-ls", "--ro", "-a", str(path), "/Program Files"],
        description="verify installed guest agents",
        capture=True,
    ).stdout.lower()
    if "cloudbase solutions" not in program_files or not any(
        name in program_files for name in ("qemu-ga", "qemu guest agent")
    ):
        raise BuildError("Cloudbase-Init or QEMU Guest Agent is missing from prepared image")
    cloudbase_config = run(
        [
            "virt-cat",
            "--ro",
            "-a",
            str(path),
            "/Program Files/Cloudbase Solutions/Cloudbase-Init/conf/cloudbase-init.conf",
        ],
        description="verify Cloudbase-Init ConfigDrive configuration",
        capture=True,
    ).stdout.lower()
    if "configdriveservice" not in cloudbase_config or "inject_user_password=true" not in cloudbase_config:
        raise BuildError("prepared image Cloudbase-Init configuration is incompatible")
    drivers = run(
        ["virt-ls", "--ro", "-a", str(path), "/Windows/System32/DriverStore/FileRepository"],
        description="verify staged VirtIO drivers",
        capture=True,
    ).stdout.lower()
    for required in ("viostor", "netkvm", "vioser"):
        if required not in drivers:
            raise BuildError(f"required VirtIO driver is not staged: {required}")


def _fsync_dir(path: pathlib.Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_no_replace(source: pathlib.Path, destination: pathlib.Path) -> str:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    manifest = destination.with_suffix(destination.suffix + ".sha256")
    if destination.exists() or manifest.exists():
        raise BuildError(f"refusing to replace published image or manifest: {destination}")
    fd, image_tmp_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    os.close(fd)
    image_tmp = pathlib.Path(image_tmp_name)
    manifest_tmp: Optional[pathlib.Path] = None
    linked_image = False
    try:
        image_tmp.unlink()
        run(
            [
                "qemu-img",
                "convert",
                "-O",
                "qcow2",
                "-o",
                "compat=1.1,lazy_refcounts=on,cluster_size=2M",
                str(source),
                str(image_tmp),
            ],
            description="normalize prepared QCOW2",
        )
        os.chmod(image_tmp, 0o640)
        verify_output(image_tmp)
        checksum = sha256_file(image_tmp)
        with image_tmp.open("rb") as stream:
            os.fsync(stream.fileno())
        try:
            os.link(image_tmp, destination)
        except FileExistsError as exc:
            raise BuildError(f"published image appeared concurrently: {destination}") from exc
        linked_image = True
        _fsync_dir(destination.parent)

        fd, manifest_tmp_name = tempfile.mkstemp(prefix=f".{manifest.name}.", dir=destination.parent)
        manifest_tmp = pathlib.Path(manifest_tmp_name)
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(f"{checksum}  {destination.name}\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(manifest_tmp, 0o640)
        try:
            os.link(manifest_tmp, manifest)
        except FileExistsError as exc:
            raise BuildError(f"checksum manifest appeared concurrently: {manifest}") from exc
        _fsync_dir(destination.parent)
        logging.info("published immutable prepared image: %s", destination)
        return checksum
    except Exception:
        if linked_image and not manifest.exists():
            destination.unlink(missing_ok=True)
            _fsync_dir(destination.parent)
        raise
    finally:
        image_tmp.unlink(missing_ok=True)
        if manifest_tmp is not None:
            manifest_tmp.unlink(missing_ok=True)


def cleanup_cached_sources(config: Config) -> None:
    for source in (config.windows_iso, config.virtio_iso, config.cloudbase_msi):
        path = config.cache_dir / source.cache_name
        if path.exists() or path.is_symlink():
            require_regular_file(path, f"cached {source.name}")
            path.unlink()
            logging.info("removed cached source: %s", source.name)


@contextlib.contextmanager
def build_lock(path: pathlib.Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="ascii") as stream:
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise BuildError("another hf-image-builder process is already running") from exc
        yield


def configure_logging(config: Config) -> pathlib.Path:
    config.log_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
    log_path = config.log_dir / "hf-image-builder.log"
    handler = logging.FileHandler(log_path, encoding="utf-8")
    os.chmod(log_path, 0o600)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[handler, logging.StreamHandler(sys.stderr)],
    )
    return log_path


def build(config: Config) -> str:
    preflight(config)
    config.cache_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
    lock_path = config.work_dir / "hf-image-builder.lock"
    with build_lock(lock_path):
        windows_iso = download_to_cache(config.windows_iso, config.cache_dir)
        virtio_iso = download_to_cache(config.virtio_iso, config.cache_dir)
        cloudbase_msi = download_to_cache(config.cloudbase_msi, config.cache_dir)
        with tempfile.TemporaryDirectory(prefix="build-", dir=config.work_dir) as temporary:
            work = pathlib.Path(temporary)
            os.chmod(work, 0o700)
            inspect_windows_iso(windows_iso, config, work)
            password = "Hf!" + secrets.token_hex(20) + "9a"
            payload = work / "payload"
            prepare_payload(config, virtio_iso, cloudbase_msi, payload, password)
            packer_output = work / "packer-output"
            image = run_packer(config, windows_iso, payload, packer_output, password)
            checksum = publish_no_replace(image, config.output_path)
        if config.cleanup_sources:
            cleanup_cached_sources(config)
        return checksum


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build_parser = subparsers.add_parser("build", help="build and atomically publish the image")
    build_parser.add_argument(
        "--cleanup-sources",
        action="store_true",
        help="delete verified cached ISO/MSI inputs after successful publication",
    )
    verify_parser = subparsers.add_parser("verify", help="verify an already published image")
    verify_parser.add_argument(
        "--image", default=f"/var/lib/honeyforge/images/{OUTPUT_NAME}", type=pathlib.Path
    )
    subparsers.add_parser("cleanup-sources", help="delete only configured cached source artifacts")
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == "verify":
            verify_output(args.image)
            manifest = args.image.with_suffix(args.image.suffix + ".sha256")
            require_regular_file(manifest, "checksum manifest")
            fields = manifest.read_text(encoding="ascii").split()
            if not fields:
                raise BuildError("checksum manifest is empty")
            first = fields[0].lower()
            if not re.fullmatch(r"[0-9a-f]{64}", first):
                raise BuildError("checksum manifest is invalid")
            verify_checksum(args.image, first, "published image")
            print(f"verified: {args.image}")
            return 0
        config = Config.from_env()
        configure_logging(config)
        if args.command == "cleanup-sources":
            cleanup_cached_sources(config)
            return 0
        if args.cleanup_sources:
            config = dataclasses.replace(config, cleanup_sources=True)
        checksum = build(config)
        print(f"published: {config.output_path}")
        print(f"sha256: {checksum}")
        return 0
    except (BuildError, OSError) as exc:
        if logging.getLogger().handlers:
            logging.error("%s", exc)
        print(f"hf-image-builder: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
