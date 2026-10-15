#!/usr/bin/env python3
"""Build a signed, read-only Arch package repository ISO for the approved ArchISO.

The guest never talks to this host or to the Internet.  hf-agent runs this helper on
the host, packages are fetched from the matching Arch Linux Archive snapshot, and
pacman in ArchISO performs the final package signature verification.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote


SNAPSHOT = "2026/09/10"
SNAPSHOT_ID = "2026-09-10"
CACHE_FORMAT_VERSION = 3
ARCH = "x86_64"
SOURCE_ROOT = f"https://archive.archlinux.org/repos/{SNAPSHOT}"
REPOSITORIES = ("core", "extra")
KEYRING_VERSION = "20260909-1"
KEYRING_FILENAME = f"archlinux-keyring-{KEYRING_VERSION}-any.pkg.tar.zst"
# Pinned from the signed official core database for the approved snapshot.
KEYRING_PACKAGE_SHA256 = "6a8ea16f51d3b305c18322d5884ca959f12c32a3f186873090fdc18465605293"
KEYRING_SIGNATURE_SHA256 = "5942acd5b5e27a45051c447b8054696465872e834af1a5bd3cb85e2881cf6cf8"
ROOT_PACKAGES = (
    "base",
    "base-devel",
    "linux",
    "linux-firmware",
    "mkinitcpio",
    "grub",
    "openssh",
    "qemu-guest-agent",
    "audit",
    "python",
    # archinstall 3.0.x selects one of these from the virtual CPU vendor.
    "amd-ucode",
    "intel-ucode",
)
MAX_DATABASE_BYTES = 64 * 1024 * 1024
MAX_PACKAGE_BYTES = 2 * 1024 * 1024 * 1024
MAX_BUNDLE_BYTES = 8 * 1024 * 1024 * 1024
DOWNLOAD_HEADROOM_BYTES = 512 * 1024 * 1024
DOWNLOAD_ATTEMPTS = 3
DOWNLOAD_RETRY_DELAY_SECONDS = 1
SAFE_FILENAME = re.compile(r"^[A-Za-z0-9@._+:-]+$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class RepositoryError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Package:
    repository: str
    name: str
    filename: str
    sha256: str
    compressed_size: int
    depends: tuple[str, ...]
    provides: tuple[str, ...]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def ensure_safe_regular(path: Path) -> None:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise RepositoryError("ARCH_REPO_CACHE_UNSAFE", f"unsafe cache entry: {path}")


def atomic_text(path: Path, content: str) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("x", encoding="utf-8") as output:
        os.chmod(temporary, 0o600)
        output.write(content)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def download(
    url: str,
    destination: Path,
    maximum: int,
    expected_sha256: str | None,
    failure_code: str = "ARCH_REPO_DOWNLOAD_FAILED",
) -> None:
    ensure_safe_regular(destination)
    checksum_path = destination.with_suffix(destination.suffix + ".sha256")
    ensure_safe_regular(checksum_path)
    partial = destination.with_name(f".{destination.name}.part")
    ensure_safe_regular(partial)
    expected = expected_sha256
    if expected is None and checksum_path.is_file():
        candidate = checksum_path.read_text(encoding="ascii").strip().split()[0].lower()
        if SHA256.fullmatch(candidate):
            expected = candidate
    if destination.is_file() and expected and destination.stat().st_size <= maximum:
        if sha256_file(destination) == expected:
            partial.unlink(missing_ok=True)
            return
    if destination.exists():
        destination.unlink()
    partial.unlink(missing_ok=True)

    last_error = "download did not start"
    final_code = failure_code
    for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
        partial.unlink(missing_ok=True)
        command = [
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--connect-timeout",
            "20",
            "--max-time",
            "1800",
            "--speed-limit",
            "1024",
            "--speed-time",
            "60",
            "--max-filesize",
            str(maximum),
            "--output",
            str(partial),
            url,
        ]
        result = subprocess.run(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True
        )
        if result.returncode:
            detail = result.stderr.strip().splitlines()[-1:]
            last_error = (detail or [f"curl exit {result.returncode}"])[0][:400]
            final_code = failure_code
        elif (
            not partial.is_file()
            or partial.stat().st_size == 0
            or partial.stat().st_size > maximum
        ):
            last_error = f"invalid size for {destination.name}"
            final_code = failure_code
        else:
            actual = sha256_file(partial)
            if expected and actual != expected:
                last_error = f"SHA-256 mismatch for {destination.name}"
                final_code = "ARCH_PACKAGE_CHECKSUM_MISMATCH"
            else:
                os.chmod(partial, 0o600)
                os.replace(partial, destination)
                atomic_text(checksum_path, f"{actual}  {destination.name}\n")
                return
        partial.unlink(missing_ok=True)
        if attempt < DOWNLOAD_ATTEMPTS:
            time.sleep(DOWNLOAD_RETRY_DELAY_SECONDS * attempt)

    raise RepositoryError(
        final_code,
        f"{destination.name}: failed after {DOWNLOAD_ATTEMPTS} attempts; last error: {last_error}",
    )


def repository_manifest(databases: dict[str, Path], packages: list[Package]) -> dict[str, object]:
    return {
        "format_version": CACHE_FORMAT_VERSION,
        "snapshot": SNAPSHOT_ID,
        "source": SOURCE_ROOT,
        "architecture": ARCH,
        "database_signatures_required": False,
        "bootstrap_keyring": {
            "version": KEYRING_VERSION,
            "filename": KEYRING_FILENAME,
            "sha256": KEYRING_PACKAGE_SHA256,
            "signature_sha256": KEYRING_SIGNATURE_SHA256,
        },
        "databases": {
            repository: sha256_file(database)
            for repository, database in sorted(databases.items())
        },
        "packages": [
            {
                "repository": item.repository,
                "name": item.name,
                "filename": item.filename,
                "sha256": item.sha256,
            }
            for item in packages
        ],
    }


def fields_from_desc(content: str) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    current: str | None = None
    for line in content.splitlines():
        if line.startswith("%") and line.endswith("%"):
            current = line[1:-1]
            fields.setdefault(current, [])
        elif line and current:
            fields[current].append(line)
    return fields


def parse_database(repository: str, path: Path) -> list[Package]:
    packages: list[Package] = []
    try:
        with tarfile.open(path, "r:*") as database:
            for member in database.getmembers():
                if not member.isfile() or not member.name.endswith("/desc"):
                    continue
                extracted = database.extractfile(member)
                if extracted is None:
                    continue
                fields = fields_from_desc(extracted.read().decode("utf-8", "strict"))
                name = fields.get("NAME", [""])[0]
                filename = fields.get("FILENAME", [""])[0]
                digest = fields.get("SHA256SUM", [""])[0].lower()
                size_text = fields.get("CSIZE", ["0"])[0]
                if (
                    not name
                    or not SAFE_FILENAME.fullmatch(filename)
                    or not SHA256.fullmatch(digest)
                    or not size_text.isdigit()
                ):
                    raise RepositoryError("ARCH_REPO_DATABASE_INVALID", member.name)
                packages.append(
                    Package(
                        repository=repository,
                        name=name,
                        filename=filename,
                        sha256=digest,
                        compressed_size=int(size_text),
                        depends=tuple(fields.get("DEPENDS", ())),
                        provides=tuple(fields.get("PROVIDES", ())),
                    )
                )
    except (tarfile.TarError, UnicodeError, OSError) as failure:
        raise RepositoryError("ARCH_REPO_DATABASE_INVALID", f"{path.name}: {failure}") from failure
    if not packages:
        raise RepositoryError("ARCH_REPO_DATABASE_INVALID", f"{path.name} contains no packages")
    return packages


def dependency_name(value: str) -> str:
    return re.split(r"[<>=]", value, maxsplit=1)[0].strip()


def resolve_packages(
    packages: list[Package], roots: tuple[str, ...] | None = None
) -> list[Package]:
    if roots is None:
        roots = ROOT_PACKAGES
    repository_order = {name: index for index, name in enumerate(REPOSITORIES)}
    by_name: dict[str, list[Package]] = {}
    providers: dict[str, list[Package]] = {}
    for package in packages:
        by_name.setdefault(package.name, []).append(package)
        for provided in (package.name, *package.provides):
            providers.setdefault(dependency_name(provided), []).append(package)
    for candidates in (*by_name.values(), *providers.values()):
        candidates.sort(key=lambda package: (repository_order[package.repository], package.name))

    selected: dict[tuple[str, str], Package] = {}
    pending: deque[Package] = deque()

    def add(package: Package) -> None:
        key = (package.repository, package.name)
        if key not in selected:
            selected[key] = package
            pending.append(package)

    for root in roots:
        candidates = by_name.get(root)
        if not candidates:
            raise RepositoryError("ARCH_REPO_PACKAGE_MISSING", root)
        add(candidates[0])

    while pending:
        package = pending.popleft()
        for dependency in package.depends:
            name = dependency_name(dependency)
            if not name or any(
                name == selected_package.name
                or any(dependency_name(item) == name for item in selected_package.provides)
                for selected_package in selected.values()
            ):
                continue
            candidates = by_name.get(name)
            if candidates:
                add(candidates[0])
                continue
            candidates = providers.get(name)
            if not candidates:
                raise RepositoryError(
                    "ARCH_REPO_DEPENDENCY_UNRESOLVED", f"{package.name} requires {dependency}"
                )
            # Pacman may choose any provider from the unmodified official database. Include
            # every provider so its own deterministic choice is always present on the ISO.
            for candidate in candidates:
                add(candidate)
    return sorted(selected.values(), key=lambda item: (repository_order[item.repository], item.name))


def parse_xorriso_listing(output: str) -> set[str]:
    listing: set[str] = set()
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            fields = shlex.split(line, posix=True)
        except ValueError:
            fields = []
        # xorriso normally emits one shell-quoted ISO path per result line.
        # With -sh_style_result on it emits the same path without quotes. Reject
        # ambiguous result lines rather than accidentally accepting diagnostics.
        if len(fields) == 1 and fields[0].startswith("/") and "\x00" not in fields[0]:
            listing.add(fields[0])
    return listing


def signature_status_error(output: str, revoked_fingerprints: set[str]) -> str | None:
    """Return a safe diagnostic for a detached signature, or None when trusted."""
    statuses: list[tuple[str, list[str]]] = []
    for line in output.splitlines():
        marker = "[GNUPG:] "
        if marker not in line:
            continue
        fields = line.split(marker, 1)[1].split()
        if fields:
            statuses.append((fields[0], fields[1:]))
    names = {name for name, _ in statuses}
    for rejected in (
        "BADSIG",
        "ERRSIG",
        "NO_PUBKEY",
        "EXPKEYSIG",
        "KEYEXPIRED",
        "SIGEXPIRED",
        "REVKEYSIG",
    ):
        if rejected in names:
            return rejected
    valid = [arguments for name, arguments in statuses if name == "VALIDSIG"]
    if len(valid) != 1:
        return "VALIDSIG_MISSING"
    fingerprints = {
        value.upper()
        for value in valid[0]
        if re.fullmatch(r"[0-9A-Fa-f]{40,64}", value)
    }
    if fingerprints & {fingerprint.upper() for fingerprint in revoked_fingerprints}:
        return "REVOKED_FINGERPRINT"
    if not ({"TRUST_FULLY", "TRUST_ULTIMATE"} & names):
        return "SIGNER_NOT_TRUSTED"
    return None


def parse_revoked_fingerprints(content: str) -> set[str]:
    fingerprints: set[str] = set()
    for line in content.splitlines():
        candidate = line.strip().split(":", 1)[0]
        if re.fullmatch(r"[0-9A-Fa-f]{40,64}", candidate):
            fingerprints.add(candidate.upper())
    return fingerprints


def extract_keyring_file(package: Path, member: str, destination: Path) -> None:
    result = subprocess.run(
        ["bsdtar", "-xOf", str(package), member],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode or not result.stdout:
        detail = result.stderr.decode("utf-8", "replace").strip().splitlines()[-1:]
        raise RepositoryError(
            "ARCH_REPO_KEYRING_INVALID",
            f"cannot extract {member}: {(detail or ['bsdtar failed'])[0][:300]}",
        )
    destination.write_bytes(result.stdout)
    os.chmod(destination, 0o600)


def preflight_package_signatures(source_cache: Path, packages: list[Package]) -> None:
    """Verify every package with the pinned current Arch keyring before VM launch."""
    keyring_package = source_cache / KEYRING_FILENAME
    if sha256_file(keyring_package) != KEYRING_PACKAGE_SHA256:
        raise RepositoryError("ARCH_REPO_KEYRING_INVALID", "bootstrap keyring checksum mismatch")
    with tempfile.TemporaryDirectory(prefix=".arch-keyring-", dir=source_cache) as directory:
        root = Path(directory)
        homedir = root / "gnupg"
        homedir.mkdir(mode=0o700)
        public_keys = root / "archlinux.gpg"
        trusted = root / "archlinux-trusted"
        revoked = root / "archlinux-revoked"
        for member, destination in (
            ("usr/share/pacman/keyrings/archlinux.gpg", public_keys),
            ("usr/share/pacman/keyrings/archlinux-trusted", trusted),
            ("usr/share/pacman/keyrings/archlinux-revoked", revoked),
        ):
            extract_keyring_file(keyring_package, member, destination)
        commands = (
            ["gpg", "--batch", "--homedir", str(homedir), "--import", str(public_keys)],
            ["gpg", "--batch", "--homedir", str(homedir), "--import-ownertrust", str(trusted)],
            ["gpg", "--batch", "--homedir", str(homedir), "--check-trustdb"],
        )
        for command in commands:
            result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            if result.returncode:
                raise RepositoryError(
                    "ARCH_REPO_KEYRING_INVALID", "could not initialize isolated verification keyring"
                )
        revoked_fingerprints = parse_revoked_fingerprints(revoked.read_text(encoding="ascii"))
        for package in packages:
            package_path = source_cache / package.filename
            signature_path = source_cache / f"{package.filename}.sig"
            result = subprocess.run(
                [
                    "gpg",
                    "--batch",
                    "--no-auto-key-retrieve",
                    "--auto-key-locate",
                    "clear",
                    "--homedir",
                    str(homedir),
                    "--status-fd",
                    "1",
                    "--verify",
                    str(signature_path),
                    str(package_path),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            diagnostic = signature_status_error(result.stdout, revoked_fingerprints)
            if result.returncode or diagnostic:
                raise RepositoryError(
                    "ARCH_REPO_SIGNATURE_PREFLIGHT_FAILED",
                    f"{package.filename}: {diagnostic or f'gpg-exit-{result.returncode}'}",
                )


def validate_cached_iso(iso_path: Path, checksum_path: Path) -> bool:
    ensure_safe_regular(iso_path)
    ensure_safe_regular(checksum_path)
    if not iso_path.is_file():
        return False
    if checksum_path.is_file():
        expected = checksum_path.read_text(encoding="ascii").strip().split()[0].lower()
        if not SHA256.fullmatch(expected) or sha256_file(iso_path) != expected:
            raise RepositoryError("ARCH_REPO_CACHE_INVALID", "cached repository ISO checksum mismatch")
    result = subprocess.run(
        [
            "xorriso",
            "-report_about",
            "FAILURE",
            "-indev",
            str(iso_path),
            "-sh_style_result",
            "on",
            "-find",
            "/",
            "-type",
            "f",
            "-exec",
            "echo",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    required = {
        "/core/os/x86_64/core.db",
        "/extra/os/x86_64/extra.db",
        "/HF-ARCH-REPO.json",
        f"/core/os/x86_64/{KEYRING_FILENAME}",
        f"/core/os/x86_64/{KEYRING_FILENAME}.sig",
    }
    listing = parse_xorriso_listing(result.stdout)
    missing = sorted(required - listing)
    if result.returncode or missing:
        discovered = sorted(listing)
        sample = ", ".join(discovered[:12]) or "<none>"
        if len(discovered) > 12:
            sample += f", ... ({len(discovered)} files total)"
        stderr = " ".join(result.stderr.strip().splitlines())[-600:] or "<none>"
        raise RepositoryError(
            "ARCH_REPO_CACHE_INVALID",
            "repository ISO structure verification failed: "
            f"xorriso_exit={result.returncode}; "
            f"missing={','.join(missing) or '<none>'}; "
            f"discovered={sample}; xorriso_stderr={stderr}",
        )
    if not checksum_path.exists():
        atomic_text(checksum_path, f"{sha256_file(iso_path)}  {iso_path.name}\n")
    return True


def build_repository(cache_dir: Path) -> Path:
    if cache_dir.is_symlink():
        raise RepositoryError("ARCH_REPO_CACHE_UNSAFE", str(cache_dir))
    cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(cache_dir, 0o700)
    lock_path = cache_dir / f".{SNAPSHOT_ID}.lock"
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        # Each format uses a new filename: previously published repository ISOs remain
        # immutable when the approved snapshot or trust bootstrap changes.
        iso_path = cache_dir / f"archlinux-{SNAPSHOT_ID}-offline-repo-v{CACHE_FORMAT_VERSION}.iso"
        checksum_path = iso_path.with_suffix(iso_path.suffix + ".sha256")
        cached_iso = validate_cached_iso(iso_path, checksum_path)

        source_cache = cache_dir / SNAPSHOT_ID
        source_cache.mkdir(mode=0o700, exist_ok=True)
        os.chmod(source_cache, 0o700)
        databases: dict[str, Path] = {}
        all_packages: list[Package] = []
        for repository in REPOSITORIES:
            database = source_cache / f"{repository}.db"
            download(
                f"{SOURCE_ROOT}/{repository}/os/{ARCH}/{repository}.db",
                database,
                MAX_DATABASE_BYTES,
                None,
            )
            databases[repository] = database
            all_packages.extend(parse_database(repository, database))

        packages = resolve_packages(all_packages)
        keyring = next((package for package in packages if package.name == "archlinux-keyring"), None)
        if (
            keyring is None
            or keyring.filename != KEYRING_FILENAME
            or keyring.sha256 != KEYRING_PACKAGE_SHA256
        ):
            raise RepositoryError(
                "ARCH_REPO_KEYRING_INVALID", "approved keyring is absent from snapshot metadata"
            )
        total_size = sum(package.compressed_size for package in packages)
        if total_size <= 0 or total_size > MAX_BUNDLE_BYTES:
            raise RepositoryError("ARCH_REPO_SIZE_INVALID", str(total_size))
        missing_package_bytes = 0
        for package in packages:
            cached_package = source_cache / package.filename
            ensure_safe_regular(cached_package)
            if not cached_package.is_file() or sha256_file(cached_package) != package.sha256:
                missing_package_bytes += package.compressed_size
        required_free = missing_package_bytes + DOWNLOAD_HEADROOM_BYTES
        if not cached_iso:
            required_free += total_size
        free = shutil.disk_usage(cache_dir).free
        if free < required_free:
            raise RepositoryError(
                "ARCH_REPO_DISK_SPACE_LOW",
                f"need at least {required_free} free bytes, have {free}",
            )

        for package in packages:
            package_path = source_cache / package.filename
            package_url = (
                f"{SOURCE_ROOT}/{package.repository}/os/{ARCH}/{quote(package.filename, safe='@._+:-')}"
            )
            download(package_url, package_path, MAX_PACKAGE_BYTES, package.sha256)
            download(
                package_url + ".sig",
                package_path.with_suffix(package_path.suffix + ".sig"),
                1024 * 1024,
                KEYRING_SIGNATURE_SHA256 if package.name == "archlinux-keyring" else None,
                "ARCH_REPO_PACKAGE_SIGNATURE_MISSING",
            )

        # Always repeat cryptographic preflight, including when the immutable ISO is
        # already cached. Hash-validated source files are reused without downloading.
        preflight_package_signatures(source_cache, packages)
        if cached_iso:
            return iso_path

        staging = Path(tempfile.mkdtemp(prefix=".arch-repo-stage-", dir=cache_dir))
        temporary_iso = cache_dir / f".{iso_path.name}.{os.getpid()}.tmp"
        try:
            for repository, database in databases.items():
                target = staging / repository / "os" / ARCH
                target.mkdir(parents=True)
                os.link(database, target / f"{repository}.db")
            for package in packages:
                target = staging / package.repository / "os" / ARCH
                os.link(source_cache / package.filename, target / package.filename)
                signature = source_cache / f"{package.filename}.sig"
                os.link(signature, target / signature.name)
            manifest = repository_manifest(databases, packages)
            (staging / "HF-ARCH-REPO.json").write_text(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    "xorriso",
                    "-as",
                    "mkisofs",
                    "-quiet",
                    "-r",
                    "-V",
                    "HF_ARCH_REPO",
                    "-o",
                    str(temporary_iso),
                    str(staging),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            if result.returncode:
                raise RepositoryError("ARCH_REPO_ISO_BUILD_FAILED", result.stderr.strip()[-400:])
            os.chmod(temporary_iso, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
            # Validate structure before the immutable image becomes visible to libvirt.
            temporary_checksum = checksum_path.with_name(f".{checksum_path.name}.{os.getpid()}.tmp")
            if not validate_cached_iso(temporary_iso, temporary_checksum):
                raise RepositoryError("ARCH_REPO_ISO_BUILD_FAILED", "repository ISO was not created")
            if iso_path.exists() or checksum_path.exists():
                raise RepositoryError("ARCH_REPO_CACHE_RACE", "repository ISO appeared during publication")
            os.replace(temporary_iso, iso_path)
            os.replace(temporary_checksum, checksum_path)
            directory = os.open(cache_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary_iso.unlink(missing_ok=True)
            shutil.rmtree(staging, ignore_errors=True)
        return iso_path


def main() -> int:
    if len(sys.argv) != 2:
        raise RepositoryError("ARCH_REPO_ARGUMENT_INVALID", "expected cache directory")
    cache_dir = Path(sys.argv[1])
    if not cache_dir.is_absolute():
        raise RepositoryError("ARCH_REPO_ARGUMENT_INVALID", "cache directory must be absolute")
    print(build_repository(cache_dir))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RepositoryError as failure:
        print(
            f"HF_HIGH_ERROR code={failure.code} stage=arch-repository: {failure}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    except (OSError, subprocess.SubprocessError, ValueError) as failure:
        print(
            f"HF_HIGH_ERROR code=ARCH_REPO_PREPARATION_FAILED stage=arch-repository: {failure}",
            file=sys.stderr,
        )
        raise SystemExit(1)
