import json
import os
import pathlib
import pwd
import shutil
import stat
import subprocess
import sys


def run(*args, input_text=None, timeout_seconds=20):
    command = " ".join(args)
    try:
        result = subprocess.run(
            args,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(
            f"guest command timed out after {timeout_seconds} seconds: {command}"
        ) from error
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        suffix = f": {detail}" if detail else ""
        raise RuntimeError(f"guest command failed with exit {result.returncode}: {command}{suffix}")


config = json.load(sys.stdin)
cloud_init = shutil.which("cloud-init")
if cloud_init and not pathlib.Path("/etc/cloud/cloud-init.disabled").exists():
    try:
        run(cloud_init, "status", "--wait", timeout_seconds=60)
    except RuntimeError as error:
        try:
            status = subprocess.run(
                (cloud_init, "status"),
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
            diagnostic = (status.stderr or status.stdout).strip()
        except (OSError, subprocess.TimeoutExpired) as diagnostic_error:
            diagnostic = f"could not read cloud-init status: {diagnostic_error}"
        if "timed out" in str(error) and "status: running" in diagnostic:
            # Arch cloud-init can wait for network time synchronization even while QGA
            # and the guest are healthy. Apply the SSH settings without blocking on it.
            pass
        elif diagnostic:
            raise RuntimeError(f"{error}; current cloud-init status: {diagnostic}") from error
        else:
            raise

hostname = config.get("hostname")
username = config.get("username")
shell = config.get("shell")
password_hash = config.get("password_hash")
ssh_host_key = config.get("ssh_host_key")
vulnerabilities = set(config.get("vulnerabilities", []))

if hostname:
    run("hostnamectl", "set-hostname", hostname)

if username:
    selected_shell = shell or "/bin/bash"
    if not os.path.isfile(selected_shell) or not os.access(selected_shell, os.X_OK):
        raise ValueError(f"requested shell is unavailable: {selected_shell}")
    try:
        pwd.getpwnam(username)
    except KeyError:
        run("useradd", "--create-home", "--shell", selected_shell, username)
    else:
        run("usermod", "--shell", selected_shell, username)
    if password_hash:
        run("chpasswd", "--encrypted", input_text=f"{username}:{password_hash}\n")

if "ssh_root_login_enabled" in vulnerabilities:
    if not password_hash:
        raise ValueError("root login needs a password hash")
    run("chpasswd", "--encrypted", input_text=f"root:{password_hash}\n")

if "sudo_nopasswd" in vulnerabilities:
    if not username:
        raise ValueError("sudo_nopasswd needs a guest username")
    sudoers = pathlib.Path("/etc/sudoers.d/90-honeyforge-local")
    sudoers.write_text(f"{username} ALL=(ALL) NOPASSWD:ALL\n", encoding="utf-8")
    sudoers.chmod(0o440)
    run("visudo", "-cf", str(sudoers))

if ssh_host_key:
    if not isinstance(ssh_host_key, str) or len(ssh_host_key) > 16384 or "\x00" in ssh_host_key:
        raise ValueError("invalid shared SSH host key")
    key_path = pathlib.Path("/etc/ssh/ssh_host_ed25519_key")
    key_fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(key_fd, 0o600)
        with os.fdopen(key_fd, "w", encoding="utf-8") as key_file:
            key_fd = -1
            key_file.write(ssh_host_key)
            if not ssh_host_key.endswith("\n"):
                key_file.write("\n")
            key_file.flush()
            os.fsync(key_file.fileno())
    finally:
        if key_fd >= 0:
            os.close(key_fd)
    public_key = subprocess.run(
        ("ssh-keygen", "-y", "-f", str(key_path)),
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
    )
    if public_key.returncode:
        raise RuntimeError(f"could not derive shared SSH public key: {public_key.stderr.strip()}")
    public_path = pathlib.Path("/etc/ssh/ssh_host_ed25519_key.pub")
    public_path.write_text(public_key.stdout, encoding="utf-8")
    public_path.chmod(0o644)

ssh_config = pathlib.Path("/etc/ssh/sshd_config.d/90-honeyforge-local.conf")
ssh_config.parent.mkdir(parents=True, exist_ok=True)
ssh_config.write_text(
    "PasswordAuthentication yes\n"
    + ("PermitRootLogin yes\n" if "ssh_root_login_enabled" in vulnerabilities else "PermitRootLogin no\n"),
    encoding="utf-8",
)
ssh_config.chmod(0o644)

def create_bait_file(raw_path, content):
    if not isinstance(raw_path, str) or not isinstance(content, str):
        raise ValueError("bait path and content must be text")
    if len(raw_path) > 256 or not raw_path.startswith("/") or "\x00" in raw_path:
        raise ValueError("invalid guest bait path")
    parts = raw_path.split("/")[1:]
    if not parts or any(not part or part in (".", "..") or len(part) > 255 for part in parts):
        raise ValueError("invalid guest bait path")
    if len(content.encode("utf-8")) > 4096 or "\x00" in content:
        raise ValueError("bait content must be text of at most 4096 bytes")

    allowed = (
        (parts[0] in ("srv", "opt") and len(parts) >= 2)
        or (parts[:2] == ["var", "backups"] and len(parts) >= 3)
        or (username and parts[:2] == ["home", username] and len(parts) >= 3)
    )
    if not allowed:
        raise ValueError("guest bait path must be under /srv, /opt, /var/backups, or the selected user's home")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_fd = os.open("/", directory_flags)
    try:
        for component in parts[:-1]:
            try:
                next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(component, 0o755, dir_fd=directory_fd)
                except FileExistsError:
                    pass
                next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd

        filename = parts[-1]
        try:
            file_fd = os.open(
                filename,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o644,
                dir_fd=directory_fd,
            )
        except FileExistsError as error:
            # Retries are safe only when the exact bait was already created by us.
            existing_fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
            try:
                metadata = os.fstat(existing_fd)
                existing = os.read(existing_fd, 4097)
            finally:
                os.close(existing_fd)
            if not stat.S_ISREG(metadata.st_mode) or existing != content.encode("utf-8"):
                raise ValueError(f"refusing to overwrite existing guest bait path: {raw_path}") from error
            return

        open_file_fd = file_fd
        try:
            os.fchmod(file_fd, 0o644)
            if username and parts[:2] == ["home", username]:
                account = pwd.getpwnam(username)
                os.fchown(file_fd, account.pw_uid, account.pw_gid)
            output_file = os.fdopen(file_fd, "wb")
            open_file_fd = None
            with output_file as output:
                output.write(content.encode("utf-8"))
                output.flush()
                os.fsync(output.fileno())
            os.fsync(directory_fd)
        except BaseException:
            if open_file_fd is not None:
                os.close(open_file_fd)
            try:
                os.unlink(filename, dir_fd=directory_fd)
            except OSError:
                pass
            raise
    finally:
        os.close(directory_fd)


seen_baits = set()
for bait in config.get("baits", []):
    path = bait["path"]
    if not isinstance(path, str):
        raise ValueError("bait path must be text")
    if path in seen_baits:
        raise ValueError(f"duplicate guest bait path: {path}")
    seen_baits.add(path)
    create_bait_file(path, bait["content"])

if username or password_hash or vulnerabilities or ssh_host_key:
    if pathlib.Path("/usr/sbin/sshd").exists():
        run("/usr/sbin/sshd", "-t")
    for service in ("ssh", "sshd"):
        result = subprocess.run(
            ("systemctl", "--no-block", "restart", service),
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if result.returncode == 0:
            break
    else:
        raise RuntimeError("could not restart SSH service")
