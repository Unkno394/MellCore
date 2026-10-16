import json
import os
import pathlib
import pwd
import shutil
import subprocess
import sys


def run(*args, input_text=None):
    command = " ".join(args)
    try:
        result = subprocess.run(
            args,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"guest command timed out after 20 seconds: {command}") from error
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        suffix = f": {detail}" if detail else ""
        raise RuntimeError(f"guest command failed with exit {result.returncode}: {command}{suffix}")


config = json.load(sys.stdin)
cloud_init = shutil.which("cloud-init")
if cloud_init:
    run(cloud_init, "status", "--wait")

hostname = config.get("hostname")
username = config.get("username")
shell = config.get("shell")
password_hash = config.get("password_hash")
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

ssh_config = pathlib.Path("/etc/ssh/sshd_config.d/90-honeyforge-local.conf")
ssh_config.parent.mkdir(parents=True, exist_ok=True)
ssh_config.write_text(
    "PasswordAuthentication yes\n"
    + ("PermitRootLogin yes\n" if "ssh_root_login_enabled" in vulnerabilities else "PermitRootLogin no\n"),
    encoding="utf-8",
)
ssh_config.chmod(0o644)

for bait in config.get("baits", []):
    path = pathlib.Path(bait["path"])
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("invalid guest bait path")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(bait["content"], encoding="utf-8")
    path.chmod(0o644)
    if username and str(path).startswith(f"/home/{username}/"):
        account = pwd.getpwnam(username)
        os.chown(path, account.pw_uid, account.pw_gid)

if username or password_hash or vulnerabilities:
    if pathlib.Path("/usr/sbin/sshd").exists():
        run("/usr/sbin/sshd", "-t")
    for service in ("ssh", "sshd"):
        result = subprocess.run(("systemctl", "restart", service), check=False)
        if result.returncode == 0:
            break
    else:
        raise RuntimeError("could not restart SSH service")
