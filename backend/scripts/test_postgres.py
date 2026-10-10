#!/usr/bin/env python3
"""Run tests against a disposable, loopback-only PostgreSQL container.

Requires Docker Desktop/Engine and Python 3; installs no host software.
Never reuses DATABASE_URL, existing containers, host directories, or volumes.
"""
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time


def main():
    root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["POSTGRES_PASSWORD"] = secrets.token_hex(24)
    image = env.get("HONEYFORGE_TEST_POSTGRES_IMAGE", "postgres:18@sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336")
    container = None
    try:
        container = subprocess.check_output([
            "docker", "run", "--detach", "--rm",
            "--label", "honeyforge.purpose=integration-test",
            "--publish", "127.0.0.1::5432", "--memory", "512m", "--cpus", "1",
            "--tmpfs", "/var/lib/postgresql:rw",
            "--env", "POSTGRES_PASSWORD", "--env", "POSTGRES_USER=honeyforge",
            "--env", "POSTGRES_DB=honeyforge_test", image,
        ], env=env, text=True).strip()
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            probe = subprocess.run([
                "docker", "exec", container, "pg_isready", "-U", "honeyforge", "-d", "honeyforge_test",
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if probe.returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("isolated PostgreSQL did not become ready")
        ports = json.loads(subprocess.check_output([
            "docker", "inspect", "--format", "{{json .NetworkSettings.Ports}}", container,
        ], text=True))
        port = ports["5432/tcp"][0]["HostPort"]
        # No credentials in the command line or test output.
        env["TEST_DATABASE_URL"] = f"postgres://honeyforge:{env['POSTGRES_PASSWORD']}@127.0.0.1:{port}/honeyforge_test"
        subprocess.run([
            "cargo", "test", "--locked", "--offline", "--test", "postgres", "--", "--ignored", "--nocapture",
        ], cwd=root, env=env, check=True)
    finally:
        if container:
            subprocess.run(["docker", "rm", "--force", container], check=True, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    try:
        main()
    except (subprocess.CalledProcessError, RuntimeError) as error:
        # Commands never contain generated passwords.
        print(f"PostgreSQL test runner failed: {error}", file=sys.stderr)
        sys.exit(1)
