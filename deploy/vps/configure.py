#!/usr/bin/env python3
"""Create persistent deployment configuration without printing secrets."""
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import uuid

DOMAIN = "yourpasswordforemail.ru"
CONFIG = Path("/etc/honeyforge")
STATE = Path("/var/lib/honeyforge/mellcore-local-agent")


def write(path, content, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content)
    temporary.chmod(mode)
    os.replace(temporary, path)


def render_hysteria_stats(original, secret):
    stats = ("trafficStats:\n  listen: 127.0.0.1:19999\n"
             f"  secret: {secret}\n")
    match = re.search(r"(?m)^trafficStats:\s*$", original)
    if match:
        tail = original[match.end():]
        next_section = re.search(r"(?m)^[a-zA-Z][a-zA-Z0-9]*:", tail)
        end = match.end() + next_section.start() if next_section else len(original)
        suffix = original[end:]
        return original[:match.start()] + stats + ("\n" if suffix else "") + suffix
    return original.rstrip() + "\n\n" + stats


def enable_agent_revocation():
    """Enable Hysteria's loopback kick API without replacing its ACME/auth settings."""
    secret_path = CONFIG / "mellcore-secrets.json"
    config = json.loads(secret_path.read_text())
    if not config.get("hysteria_stats_secret"):
        config["hysteria_stats_secret"] = secrets.token_hex(32)
        write(secret_path, json.dumps(config, indent=2))
    secret = config["hysteria_stats_secret"]
    if not re.fullmatch(r"[a-f0-9]{64}", secret):
        raise SystemExit("Некорректный Hysteria stats secret")
    center_env = CONFIG / "center.env"
    lines = [line for line in center_env.read_text().splitlines()
             if not line.startswith(("HF_HYSTERIA_STATS_URL=", "HF_HYSTERIA_STATS_SECRET="))]
    lines += ["HF_HYSTERIA_STATS_URL=http://127.0.0.1:19999",
              f"HF_HYSTERIA_STATS_SECRET={secret}"]
    write(center_env, "\n".join(lines) + "\n")
    hysteria_config = Path("/etc/hysteria/config.yaml")
    original = hysteria_config.read_text()
    updated = render_hysteria_stats(original, secret)
    write(hysteria_config, updated, mode=0o640)
    subprocess.run(["chown", "root:hysteria", str(hysteria_config)], check=True)


def main():
    CONFIG.mkdir(mode=0o750, exist_ok=True)
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    secret_path = CONFIG / "mellcore-secrets.json"
    if secret_path.exists():
        config = json.loads(secret_path.read_text())
    else:
        config = {name: secrets.token_hex(32) for name in (
            "postgres_password", "jwt_secret", "control_token", "telemetry_token", "agent_credential"
        )}
        config.update(admin_email="akimenkovaleria403@gmail.com", admin_password=secrets.token_urlsafe(24),
                      agent_id=str(uuid.uuid4()), domain=DOMAIN)
        write(secret_path, json.dumps(config, indent=2))
    if "clickhouse_password" not in config:
        config["clickhouse_password"] = secrets.token_urlsafe(32)
        write(secret_path, json.dumps(config, indent=2))
    if "center_graph_token" not in config:
        config["center_graph_token"] = secrets.token_urlsafe(32)
        write(secret_path, json.dumps(config, indent=2))
    backend_env = (
        "API_BIND=127.0.0.1:18080\nDOCS_ENABLED=true\nINTEGRATION_MODE=mock\n"
        f"DATABASE_URL=postgres://honeyforge:{config['postgres_password']}@127.0.0.1:54329/honeyforge\n"
        "DATABASE_ALLOW_INSECURE_LOCAL=true\nDATABASE_MAX_CONNECTIONS=5\n"
        f"JWT_SECRET={config['jwt_secret']}\nFRONTEND_URL=https://{DOMAIN}\n"
        f"TELEMETRY_INGEST_TOKEN={config['telemetry_token']}\n"
        f"CENTER_INGEST_TOKEN={config['center_graph_token']}\n"
        f"CENTER_CONTROL_TOKEN={config['control_token']}\n"
        f"TELEMETRY_PUBLIC_ENDPOINT=https://{DOMAIN}/internal/v1/telemetry/batches\n"
        "REQUIRE_EMAIL_VERIFICATION=false\nRUST_LOG=honeyforge_backend=info\n"
    )
    write(CONFIG / "backend.env", backend_env)
    write(CONFIG / "postgres.env", (
        f"POSTGRES_PASSWORD={config['postgres_password']}\nPOSTGRES_PORT=54329\n"
        f"CLICKHOUSE_PASSWORD={config['clickhouse_password']}\nCLICKHOUSE_PORT=8123\n"
    ))
    write(CONFIG / "center.env", (
        "HF_CENTER_LISTEN=127.0.0.1:18081\nHF_KAZIK_UDP_LISTEN=127.0.0.1:44000\n"
        "HF_AGENT_BINARY=/usr/local/bin/hf-agent\nHF_DISPATCHER_BINARY=/usr/local/bin/hf-dispatcher\n"
        "HF_HYSTERIA_BINARY=/usr/local/bin/hysteria\n"
        f"HF_PUBLIC_CENTER_URL=https://{DOMAIN}\nHF_HYSTERIA_SERVER={DOMAIN}:443\nHF_HYSTERIA_SNI={DOMAIN}\n"
        "HF_CENTER_CREDENTIALS_FILE=/var/lib/honeyforge/center-credentials.json\n"
        f"HF_LOCAL_AGENT_ID={config['agent_id']}\nHF_LOCAL_AGENT_TARGET={DOMAIN}\n"
        "HF_CENTER_CLICKHOUSE_URL=http://127.0.0.1:8123\nHF_CENTER_CLICKHOUSE_USER=honeyforge\n"
        f"HF_CENTER_CLICKHOUSE_PASSWORD={config['clickhouse_password']}\n"
        "HF_CENTER_POSTGRES_TELEMETRY_URL=http://127.0.0.1:18080/internal/v1/center/events\n"
        "HF_CENTER_REGISTRY_URL=http://127.0.0.1:18080/internal/v1/center/traps\n"
        f"HF_CENTER_POSTGRES_TELEMETRY_TOKEN={config['center_graph_token']}\n"
        "HF_KOZYAVKA_IMAGE_ARCHIVE=/opt/mellcore/artifacts/low.tar\n"
        "HF_PRITVORYASHKA_IMAGE_ARCHIVE=/opt/mellcore/artifacts/middle.tar\n"
        "HF_HIGH_UBUNTU_RECIPE_ARCHIVE=/opt/mellcore/artifacts/hf-high-ubuntu-ssh.tar.gz\n"
        f"HF_CONTROL_TOKEN={config['control_token']}\n"
    ))
    write(CONFIG / "agent.env", (
        f"HF_CENTER_URL=https://{DOMAIN}\nHF_STATE_DIR={STATE}\n"
        "HF_KAZIK_HYSTERIA_SOCKS=127.0.0.1:1080\nHF_KAZIK_CENTER_UDP=127.0.0.1:44000\n"
        f"HF_TELEMETRY_PUBLIC_ENDPOINT=https://{DOMAIN}/internal/v1/telemetry/batches\n"
        f"HF_TELEMETRY_INGEST_TOKEN={config['telemetry_token']}\n"
    ))
    write(STATE / "identity.json", json.dumps({
        "agent_id": config["agent_id"], "transport_credential": config["agent_credential"],
        "hysteria": {"server": DOMAIN + ":443", "sni": DOMAIN}
    }, indent=2))
    credential_file = Path("/var/lib/honeyforge/center-credentials.json")
    first_credential_setup = not credential_file.exists()
    credentials = json.loads(credential_file.read_text()) if not first_credential_setup else {}
    if first_credential_setup:
        credentials[config["agent_id"]] = config["agent_credential"]
    hysteria_config = Path("/etc/hysteria/config.yaml")
    original = hysteria_config.read_text()
    match = re.search(r"(?m)^  password: ['\"]?([a-f0-9]{48})['\"]?\s*$", original)
    if match and first_credential_setup:
        # Keep the previously issued user connection valid alongside per-agent auth.
        credentials[str(uuid.uuid4())] = match.group(1)
    write(credential_file, json.dumps(credentials, indent=2))
    start = re.search(r"(?m)^auth:\s*$", original)
    if not start:
        raise SystemExit("В конфигурации Hysteria не найден блок auth")
    tail = original[start.end():]
    next_section = re.search(r"(?m)^[a-zA-Z][a-zA-Z0-9]*:", tail)
    end = start.end() + next_section.start() if next_section else len(original)
    auth = "auth:\n  type: http\n  http:\n    url: http://127.0.0.1:18081/v1/hysteria/auth\n\n"
    write(hysteria_config, original[:start.start()] + auth + original[end:], mode=0o640)
    subprocess.run(["chown", "root:hysteria", str(hysteria_config)], check=True)
    enable_agent_revocation()
    encrypted = subprocess.run(["openssl", "passwd", "-6", "-stdin"], input=config["admin_password"] + "\n",
                               text=True, check=True, capture_output=True).stdout.strip()
    write(CONFIG / "panel.htpasswd", "admin:" + encrypted + "\n", mode=0o640)
    subprocess.run(["chown", "root:www-data", str(CONFIG / "panel.htpasswd")], check=True)
    access = (
        f"Панель: https://{DOMAIN}/\nHTTP Basic login: admin\nHTTP Basic password: {config['admin_password']}\n"
        f"Backend admin email: {config['admin_email']}\nBackend admin password: {config['admin_password']}\n"
        f"Local agent ID: {config['agent_id']}\nControl token: {config['control_token']}\n"
        "API: /api/v1/; локальная документация: http://127.0.0.1:18080/docs/\n"
        "Общий SSH порт ловушек: 2222; Low/Middle распределяются Dispatcher 50/50 по source IP.\n"
    )
    write("/root/mellcore-access.txt", access)


if __name__ == "__main__":
    main()
