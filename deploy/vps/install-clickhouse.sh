#!/usr/bin/env bash
set -euo pipefail
umask 077
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
[[ $EUID -eq 0 ]] || { echo 'Запустите от root.' >&2; exit 1; }
secrets=/etc/honeyforge/mellcore-secrets.json
[[ -r $secrets ]] || { echo "Не найден $secrets; сначала настройте MellCore на VPS." >&2; exit 1; }

python3 - <<'PY'
import json, os, secrets, tempfile
from pathlib import Path

config_path = Path('/etc/honeyforge/mellcore-secrets.json')
config = json.loads(config_path.read_text())
config.setdefault('clickhouse_password', secrets.token_urlsafe(32))

def write_secret(path, entries):
    path = Path(path)
    current = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if '=' in line and not line.lstrip().startswith('#'):
                key, value = line.split('=', 1)
                current[key] = value
    current.update(entries)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=path.name + '.')
    with os.fdopen(fd, 'w') as output:
        output.write(''.join(f'{key}={value}\n' for key, value in current.items()))
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)

fd, temporary = tempfile.mkstemp(dir=config_path.parent, prefix='mellcore-secrets.')
with os.fdopen(fd, 'w') as output:
    json.dump(config, output, indent=2)
    output.write('\n')
os.chmod(temporary, 0o600)
os.replace(temporary, config_path)
write_secret('/etc/honeyforge/postgres.env', {
    'POSTGRES_PASSWORD': config['postgres_password'], 'POSTGRES_PORT': '54329',
    'CLICKHOUSE_PASSWORD': config['clickhouse_password'], 'CLICKHOUSE_PORT': '8123',
})
write_secret('/etc/honeyforge/center.env', {
    'HF_CENTER_CLICKHOUSE_URL': 'http://127.0.0.1:8123',
    'HF_CENTER_CLICKHOUSE_USER': 'honeyforge',
    'HF_CENTER_CLICKHOUSE_PASSWORD': config['clickhouse_password'],
    'HF_CENTER_POSTGRES_TELEMETRY_URL': 'http://127.0.0.1:18080/internal/v1/center/events',
    'HF_CENTER_POSTGRES_TELEMETRY_TOKEN': config['telemetry_token'],
})
PY

compose=(docker compose --env-file /etc/honeyforge/postgres.env -p mellcore-vps -f "$repo/backend/compose.yaml")
"${compose[@]}" config --quiet
"${compose[@]}" up -d clickhouse
for attempt in $(seq 1 90); do
    if "${compose[@]}" exec -T clickhouse clickhouse-client --query 'SELECT 1' >/dev/null 2>&1; then break; fi
    sleep 2
done
"${compose[@]}" exec -T clickhouse clickhouse-client --query 'SELECT 1' >/dev/null
"${compose[@]}" exec -T clickhouse clickhouse-client --multiquery < "$repo/deploy/vps/clickhouse/001-telemetry.sql"
docker update --restart unless-stopped mellcore-vps-clickhouse-1 >/dev/null
echo 'ClickHouse запущен на 127.0.0.1:8123; таблица honeyforge.telemetry_events готова.'
echo 'После установки новой сборки hf-center перезапустите systemctl restart hf-center.'
