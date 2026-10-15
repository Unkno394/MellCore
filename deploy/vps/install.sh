#!/usr/bin/env bash
set -euo pipefail
umask 077
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
[[ $EUID -eq 0 ]] || { echo 'Запустите от root.' >&2; exit 1; }
artifact_dir=${1:-${MELLCORE_ARTIFACT_DIR:-}}
if [[ -z $artifact_dir ]]; then
    shopt -s nullglob
    candidates=(/root/mellcore-upload-*)
    shopt -u nullglob
    ((${#candidates[@]} == 1)) || {
        echo 'Не удалось однозначно выбрать каталог артефактов. Укажите его первым аргументом.' >&2
        exit 1
    }
    artifact_dir=${candidates[0]}
fi
artifact_dir=$(realpath "$artifact_dir")
python3 "$repo/deploy/vps/validate-artifacts.py" "$artifact_dir"
exec 9>/root/.mellcore-install.lock
flock -n 9 || { echo 'Установка уже выполняется.' >&2; exit 1; }
trap 'echo "Остановка на строке $LINENO. Данные PostgreSQL, ClickHouse и сертификаты сохранены; можно повторить скрипт после исправления причины." >&2' ERR
systemctl list-units --no-pager >/dev/null
docker info >/dev/null
nginx -t
managed_install=false
[[ ! -e /etc/honeyforge/mellcore-installed ]] || managed_install=true
if [[ $managed_install == false ]]; then
    for unit in hf-agent.service hf-center.service hf-dispatcher.service honeyforge-backend.service; do
        [[ ! -e "/etc/systemd/system/$unit" ]] || { echo "Существует $unit, не созданный установщиком MellCore; проверьте его вручную." >&2; exit 1; }
    done
    [[ ! -e /etc/nginx/conf.d/mellcore-https.conf ]] || { echo 'Найден существующий nginx-файл MellCore без install marker; проверьте его вручную.' >&2; exit 1; }
    if docker ps -q --filter name='^/mellcore-vps-postgres-1$' | grep -q .; then
        echo 'Найден уже работающий mellcore-vps-postgres-1 без install marker; остановка запрещена.' >&2
        exit 1
    fi
fi
# Validate that the archived Middle binary can start against the libc in its
# own runtime image before replacing services or installing host binaries.
docker load --input "$artifact_dir/middle.tar" >/dev/null
bash "$repo/deploy/vps/check-middle-image.sh" honeyforge-pritvoryashka:local
if ! docker compose version >/dev/null 2>&1 || ! docker buildx version >/dev/null 2>&1; then
    install -d -m 0755 /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/mellcore-docker.asc
    chmod 0644 /etc/apt/keyrings/mellcore-docker.asc
    architecture=$(dpkg --print-architecture)
    cat > /etc/apt/sources.list.d/mellcore-docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: noble
Components: stable
Architectures: $architecture
Signed-By: /etc/apt/keyrings/mellcore-docker.asc
EOF
    apt-get update
    apt-get install -y --no-install-recommends docker-compose-plugin docker-buildx-plugin
fi
apt-get update
apt-get install -y libssl3t64 libssh2-1t64 ca-certificates python3 openssl curl
if [[ ! -f /etc/honeyforge/mellcore-secrets.json ]]; then
    for port in 1080 18080 18081 54329 8123 2222 31001 31002; do
        listeners=$(ss -H -ltn "sport = :$port")
        [[ -z $listeners ]] || { echo "TCP $port уже занят; требуется выбрать другой порт." >&2; exit 1; }
    done
    [[ ! -e /etc/systemd/system/hf-agent.service ]] || { echo 'Уже существует hf-agent.service; требуется проверить текущую установку.' >&2; exit 1; }
fi
ldd "$artifact_dir/bin/hf-center" | grep -q 'not found' && { echo 'hf-center отсутствует системная библиотека.' >&2; exit 1; } || true
ldd "$artifact_dir/bin/hf-agent" | grep -q 'not found' && { echo 'hf-agent отсутствует системная библиотека.' >&2; exit 1; } || true
ldd "$artifact_dir/bin/hf-dispatcher" | grep -q 'not found' && { echo 'hf-dispatcher отсутствует системная библиотека.' >&2; exit 1; } || true
ldd "$artifact_dir/bin/honeyforge-backend" | grep -q 'not found' && { echo 'honeyforge-backend отсутствует системная библиотека.' >&2; exit 1; } || true
install -d -m 0755 /opt/mellcore/artifacts
install -d -m 0755 /opt/mellcore/artifacts/bin
for binary in hf-center hf-agent hf-dispatcher honeyforge-backend; do
    install -m 0755 "$artifact_dir/bin/$binary" "/opt/mellcore/artifacts/bin/$binary"
    if [[ -f "/usr/local/bin/$binary" && ! -L "/usr/local/bin/$binary" ]]; then
        install -d -m 0700 /root/mellcore-backups/binaries
        cp -an "/usr/local/bin/$binary" "/root/mellcore-backups/binaries/$binary"
    fi
    install -m 0755 "$artifact_dir/bin/$binary" "/usr/local/bin/$binary"
done
install -m 0600 "$artifact_dir/low.tar" /opt/mellcore/artifacts/low.tar
install -m 0600 "$artifact_dir/middle.tar" /opt/mellcore/artifacts/middle.tar
install -m 0644 "$artifact_dir/hf-high-ubuntu-ssh.tar.gz" /opt/mellcore/artifacts/hf-high-ubuntu-ssh.tar.gz
docker load --input /opt/mellcore/artifacts/low.tar
sha256sum /opt/mellcore/artifacts/bin/* /opt/mellcore/artifacts/*.tar* > /opt/mellcore/artifacts/SHA256SUMS
chmod 0600 /opt/mellcore/artifacts/SHA256SUMS
for binary in hf-center hf-agent hf-dispatcher honeyforge-backend; do
    ldd "/usr/local/bin/$binary" | grep -q 'not found' && { echo "$binary отсутствует системная библиотека." >&2; exit 1; } || true
done
install -d -m 0755 /usr/local/lib/honeyforge
tar --no-same-owner -xzf /opt/mellcore/artifacts/hf-high-ubuntu-ssh.tar.gz -C /usr/local/lib/honeyforge
chmod 0755 /usr/local/lib/honeyforge/hf-image-builder/hf-image-builder
install -d -m 0700 /root/mellcore-backups
cp -p /etc/hysteria/config.yaml "/root/mellcore-backups/hysteria-$(date +%Y%m%d-%H%M%S).yaml"
systemctl stop hf-agent hf-center 2>/dev/null || true
python3 "$repo/deploy/vps/configure.py"
python3 - <<'PY'
import json
from pathlib import Path

secrets = json.loads(Path('/etc/honeyforge/mellcore-secrets.json').read_text())
token = secrets['control_token']
if not token or any(ch not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for ch in token):
    raise SystemExit('Некорректный control token')
snippet = Path('/etc/nginx/snippets/mellcore-control-token.conf')
snippet.parent.mkdir(parents=True, exist_ok=True)
temporary = snippet.with_suffix('.conf.tmp')
temporary.write_text(f'proxy_set_header X-Honeyforge-Control-Token {token};\n')
temporary.chmod(0o600)
temporary.replace(snippet)
PY
getent passwd honeyforge >/dev/null || useradd --system --home-dir /var/lib/honeyforge/backend --create-home --shell /usr/sbin/nologin honeyforge
install -d -m 0755 /etc/honeyforge
chown root:honeyforge /etc/honeyforge/backend.env
chmod 0640 /etc/honeyforge/backend.env
docker compose --env-file /etc/honeyforge/postgres.env -p mellcore-vps -f "$repo/backend/compose.yaml" up -d postgres clickhouse
docker update --restart unless-stopped mellcore-vps-postgres-1 >/dev/null
docker update --restart unless-stopped mellcore-vps-clickhouse-1 >/dev/null
for attempt in $(seq 1 60); do
    if docker compose --env-file /etc/honeyforge/postgres.env -p mellcore-vps -f "$repo/backend/compose.yaml" exec -T postgres pg_isready -U honeyforge -d honeyforge >/dev/null; then break; fi
    sleep 2
done
for attempt in $(seq 1 90); do
    if docker compose --env-file /etc/honeyforge/postgres.env -p mellcore-vps -f "$repo/backend/compose.yaml" exec -T clickhouse clickhouse-client --query 'SELECT 1' >/dev/null 2>&1; then break; fi
    sleep 2
done
docker compose --env-file /etc/honeyforge/postgres.env -p mellcore-vps -f "$repo/backend/compose.yaml" exec -T clickhouse clickhouse-client --query 'SELECT 1' >/dev/null
systemctl stop honeyforge-backend 2>/dev/null || true
docker compose --env-file /etc/honeyforge/postgres.env -p mellcore-vps -f "$repo/backend/compose.yaml" exec -T postgres pg_dump -U honeyforge -d honeyforge > "/root/mellcore-backups/database-$(date +%Y%m%d-%H%M%S).sql"
set -a
source /etc/honeyforge/backend.env
set +a
/usr/local/bin/honeyforge-backend migrate
python3 "$repo/deploy/vps/bootstrap-admin.py"
for component in center agent; do
    cat > "/etc/systemd/system/hf-$component.service" <<EOF
[Unit]
Description=MellCore HoneyForge $component
After=network-online.target docker.service
Wants=network-online.target
[Service]
EnvironmentFile=/etc/honeyforge/$component.env
ExecStart=/usr/local/bin/hf-$component
Restart=on-failure
RestartSec=5
WorkingDirectory=/var/lib/honeyforge
[Install]
WantedBy=multi-user.target
EOF
done
cat > /etc/systemd/system/honeyforge-backend.service <<'EOF'
[Unit]
Description=MellCore management API
After=network-online.target docker.service
Wants=network-online.target
[Service]
User=honeyforge
Group=honeyforge
EnvironmentFile=/etc/honeyforge/backend.env
ExecStart=/usr/local/bin/honeyforge-backend serve
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/hf-dispatcher.service <<'EOF'
[Unit]
Description=MellCore TCP dispatcher
After=network-online.target docker.service
[Service]
ExecStart=/usr/local/bin/hf-dispatcher --config /etc/honeyforge/dispatcher.json
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
EOF
install -m 0755 "$repo/deploy/vps/sync-certificate.py" /usr/local/bin/mellcore-sync-certificate
/usr/local/bin/mellcore-sync-certificate
cat > /etc/nginx/conf.d/mellcore-https.conf <<'EOF'
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name yourpasswordforemail.ru;
    ssl_certificate /etc/honeyforge/tls/fullchain.pem;
    ssl_certificate_key /etc/honeyforge/tls/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 1m;
    auth_basic "MellCore operators";
    auth_basic_user_file /etc/honeyforge/panel.htpasswd;
    location = /v1/hysteria/auth { return 404; }
    location = /v1/agents/register {
        auth_basic off;
        proxy_pass http://127.0.0.1:18081;
    }
    location /api/ {
        auth_basic off;
        proxy_pass http://127.0.0.1:18080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
    }
    location = /internal/v1/telemetry/batches {
        auth_basic off;
        proxy_pass http://127.0.0.1:18080;
    }
    location /health/ {
        proxy_pass http://127.0.0.1:18080;
    }
    location / {
        proxy_pass http://127.0.0.1:18081;
        include /etc/nginx/snippets/mellcore-control-token.conf;
        proxy_read_timeout 900s;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
    }
}
EOF
nginx -t
systemctl reload nginx
cat > /etc/systemd/system/mellcore-certificate.service <<'EOF'
[Unit]
Description=Sync MellCore HTTPS certificate from Hysteria
[Service]
Type=oneshot
ExecStart=/usr/local/bin/mellcore-sync-certificate
EOF
cat > /etc/systemd/system/mellcore-certificate.timer <<'EOF'
[Unit]
Description=Refresh MellCore HTTPS certificate
[Timer]
OnBootSec=5min
OnUnitActiveSec=1h
Persistent=true
[Install]
WantedBy=timers.target
EOF
mkdir -p /etc/systemd/system/hysteria-server.service.d
cat > /etc/systemd/system/hysteria-server.service.d/mellcore.conf <<'EOF'
[Unit]
After=hf-center.service
Wants=hf-center.service
[Service]
Restart=on-failure
RestartSec=5
EOF
systemctl daemon-reload
systemctl enable --now honeyforge-backend hf-center mellcore-certificate.timer
systemctl restart honeyforge-backend hf-center
systemctl restart hysteria-server
systemctl enable --now hf-agent
systemctl restart hf-agent
if command -v ufw >/dev/null && ufw status | grep '^Status: active' >/dev/null; then
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 443/udp
    ufw allow 2222/tcp
fi
python3 "$repo/deploy/vps/verify-and-seed.py"
touch /etc/honeyforge/mellcore-installed
echo 'Компоненты запущены и проверены. Панель: https://yourpasswordforemail.ru/'
echo 'Данные входа: /root/mellcore-access.txt (cat /root/mellcore-access.txt)'
if [[ ! -c /dev/kvm ]]; then echo 'Публичные High VM требуют /dev/kvm; для локальной проверки используйте standalone TCG test mode.'; fi
echo 'SMTP и полноценная связь backend CRUD с агентом пока не реализованы в этом контуре.'
