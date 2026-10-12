#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

[[ $EUID -eq 0 ]] || { echo 'Запусти от root.' >&2; exit 1; }
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
center_bin=${1:-/tmp/hf-center-bootstrap}
backend_bin=${2:-/tmp/honeyforge-backend-bootstrap}
frontend_archive=${3:-/tmp/mellcore-frontend-dist.tar.gz}
for path in "$center_bin" "$backend_bin" "$frontend_archive"; do
    [[ -s $path ]] || { echo "Не найден артефакт: $path" >&2; exit 1; }
done
for path in "$center_bin" "$backend_bin"; do
    file "$path" | grep -q 'ELF 64-bit.*x86-64' || { echo "Нужен ELF x86-64: $path" >&2; exit 1; }
    if ldd "$path" | grep -q 'not found'; then
        echo "Отсутствует системная библиотека для $path" >&2
        exit 1
    fi
done

backup="/root/mellcore-backups/server-bootstrap-$(date +%Y%m%d-%H%M%S)"
install -d -m 0700 "$backup"
cp -a /usr/local/bin/hf-center /usr/local/bin/honeyforge-backend "$backup/"
cp -a /etc/honeyforge/backend.env /etc/nginx/conf.d/mellcore-https.conf "$backup/"
rollback() {
    cp -a "$backup/hf-center" "$backup/honeyforge-backend" /usr/local/bin/
    cp -a "$backup/backend.env" /etc/honeyforge/backend.env
    cp -a "$backup/mellcore-https.conf" /etc/nginx/conf.d/mellcore-https.conf
    systemctl restart hf-center honeyforge-backend || true
    nginx -t && systemctl reload nginx || true
    echo "Активация не завершилась; файлы сервисов восстановлены из $backup" >&2
}
trap rollback ERR

python3 - <<'PY'
import json, os
from pathlib import Path
secrets = json.loads(Path('/etc/honeyforge/mellcore-secrets.json').read_text())
token = secrets['control_token']
if len(token) < 32 or not all(c.isalnum() or c in '-_' for c in token):
    raise SystemExit('Некорректный control token')
env = Path('/etc/honeyforge/backend.env')
lines = [line for line in env.read_text().splitlines() if not line.startswith('CENTER_CONTROL_TOKEN=')]
lines.append('CENTER_CONTROL_TOKEN=' + token)
temporary = env.with_suffix('.env.bootstrap-tmp')
temporary.write_text('\n'.join(lines) + '\n')
temporary.chmod(0o640)
os.chown(temporary, 0, __import__('grp').getgrnam('honeyforge').gr_gid)
temporary.replace(env)
PY

python3 - <<'PY'
from pathlib import Path
conf = Path('/etc/nginx/conf.d/mellcore-https.conf')
text = conf.read_text()
block = '    location ^~ /v1/agents/bootstrap { return 404; }\n'
if block not in text:
    marker = '    location /v1/ {\n'
    if marker not in text:
        raise SystemExit('Не найден публичный маршрут /v1/ в Nginx')
    conf.write_text(text.replace(marker, block + marker, 1))
PY
nginx -t
systemctl reload nginx

install -m 0755 "$backend_bin" /usr/local/bin/honeyforge-backend
set -a
source /etc/honeyforge/backend.env
set +a
/usr/local/bin/honeyforge-backend migrate
install -m 0755 "$center_bin" /usr/local/bin/hf-center
systemctl restart hf-center honeyforge-backend
systemctl is-active --quiet hf-center honeyforge-backend
bash "$repo/deploy/vps/deploy-frontend.sh" "$frontend_archive"
trap - ERR
echo "Bootstrap API и React-форма активированы. Backup: $backup"
