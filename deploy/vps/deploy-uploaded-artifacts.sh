#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

[[ $EUID -eq 0 ]] || { echo 'Запусти от root.' >&2; exit 1; }
artifacts=/tmp
for name in hf-center hf-agent hf-dispatcher honeyforge-backend mellcore-frontend-dist.tar.gz; do
    [[ -s "$artifacts/$name" ]] || { echo "Нет артефакта: $artifacts/$name" >&2; exit 1; }
done

for name in hf-center hf-agent hf-dispatcher honeyforge-backend; do
    file="$artifacts/$name"
    [[ -x "$file" ]] || { echo "Нет права запуска у $file" >&2; exit 1; }
    file "$file" | grep -q 'ELF 64-bit.*x86-64' || { echo "Нужен ELF x86-64: $file" >&2; exit 1; }
    if ldd "$file" | grep -q 'not found'; then
        echo "У $name отсутствуют системные библиотеки." >&2
        exit 1
    fi
done
"$artifacts/hf-center" --help | grep -F HF_CENTER_CREDENTIALS_FILE >/dev/null
"$artifacts/hf-center" --help | grep -F HF_HYSTERIA_STATS_URL >/dev/null
strings "$artifacts/hf-agent" | grep -F HF_TELEMETRY_PUBLIC_ENDPOINT >/dev/null
strings "$artifacts/hf-agent" | grep -F 'final trap telemetry queued before removal' >/dev/null

python3 - "$artifacts/mellcore-frontend-dist.tar.gz" <<'PY'
import sys, tarfile
with tarfile.open(sys.argv[1], 'r:gz') as archive:
    members = archive.getmembers()
    if not members or not any(m.name.lstrip('./') == 'index.html' for m in members):
        raise SystemExit('Frontend archive has no index.html')
    for member in members:
        parts = member.name.split('/')
        if member.name.startswith('/') or '..' in parts or member.issym() or member.islnk():
            raise SystemExit(f'Unsafe frontend archive entry: {member.name}')
PY

nginx_conf=/etc/nginx/conf.d/mellcore-https.conf
[[ -f "$nginx_conf" ]] || { echo "Не найден $nginx_conf" >&2; exit 1; }
backup="/root/mellcore-backups/deploy-$(date +%Y%m%d-%H%M%S)"
install -d -m 0700 "$backup/bin" "$backup/nginx"
for name in hf-center hf-agent hf-dispatcher honeyforge-backend; do
    [[ ! -e "/usr/local/bin/$name" ]] || cp -a "/usr/local/bin/$name" "$backup/bin/$name"
done
cp -a "$nginx_conf" "$backup/nginx/mellcore-https.conf"

web_root=/var/www/mellcore
release="$web_root/releases/$(date +%Y%m%d-%H%M%S)"
install -d -m 0755 "$release"
tar --no-same-owner --no-same-permissions -xzf "$artifacts/mellcore-frontend-dist.tar.gz" -C "$release"
[[ -s "$release/index.html" ]] || { echo 'В React-сборке отсутствует index.html' >&2; exit 1; }
chmod -R a+rX "$release"
ln -s "$release" "$web_root/current.new"
mv -Tf "$web_root/current.new" "$web_root/current"

python3 - "$nginx_conf" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
old = '''    location / {
        proxy_pass http://127.0.0.1:18081;
        include /etc/nginx/snippets/mellcore-control-token.conf;
        proxy_read_timeout 900s;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
    }
'''
new = '''    location /v1/ {
        proxy_pass http://127.0.0.1:18081;
        include /etc/nginx/snippets/mellcore-control-token.conf;
        proxy_read_timeout 900s;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
    }
    location / {
        auth_basic off;
        root /var/www/mellcore/current;
        try_files $uri $uri/ /index.html;
    }
'''
if 'location /v1/' not in text or 'proxy_pass http://127.0.0.1:18081;' not in text:
    if text.count(old) != 1:
        raise SystemExit('Не найден ожидаемый старый location / или маршрут /v1/; nginx не менялся.')
    text = text.replace(old, new, 1)
    path.write_text(text)
elif (
    'location / {' not in text
    or 'root /var/www/mellcore/current;' not in text
    or 'try_files $uri $uri/ /index.html;' not in text
):
    raise SystemExit('В Nginx не найден статический React root; nginx не менялся.')
PY

if ! nginx -t; then
    cp -a "$backup/nginx/mellcore-https.conf" "$nginx_conf"
    echo "Nginx-конфиг восстановлен из $backup/nginx/mellcore-https.conf" >&2
    exit 1
fi

# The backend verifies the exact migration set at startup. Apply migrations
# embedded in the uploaded binary before activating it, using the production
# environment file rather than a checkout-local .env.
(cd / && env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    "$artifacts/honeyforge-backend" migrate)

for name in hf-center hf-agent hf-dispatcher honeyforge-backend; do
    install -m 0755 "$artifacts/$name" "/usr/local/bin/.$name.new"
    mv -f "/usr/local/bin/.$name.new" "/usr/local/bin/$name"
done
systemctl reload nginx
systemctl restart honeyforge-backend hf-center hf-agent
if [[ -s /etc/honeyforge/dispatcher.json ]]; then
    systemctl enable hf-dispatcher
    systemctl restart hf-dispatcher
else
    # No shared trap group is configured on this host. The agent enables the
    # dispatcher after it writes the first valid routing config.
    systemctl disable --now hf-dispatcher 2>/dev/null || true
fi

printf 'Выкладка завершена. Backup: %s\n' "$backup"
printf 'Frontend: %s\n' "$release"
printf 'Nginx root теперь раздаёт React; /api идёт в backend, /v1 идёт в hf-center.\n'
