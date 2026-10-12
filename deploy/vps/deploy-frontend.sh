#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

[[ $EUID -eq 0 ]] || { echo 'Запусти от root.' >&2; exit 1; }
archive=${1:-/tmp/mellcore-frontend-dist.tar.gz}
[[ -s $archive ]] || { echo "Не найден архив фронтенда: $archive" >&2; exit 1; }

conf=/etc/nginx/conf.d/mellcore-https.conf
[[ -f $conf ]] || { echo "Не найден $conf" >&2; exit 1; }
web_root=/var/www/mellcore
stamp=$(date +%Y%m%d-%H%M%S)
release="$web_root/releases/$stamp"
backup="/root/mellcore-backups/frontend-$stamp"
install -d -m 0755 "$release"
install -d -m 0700 "$backup"
cp -a "$conf" "$backup/mellcore-https.conf"
if [[ -L "$web_root/current" ]]; then
    readlink "$web_root/current" > "$backup/previous-release"
fi

python3 - "$archive" "$release" <<'PY'
from pathlib import Path
import sys, tarfile

archive, destination = sys.argv[1:]
destination = Path(destination).resolve()
with tarfile.open(archive, 'r:gz') as bundle:
    members = bundle.getmembers()
    if not members or not any(Path(m.name).name == 'index.html' and not m.isdir() for m in members):
        raise SystemExit('В архиве нет index.html')
    for member in members:
        parts = Path(member.name).parts
        if Path(member.name).is_absolute() or '..' in parts or member.issym() or member.islnk():
            raise SystemExit(f'Небезопасный путь в архиве: {member.name}')
    bundle.extractall(destination, filter='data')
if not (destination / 'index.html').is_file():
    raise SystemExit('index.html должен лежать в корне архива')
PY
# A browser may still have index.html from a previous release. Keep its
# content-addressed assets available while those cached pages are in use.
for previous_assets in "$web_root"/releases/*/assets; do
    [[ -d $previous_assets && $previous_assets != "$release/assets" ]] || continue
    cp -an "$previous_assets/." "$release/assets/"
done
chmod -R a+rX "$release"

python3 - "$conf" <<'PY'
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
if text.count(old) == 1:
    text = text.replace(old, new, 1)
elif 'location /v1/' not in text or 'root /var/www/mellcore/current;' not in text:
    raise SystemExit('Не найден ожидаемый location /; Nginx не изменён.')
# Missing JS/CSS must return 404 instead of the SPA's HTML fallback. The
# document itself must be revalidated so browsers discover a new asset name.
static_locations = '''    location = /index.html {
        auth_basic off;
        root /var/www/mellcore/current;
        add_header Cache-Control "no-cache, must-revalidate" always;
    }
    location /assets/ {
        auth_basic off;
        root /var/www/mellcore/current;
        try_files $uri =404;
    }
'''
if 'location /assets/' not in text:
    text = text.replace('    location / {\n', static_locations + '    location / {\n', 1)
# Center's privileged bootstrap must only be reachable on its loopback listener.
# The browser uses the authenticated management API instead.
block_bootstrap = '    location ^~ /v1/agents/bootstrap { return 404; }\n'
if block_bootstrap not in text:
    text = text.replace('    location /v1/ {\n', block_bootstrap + '    location /v1/ {\n', 1)
# Ensure a server-level Basic Auth directive cannot trigger a browser prompt.
text = '\n'.join(line for line in text.split('\n') if not line.strip().startswith(('auth_basic "', 'auth_basic_user_file ')))
path.write_text(text)
PY

if ! nginx -t; then
    cp -a "$backup/mellcore-https.conf" "$conf"
    echo "Проверка Nginx не прошла; исходный конфиг восстановлен. Backup: $backup" >&2
    exit 1
fi

ln -s "$release" "$web_root/current.new"
mv -Tf "$web_root/current.new" "$web_root/current"
if ! systemctl reload nginx; then
    cp -a "$backup/mellcore-https.conf" "$conf"
    if [[ -s "$backup/previous-release" ]]; then
        ln -s "$(cat "$backup/previous-release")" "$web_root/current.rollback"
        mv -Tf "$web_root/current.rollback" "$web_root/current"
    else
        rm -f "$web_root/current"
    fi
    systemctl reload nginx || true
    echo "Выкладка откатилась. Backup: $backup" >&2
    exit 1
fi

echo "React frontend опубликован: https://yourpasswordforemail.ru/"
echo "Frontend: $release"
echo "Nginx backup: $backup/mellcore-https.conf"
