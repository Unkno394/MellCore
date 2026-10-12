#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Запусти от root.' >&2; exit 1; }
conf=/etc/nginx/conf.d/mellcore-https.conf
[[ -f $conf ]] || { echo "Не найден $conf" >&2; exit 1; }
backup="${conf}.bak.$(date +%Y%m%d-%H%M%S)"
cp -a "$conf" "$backup"
python3 - "$conf" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()
text = text.replace('    auth_basic "MellCore operators";\n', '')
text = text.replace('    auth_basic_user_file /etc/honeyforge/panel.htpasswd;\n', '')
path.write_text(text)
PY
if ! nginx -t; then
    cp -a "$backup" "$conf"
    echo "Конфиг восстановлен из $backup" >&2
    exit 1
fi
systemctl reload nginx
echo 'HTTP Basic Auth для сайта отключён. API и TLS-конфигурация не менялись.'
echo "Резервная копия: $backup"
