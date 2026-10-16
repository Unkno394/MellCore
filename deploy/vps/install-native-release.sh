#!/usr/bin/env bash
# Apply a native MellCore release on the existing Center VPS. No Docker calls.
set -Eeuo pipefail
umask 077

bundle=${1:?Usage: install-native-release.sh RELEASE_DIRECTORY}
bundle=$(realpath "$bundle")
[[ $EUID -eq 0 ]] || { echo 'Run as root on the Center VPS.' >&2; exit 1; }
for file in bin/honeyforge-backend bin/hf-agent frontend.tar.gz deploy-frontend.sh SHA256SUMS; do
    [[ -s $bundle/$file ]] || { echo "Missing artifact: $file" >&2; exit 1; }
done
(cd "$bundle" && sha256sum --check SHA256SUMS)
for name in honeyforge-backend hf-agent; do
    file "$bundle/bin/$name" | grep -q 'ELF 64-bit.*x86-64' || { echo "Invalid executable: $name" >&2; exit 1; }
    if ldd "$bundle/bin/$name" | grep -q 'not found'; then
        echo "Missing shared library for $name" >&2
        exit 1
    fi
done
"$bundle/bin/hf-agent" --help >/dev/null

backup="/root/mellcore-backups/native-$(date +%Y%m%d-%H%M%S)"
install -d -m 0700 "$backup"
cp -a /usr/local/bin/honeyforge-backend /usr/local/bin/hf-agent "$backup/"
printf '%s\n' "Backup: $backup"

# The new binary embeds additive SQL migrations. The old binary rejects a
# newer migration set, so finish backend activation immediately after migrate.
python3 - "$bundle/bin/honeyforge-backend" <<'PY'
import os
import shlex
import sys

environment = os.environ.copy()
with open('/etc/honeyforge/backend.env', encoding='utf-8') as config:
    for line in config:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, value = line.split('=', 1)
        parts = shlex.split(value, comments=False)
        environment[key] = parts[0] if len(parts) == 1 else value
os.execve(sys.argv[1], [sys.argv[1], 'migrate'], environment)
PY
install -m 0755 "$bundle/bin/honeyforge-backend" /usr/local/bin/.honeyforge-backend.new
mv -f /usr/local/bin/.honeyforge-backend.new /usr/local/bin/honeyforge-backend
systemctl restart honeyforge-backend.service
for _ in {1..20}; do
    if curl --fail --silent --output /dev/null http://127.0.0.1:18080/health/ready; then break; fi
    sleep 1
done
curl --fail --silent --show-error http://127.0.0.1:18080/health/ready >/dev/null

bash "$bundle/deploy-frontend.sh" "$bundle/frontend.tar.gz"

install -m 0755 "$bundle/bin/hf-agent" /usr/local/bin/.hf-agent.new
mv -f /usr/local/bin/.hf-agent.new /usr/local/bin/hf-agent
if ! systemctl restart hf-agent.service || ! systemctl is-active --quiet hf-agent.service; then
    install -m 0755 "$backup/hf-agent" /usr/local/bin/.hf-agent.rollback
    mv -f /usr/local/bin/.hf-agent.rollback /usr/local/bin/hf-agent
    systemctl restart hf-agent.service || true
    echo 'hf-agent did not start; its previous binary was restored.' >&2
    exit 1
fi
ln -sfn /usr/local/bin/hf-agent /usr/local/bin/hf
curl --fail --silent --show-error --resolve yourpasswordforemail.ru:443:127.0.0.1 \
    https://yourpasswordforemail.ru/ >/dev/null
echo 'Native backend, frontend and local agent deployed successfully.'
