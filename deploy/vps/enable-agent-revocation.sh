#!/usr/bin/env bash
# Run on the Center VPS after installing the newly built hf-center binary.
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
[[ $(id -u) -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
grep -a 'HF_HYSTERIA_STATS_URL' /usr/local/bin/hf-center >/dev/null || {
    echo 'Install the new hf-center binary first' >&2; exit 1;
}
grep -a 'final trap telemetry queued before removal' /usr/local/bin/hf-agent >/dev/null || {
    echo 'Install the new hf-agent binary on Center before enabling trap removal' >&2; exit 1;
}
backup_dir=$(mktemp -d /root/hf-revocation-backup.XXXXXX)
cp -p /etc/honeyforge/mellcore-secrets.json /etc/honeyforge/center.env /etc/hysteria/config.yaml "$backup_dir/"
rollback() {
    cp -p "$backup_dir/mellcore-secrets.json" /etc/honeyforge/mellcore-secrets.json
    cp -p "$backup_dir/center.env" /etc/honeyforge/center.env
    cp -p "$backup_dir/config.yaml" /etc/hysteria/config.yaml
    systemctl restart hysteria-server hf-center || true
    echo "Configuration restored from $backup_dir" >&2
}
trap rollback ERR
python3 - "$repo/deploy/vps" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from configure import enable_agent_revocation
enable_agent_revocation()
PY
systemctl restart hysteria-server
systemctl restart hf-center
python3 - <<'PY'
import json
from pathlib import Path
from urllib.request import Request, urlopen
secret = json.loads(Path('/etc/honeyforge/mellcore-secrets.json').read_text())['hysteria_stats_secret']
request = Request('http://127.0.0.1:19999/online', headers={'Authorization': secret})
with urlopen(request, timeout=5) as response:
    if not isinstance(json.load(response), dict):
        raise SystemExit('Hysteria /online returned an invalid response')
PY
trap - ERR
echo 'Agent revocation enabled; Hysteria kick API is responding on loopback.'
