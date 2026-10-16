#!/bin/sh
set -eu
base_iso=${1:?verified Windows ISO}; instance_dir=${2:?instance directory}; instance_id=${3:?instance UUID}
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
. "$script_dir/../../high-ubuntu-ssh/scripts/firewall-common.sh"
validate_instance_id "$instance_id"
command -v qemu-img >/dev/null
command -v openssl >/dev/null
[ -r "$base_iso" ]
if command -v xorriso >/dev/null 2>&1; then iso_tool=xorriso; elif command -v genisoimage >/dev/null 2>&1; then iso_tool=genisoimage; else echo 'xorriso or genisoimage is required for unattended Windows seed' >&2; exit 1; fi
mkdir -p "$instance_dir"
password_file="$instance_dir/rdp-password"
if [ -r "$password_file" ]; then admin_password=$(cat "$password_file"); else admin_password="Hf!$(openssl rand -hex 16)9a"; umask 077; printf '%s\n' "$admin_password" > "$password_file"; fi
[ -n "$admin_password" ] || { echo 'generated Windows password is empty' >&2; exit 1; }
hostname="HF-$(printf '%s' "$instance_id" | tr -d '-' | cut -c1-12)"
if [ -n "${HF_HIGH_ISO_HOSTNAME:-}" ]; then hostname=$HF_HIGH_ISO_HOSTNAME; fi
python3 - "$script_dir/../autounattend.xml" "$instance_dir/Autounattend.xml" "$password_file" "$hostname" <<'PY'
from pathlib import Path
from xml.sax.saxutils import escape
import sys
template_path, output_path, password_path, hostname = map(Path, sys.argv[1:])
password = password_path.read_text(encoding="utf-8").rstrip("\n")
if not password or any(ord(character) < 32 for character in password):
    raise SystemExit("Windows password contains an invalid control character")
template = template_path.read_text(encoding="utf-8")
rendered = template.replace("@@ADMIN_PASSWORD@@", escape(password)).replace("@@HOSTNAME@@", escape(str(hostname)))
output_path.write_text(rendered, encoding="utf-8")
output_path.chmod(0o600)
PY
if grep -q '@@[A-Z0-9_][A-Z0-9_]*@@' "$instance_dir/Autounattend.xml"; then
  echo 'unresolved Windows answer-file marker' >&2
  exit 1
fi
qemu-img create -f qcow2 "$instance_dir/disk.qcow2" 80G
if [ "$iso_tool" = xorriso ]; then xorriso -as mkisofs -V HFSEED -J -r -o "$instance_dir/seed.iso" "$instance_dir/Autounattend.xml" >/dev/null 2>&1; else genisoimage -V HFSEED -J -r -o "$instance_dir/seed.iso" "$instance_dir/Autounattend.xml" >/dev/null 2>&1; fi
chmod 0600 "$instance_dir/disk.qcow2" "$instance_dir/seed.iso" "$instance_dir/Autounattend.xml" "$password_file"
