#!/bin/sh
set -eu

base_image=${1:?verified prepared Windows QCOW2}
instance_dir=${2:?instance directory}
instance_id=${3:?instance UUID}
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
. "$script_dir/../../high-ubuntu-ssh/scripts/firewall-common.sh"
validate_instance_id "$instance_id"
command -v qemu-img >/dev/null
command -v openssl >/dev/null
command -v python3 >/dev/null
[ -r "$base_image" ]
if command -v xorriso >/dev/null 2>&1; then
  iso_tool=xorriso
elif command -v genisoimage >/dev/null 2>&1; then
  iso_tool=genisoimage
else
  echo 'xorriso or genisoimage is required for the Cloudbase-Init config-drive' >&2
  exit 1
fi

mkdir -p "$instance_dir"
chmod 0700 "$instance_dir"
username=hfadmin
password_file="$instance_dir/rdp-password"
username_file="$instance_dir/rdp-username"
if [ -r "$password_file" ]; then
  admin_password=$(cat "$password_file")
else
  admin_password="Hf!$(openssl rand -hex 16)9a"
  umask 077
  printf '%s\n' "$admin_password" > "$password_file"
fi
[ -n "$admin_password" ] || { echo 'generated Windows password is empty' >&2; exit 1; }
printf '%s\n' "$username" > "$username_file"

hostname="hf-$(printf '%s' "$instance_id" | tr -d '-' | cut -c1-12)"
config_root="$instance_dir/config-drive"
metadata_dir="$config_root/openstack/latest"
mkdir -p "$metadata_dir"
python3 - "$metadata_dir/meta_data.json" "$instance_id" "$hostname" "$username" "$admin_password" <<'PY'
import json
import os
import sys

path, instance_id, hostname, username, password = sys.argv[1:]
metadata = {
    "uuid": instance_id,
    "hostname": hostname,
    "name": hostname,
    "meta": {"admin_username": username, "admin_pass": password},
}
with open(path, "x", encoding="utf-8") as stream:
    json.dump(metadata, stream, separators=(",", ":"))
    stream.write("\n")
os.chmod(path, 0o600)
PY

virtual_size=$(qemu-img info --output=json "$base_image" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("virtual-size", 0))')
[ "$virtual_size" -gt 0 ] 2>/dev/null || { echo 'prepared Windows image has no valid virtual size' >&2; exit 1; }
qemu-img create -f qcow2 -F qcow2 -b "$base_image" "$instance_dir/disk.qcow2" "$virtual_size"
if [ "$iso_tool" = xorriso ]; then
  xorriso -as mkisofs -V config-2 -J -r -o "$instance_dir/config-drive.iso" "$config_root" >/dev/null 2>&1
else
  genisoimage -V config-2 -J -r -o "$instance_dir/config-drive.iso" "$config_root" >/dev/null 2>&1
fi
chmod 0600 "$instance_dir/disk.qcow2" "$instance_dir/config-drive.iso" \
  "$metadata_dir/meta_data.json" "$password_file" "$username_file"
