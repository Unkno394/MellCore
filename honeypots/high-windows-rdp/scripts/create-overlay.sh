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
sed -e "s|@@ADMIN_PASSWORD@@|$admin_password|g" -e "s|@@HOSTNAME@@|$hostname|g" "$script_dir/../autounattend.xml" > "$instance_dir/Autounattend.xml"
if grep -q '@@[A-Z0-9_][A-Z0-9_]*@@' "$instance_dir/Autounattend.xml"; then
  echo 'unresolved Windows answer-file marker' >&2
  exit 1
fi
qemu-img create -f qcow2 "$instance_dir/disk.qcow2" 80G
if [ "$iso_tool" = xorriso ]; then xorriso -as mkisofs -V HFSEED -J -r -o "$instance_dir/seed.iso" "$instance_dir/Autounattend.xml" >/dev/null 2>&1; else genisoimage -V HFSEED -J -r -o "$instance_dir/seed.iso" "$instance_dir/Autounattend.xml" >/dev/null 2>&1; fi
chmod 0600 "$instance_dir/disk.qcow2" "$instance_dir/seed.iso" "$instance_dir/Autounattend.xml" "$password_file"
