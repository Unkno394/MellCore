#!/bin/sh
set -eu

destination=${1:?destination path is required}
image_name=debian-12-genericcloud-amd64.qcow2
base_url=https://cloud.debian.org/images/cloud/bookworm/latest
image_url="$base_url/$image_name"
manifest_url="$base_url/SHA512SUMS"
command -v curl >/dev/null
command -v sha512sum >/dev/null
command -v qemu-img >/dev/null
command -v python3 >/dev/null
command -v virt-customize >/dev/null

if [ -f "$destination" ]; then
  qemu-img check -q -f qcow2 "$destination" || {
    echo 'cached HoneyForge Debian image failed QCOW2 integrity verification' >&2
    exit 1
  }
  LIBGUESTFS_BACKEND=direct virt-customize -a "$destination" --no-network \
    --run-command 'test -x /usr/bin/qemu-ga' || {
    echo 'cached HoneyForge Debian image does not contain qemu-guest-agent' >&2
    exit 1
  }
  exit 0
fi

mkdir -p "$(dirname "$destination")"
tmpdir=$(mktemp -d "$(dirname "$destination")/.debian-image.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT INT TERM
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 --output "$tmpdir/SHA512SUMS" "$manifest_url"
expected=$(awk -v image="$image_name" '$2 == image || $2 == "*" image { print $1; exit }' "$tmpdir/SHA512SUMS")
printf '%s' "$expected" | grep -Eq '^[0-9A-Fa-f]{128}$' || {
  echo 'official Debian SHA512SUMS has no expected image digest' >&2
  exit 1
}

verify_image() {
  candidate=$1
  actual=$(sha512sum "$candidate" | awk '{print $1}')
  [ "$actual" = "$expected" ] || return 1
  qemu-img info --output=json -f qcow2 "$candidate" | python3 -c '
import json, sys
info = json.load(sys.stdin)
if info.get("format") != "qcow2": raise SystemExit("Debian image is not QCOW2")
if info.get("backing-filename") or info.get("full-backing-filename"):
    raise SystemExit("Debian base image must not have a backing file")
'
  qemu-img check -q -f qcow2 "$candidate"
}

verify_prepared_image() {
  qemu-img info --output=json -f qcow2 "$1" | python3 -c '
import json, sys
info = json.load(sys.stdin)
if info.get("format") != "qcow2": raise SystemExit("Debian image is not QCOW2")
if info.get("backing-filename") or info.get("full-backing-filename"):
    raise SystemExit("Debian base image must not have a backing file")
'
  qemu-img check -q -f qcow2 "$1"
}

curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 --output "$tmpdir/$image_name" "$image_url"
verify_image "$tmpdir/$image_name" || {
  echo 'downloaded Debian image failed checksum or QCOW2 integrity verification' >&2
  exit 1
}
if ! LIBGUESTFS_BACKEND=direct virt-customize -a "$tmpdir/$image_name" --network \
  --install qemu-guest-agent \
  --run-command 'systemctl --root=/ enable qemu-guest-agent.service'; then
  echo 'could not prepare Debian base image with qemu-guest-agent; check DHCP and DNS in the libguestfs appliance and access to Debian package mirrors; VM was not started' >&2
  exit 1
fi
verify_prepared_image "$tmpdir/$image_name" || {
  echo 'Debian base image failed QCOW2 integrity verification after guest-agent setup' >&2
  exit 1
}
chmod 0600 "$tmpdir/$image_name"
ln "$tmpdir/$image_name" "$destination"
