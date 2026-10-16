#!/bin/sh
set -eu

# Build an immutable HoneyForge base copy with qemu-guest-agent installed and enabled.
# Verify the upstream payload before making any guest changes.
destination=${1:?destination path is required}
image_name=noble-server-cloudimg-amd64.img
base_url=https://cloud-images.ubuntu.com/noble/current
image_url="$base_url/$image_name"
manifest_url="$base_url/SHA256SUMS"

if [ -f "$destination" ]; then
  qemu-img check -q -f qcow2 "$destination" || {
    echo 'cached HoneyForge Ubuntu image failed QCOW2 integrity verification' >&2
    exit 1
  }
  LIBGUESTFS_BACKEND=direct virt-customize -a "$destination" --no-network \
    --run-command 'test -x /usr/bin/qemu-ga' || {
    echo 'cached HoneyForge Ubuntu image does not contain qemu-guest-agent' >&2
    exit 1
  }
  exit 0
fi

mkdir -p "$(dirname "$destination")"
tmpdir=$(mktemp -d "$(dirname "$destination")/.ubuntu-image.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT INT TERM

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl --fail --location --proto '=https' --tlsv1.2 --retry 3 --output "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget --https-only --tries=3 -O "$2" "$1"
  else
    echo 'curl or wget is required to fetch the Ubuntu cloud image' >&2
    exit 1
  fi
}

fetch "$manifest_url" "$tmpdir/SHA256SUMS"
expected=$(awk -v image="$image_name" '$2 == image || $2 == "*" image { print $1; exit }' "$tmpdir/SHA256SUMS")
[ "${#expected}" -eq 64 ] || { echo 'official SHA256SUMS has no expected image digest' >&2; exit 1; }

fetch "$image_url" "$tmpdir/$image_name"
actual=$(sha256sum "$tmpdir/$image_name" | awk '{print $1}')
[ "$actual" = "$expected" ] || { echo 'Ubuntu cloud image checksum mismatch' >&2; exit 1; }

if ! LIBGUESTFS_BACKEND=direct virt-customize -a "$tmpdir/$image_name" --network \
  --install qemu-guest-agent \
  --run-command 'systemctl --root=/ enable qemu-guest-agent.service'; then
  echo 'could not prepare Ubuntu base image with qemu-guest-agent; check DHCP and DNS in the libguestfs appliance and access to Ubuntu package mirrors; VM was not started' >&2
  exit 1
fi
qemu-img check -q -f qcow2 "$tmpdir/$image_name" || {
  echo 'Ubuntu base image failed QCOW2 integrity verification after guest-agent setup' >&2
  exit 1
}

chmod 0600 "$tmpdir/$image_name"
mv "$tmpdir/$image_name" "$destination"
