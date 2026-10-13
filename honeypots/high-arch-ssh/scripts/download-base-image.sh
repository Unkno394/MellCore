#!/bin/sh
set -eu

destination=${1:?destination path is required}
default_url='https://geo.mirror.pkgbuild.com/images/v20261001.604814/Arch-Linux-x86_64-cloudimg-20261001.604814.qcow2'
default_sha256='360f0fa49db6813bdc8e35bed230a2dc2ae3567b7b5ab74719c0a706e4e34e87'
image_url=${HF_HIGH_ARCH_IMAGE_URL:-$default_url}
expected=${HF_HIGH_ARCH_IMAGE_SHA256:-$default_sha256}
case "$image_url" in https://*) ;; *) echo 'Arch image URL must use HTTPS' >&2; exit 1 ;; esac
printf '%s' "$expected" | grep -Eq '^[0-9A-Fa-f]{64}$' || { echo 'Arch image SHA-256 is invalid' >&2; exit 1; }
expected=$(printf '%s' "$expected" | tr 'A-F' 'a-f')
command -v qemu-img >/dev/null

verify_image() {
  candidate=$1
  actual=$(sha256sum "$candidate" | awk '{print $1}')
  [ "$actual" = "$expected" ] || return 1
  [ "$(qemu-img info --output=json "$candidate" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("format", ""))')" = qcow2 ] || {
    echo 'Arch image is not QCOW2' >&2
    return 1
  }
}

if [ -e "$destination" ]; then
  [ -f "$destination" ] && [ ! -L "$destination" ] || {
    echo 'Arch image cache path is not a regular file' >&2
    exit 1
  }
  if verify_image "$destination"; then
    chmod 0600 "$destination"
    exit 0
  fi
  # Never replace a mismatching file in place: existing overlays may still use this exact
  # pathname as their immutable backing image. An operator must investigate it first.
  echo 'cached Arch image verification failed; refusing to replace a possible live backing image' >&2
  exit 1
fi

mkdir -p "$(dirname "$destination")"
tmp=$(mktemp "$(dirname "$destination")/.arch-image.XXXXXX")
trap 'rm -f "$tmp"' EXIT INT TERM
if command -v curl >/dev/null 2>&1; then
  curl --fail --location --proto '=https' --tlsv1.2 --retry 3 --output "$tmp" "$image_url"
else
  wget --https-only --tries=3 -O "$tmp" "$image_url"
fi
verify_image "$tmp" || { echo 'downloaded Arch image verification failed' >&2; exit 1; }
chmod 0600 "$tmp"
mv "$tmp" "$destination"
