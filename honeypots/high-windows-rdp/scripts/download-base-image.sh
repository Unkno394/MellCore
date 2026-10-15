#!/bin/sh
set -eu
destination=${1:?destination path is required}
[ -f "$destination" ] && exit 0
image_url=${HF_HIGH_WINDOWS_ISO_URL:?HF_HIGH_WINDOWS_ISO_URL must name approved Windows installation media}
expected=${HF_HIGH_WINDOWS_ISO_SHA256:?HF_HIGH_WINDOWS_ISO_SHA256 must contain approved media SHA-256}
case "$image_url" in https://*) ;; *) echo 'Windows ISO URL must use HTTPS' >&2; exit 1 ;; esac
printf '%s' "$expected" | grep -Eq '^[0-9A-Fa-f]{64}$' || { echo 'Windows ISO SHA-256 is invalid' >&2; exit 1; }
expected=$(printf '%s' "$expected" | tr 'A-F' 'a-f')
mkdir -p "$(dirname "$destination")"
tmp=$(mktemp "$(dirname "$destination")/.windows-iso.XXXXXX")
trap 'rm -f "$tmp"' EXIT INT TERM
if command -v curl >/dev/null 2>&1; then curl --fail --location --proto '=https' --tlsv1.2 --retry 3 --output "$tmp" "$image_url"; else wget --https-only --tries=3 -O "$tmp" "$image_url"; fi
actual=$(sha256sum "$tmp" | awk '{print $1}')
[ "$actual" = "$expected" ] || { echo 'Windows ISO checksum mismatch' >&2; exit 1; }
chmod 0600 "$tmp"; mv "$tmp" "$destination"
