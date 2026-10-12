#!/bin/sh
set -eu

output_dir=${1:?usage: build-package-bundle.sh OUTPUT_DIRECTORY}
command -v apt-get >/dev/null
command -v apt-cache >/dev/null
command -v sha256sum >/dev/null

[ "$(. /etc/os-release && printf '%s' "$ID")" = ubuntu ] || {
  echo 'bundle must be built on Ubuntu' >&2
  exit 1
}
[ "$(. /etc/os-release && printf '%s' "$VERSION_ID")" = 24.04 ] || {
  echo 'bundle must be built on Ubuntu 24.04' >&2
  exit 1
}
[ "$(dpkg --print-architecture)" = amd64 ] || {
  echo 'bundle must be built for amd64' >&2
  exit 1
}

mkdir -p "$output_dir"
output_dir=$(CDPATH= cd -- "$output_dir" && pwd)
[ -z "$(find "$output_dir" -mindepth 1 -maxdepth 1 -print -quit)" ] || {
  echo 'output directory must be empty' >&2
  exit 1
}
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT INT TERM

apt-get update
packages='auditd audispd-plugins qemu-guest-agent'
dependencies=$(apt-cache depends --recurse --no-recommends --no-suggests \
  --no-conflicts --no-breaks --no-replaces --no-enhances $packages |
  sed -n 's/^[[:space:]]*Depends:[[:space:]]*//p' |
  tr -d '<>' |
  sort -u)

cd "$work_dir"
# apt-get download does not install anything on the staging host.
apt-get download $packages $dependencies
dpkg-deb --info ./*.deb >/dev/null
sha256sum ./*.deb | sed 's#  \./#  #' > SHA256SUMS
{
  printf '%s\n' 'ubuntu_release=24.04'
  printf '%s\n' 'architecture=amd64'
  for package in $packages; do
    apt-cache policy "$package" | awk -v package="$package" '/Candidate:/ {print package "=" $2}'
  done
} > VERSIONS

cp ./*.deb SHA256SUMS VERSIONS "$output_dir/"
printf '%s\n' "offline package bundle created in $output_dir"
