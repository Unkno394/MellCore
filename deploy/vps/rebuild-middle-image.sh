#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
artifact_dir=${1:-${MELLCORE_ARTIFACT_DIR:-/root/mellcore-middle-$(date +%Y%m%d-%H%M%S)}}
[[ $EUID -eq 0 ]] || { echo 'Запустите от root.' >&2; exit 1; }
install -d -m 0700 "$artifact_dir"
artifact_dir=$(realpath "$artifact_dir")
docker info >/dev/null

backup_dir=/root/mellcore-artifact-backups/middle-$(date +%Y%m%d-%H%M%S)
install -d -m 0700 "$backup_dir"
if [[ -f $artifact_dir/middle.tar ]]; then
    cp -p "$artifact_dir/middle.tar" "$backup_dir/upload-middle.tar"
fi
if [[ -f /opt/mellcore/artifacts/middle.tar ]]; then
    cp -p /opt/mellcore/artifacts/middle.tar "$backup_dir/installed-middle.tar"
fi

docker build -f "$repo/honeypots/pritvoryashka/Dockerfile" \
    --tag honeyforge-pritvoryashka:local "$repo"
bash "$repo/deploy/vps/check-middle-image.sh" honeyforge-pritvoryashka:local

middle_tmp="$artifact_dir/.middle.tar.$$"
trap 'rm -f "$middle_tmp"' EXIT
docker save --output "$middle_tmp" honeyforge-pritvoryashka:local
test -s "$middle_tmp"
mv -f "$middle_tmp" "$artifact_dir/middle.tar"
trap - EXIT

installed_artifacts=/opt/mellcore/artifacts
if [[ -d $installed_artifacts && -f $installed_artifacts/middle.tar ]]; then
    installed_tmp="$installed_artifacts/.middle.tar.$$"
    install -m 0600 "$artifact_dir/middle.tar" "$installed_tmp"
    mv -f "$installed_tmp" "$installed_artifacts/middle.tar"
    checksum_tmp="$installed_artifacts/.SHA256SUMS.$$"
    sha256sum "$installed_artifacts"/bin/* "$installed_artifacts"/*.tar* > "$checksum_tmp"
    chmod 0600 "$checksum_tmp"
    mv -f "$checksum_tmp" "$installed_artifacts/SHA256SUMS"
fi

echo "Middle image пересобран и проверен. Архив: $artifact_dir/middle.tar; резервная копия: $backup_dir"
