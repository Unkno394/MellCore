#!/usr/bin/env bash
set -euo pipefail
umask 077
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
artifact_dir=${1:-${MELLCORE_ARTIFACT_DIR:-}}
if [[ -z $artifact_dir ]]; then
    shopt -s nullglob
    candidates=(/root/mellcore-upload-*)
    shopt -u nullglob
    ((${#candidates[@]} == 1)) || {
        echo 'Передайте путь к каталогу артефактов первым аргументом.' >&2
        exit 1
    }
    artifact_dir=${candidates[0]}
fi
artifact_dir=$(realpath "$artifact_dir")
[[ $EUID -eq 0 ]] || { echo 'Запустите от root.' >&2; exit 1; }
[[ -f $artifact_dir/low.tar && -f $artifact_dir/middle.tar ]] || {
    echo 'В каталоге не найдены low.tar и middle.tar.' >&2
    exit 1
}
docker info >/dev/null
docker build -f "$repo/deploy/vps/Dockerfile.host-binaries" \
    --tag mellcore-host-binaries:local "$repo"
container=$(docker create mellcore-host-binaries:local /artifacts/hf-center --help)
backup_dir=/root/mellcore-artifact-backups/$(date +%Y%m%d-%H%M%S)
install -d -m 0700 "$backup_dir"
cp -p "$artifact_dir/bin/hf-center" "$backup_dir/hf-center"
cp -p "$artifact_dir/bin/hf-agent" "$backup_dir/hf-agent"
docker cp "$container:/artifacts/hf-center" "$artifact_dir/bin/hf-center"
docker cp "$container:/artifacts/hf-agent" "$artifact_dir/bin/hf-agent"
docker rm "$container" >/dev/null
chmod 0755 "$artifact_dir/bin/hf-center" "$artifact_dir/bin/hf-agent"
python3 "$repo/deploy/vps/validate-artifacts.py" "$artifact_dir"
echo "Обновлены hf-center и hf-agent; предыдущие файлы сохранены в $backup_dir"
