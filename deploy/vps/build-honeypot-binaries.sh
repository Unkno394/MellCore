#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
artifact_dir=${1:-/root/mellcore-honeypot-binaries-$(date +%Y%m%d-%H%M%S)}
[[ $EUID -eq 0 ]] || { echo 'Запустите от root.' >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo 'Не найден Docker Buildx.' >&2; exit 1; }
docker buildx version >/dev/null

install -d -m 0700 "$artifact_dir"
artifact_dir=$(realpath "$artifact_dir")
low_export="$artifact_dir/.low-export"
middle_export="$artifact_dir/.middle-export"
mkdir -p "$low_export" "$middle_export"

docker buildx build \
    --progress=plain \
    --file "$repo/honeypots/kozyavka/Dockerfile" \
    --target binary-artifact \
    --output "type=local,dest=$low_export" \
    "$repo/honeypots/kozyavka"

docker buildx build \
    --progress=plain \
    --file "$repo/honeypots/pritvoryashka/Dockerfile" \
    --target binary-artifact \
    --output "type=local,dest=$middle_export" \
    "$repo"

for pair in "honeyforge-low:$low_export/honeyforge-low" "pritvoryashka:$middle_export/pritvoryashka"; do
    name=${pair%%:*}
    source=${pair#*:}
    [[ -s $source ]] || { echo "Не собран бинарник $name." >&2; exit 1; }
    install -m 0755 "$source" "$artifact_dir/$name"
done

rm -rf "$low_export" "$middle_export"
(cd "$artifact_dir" && sha256sum honeyforge-low pritvoryashka > SHA256SUMS)
tar -czf "$artifact_dir/honeypot-binaries.tar.gz" \
    -C "$artifact_dir" honeyforge-low pritvoryashka SHA256SUMS

echo "Бинарники собраны из builder stages; runtime-образы не собирались."
echo "Low:    $artifact_dir/honeyforge-low"
echo "Middle: $artifact_dir/pritvoryashka"
echo "Архив:  $artifact_dir/honeypot-binaries.tar.gz"
