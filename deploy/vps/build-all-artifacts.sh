#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
middle_archive=''
if [[ ${1:-} == --skip-middle ]]; then
    [[ -s ${2:-} ]] || {
        echo 'Для --skip-middle укажите существующий middle.tar.' >&2
        exit 1
    }
    middle_archive=$(realpath "$2")
    artifact_dir=${3:-/root/mellcore-upload-$(date +%Y%m%d-%H%M%S)}
else
    artifact_dir=${1:-/root/mellcore-upload-$(date +%Y%m%d-%H%M%S)}
fi
[[ $EUID -eq 0 ]] || { echo 'Запустите от root.' >&2; exit 1; }
[[ ! -e $artifact_dir ]] || { echo "Каталог уже существует: $artifact_dir" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo 'Установите Docker.' >&2; exit 1; }
command -v npm >/dev/null 2>&1 || { echo 'Установите Node.js и npm для сборки frontend.' >&2; exit 1; }
docker info >/dev/null

mkdir -m 0700 -p "$artifact_dir"
container=''
cleanup() {
    if [[ -n $container ]]; then docker rm -f "$container" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

# Build Rust binaries and the High recipe inside Debian Bookworm. Tests are
# opt-in; this artifact command compiles the release binaries only.
docker build -f "$repo/deploy/vps/Dockerfile" --target artifacts \
    --build-arg RUN_BUILD_TESTS=false --tag mellcore-build-artifacts:local "$repo"
container=$(docker create mellcore-build-artifacts:local)
docker cp "$container:/artifacts/." "$artifact_dir/"
docker rm "$container" >/dev/null
container=''

docker build -f "$repo/deploy/vps/Dockerfile" --target low \
    --build-arg RUN_BUILD_TESTS=false --tag honeyforge-low:local "$repo"
docker save --output "$artifact_dir/low.tar" honeyforge-low:local

if [[ -n $middle_archive ]]; then
    cp -p "$middle_archive" "$artifact_dir/middle.tar"
    echo "Middle image оставлен без пересборки: $middle_archive"
else
    docker build -f "$repo/deploy/vps/Dockerfile" --target middle \
        --build-arg RUN_BUILD_TESTS=false --tag honeyforge-pritvoryashka:local "$repo"
    bash "$repo/deploy/vps/check-middle-image.sh" honeyforge-pritvoryashka:local
    docker save --output "$artifact_dir/middle.tar" honeyforge-pritvoryashka:local
fi

(cd "$repo/frontend" && npm ci && npm run build)
tar -czf "$artifact_dir/mellcore-frontend-dist.tar.gz" -C "$repo/frontend/dist" .

python3 "$repo/deploy/vps/validate-artifacts.py" "$artifact_dir"
(cd "$artifact_dir" && sha256sum bin/* low.tar middle.tar hf-high-ubuntu-ssh.tar.gz \
    mellcore-frontend-dist.tar.gz > SHA256SUMS)
chmod 0600 "$artifact_dir/SHA256SUMS"
echo "Полная сборка готова: $artifact_dir"
