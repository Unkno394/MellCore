#!/usr/bin/env bash
set -Eeuo pipefail

[[ $EUID -eq 0 ]] || { echo 'Запусти от root на сервере агента.' >&2; exit 1; }
archive=${1:-/tmp/middle.tar}
image=${2:-honeyforge-pritvoryashka:local}
state_dir=${HF_STATE_DIR:-/var/lib/honeyforge}
if [[ -r /etc/honeyforge/agent.env ]]; then
    configured_state_dir=$(sed -n 's/^HF_STATE_DIR=//p' /etc/honeyforge/agent.env | head -n 1)
    configured_trap_root=$(sed -n 's/^HF_TRAP_ROOT=//p' /etc/honeyforge/agent.env | head -n 1)
    [[ -z $configured_state_dir || -n ${HF_STATE_DIR:-} ]] || state_dir=$configured_state_dir
fi
trap_root=${HF_TRAP_ROOT:-${configured_trap_root:-$state_dir/traps}}
[[ -s $archive ]] || { echo "Не найден архив Middle: $archive" >&2; exit 1; }
bundle_dir=$(cd -- "$(dirname -- "$archive")" && pwd)
if [[ -s $bundle_dir/SHA256SUMS ]]; then
    (cd "$bundle_dir" && sha256sum --check SHA256SUMS)
fi
docker info >/dev/null

old_image_id=$(docker image inspect --format '{{.Id}}' "$image" 2>/dev/null || true)
load_output=$(docker load --input "$archive")
printf '%s\n' "$load_output"
if ! grep -Fq "Loaded image: $image" <<<"$load_output"; then
    echo "Архив не загрузил ожидаемый тег $image; контейнеры не пересоздавались." >&2
    exit 1
fi
if ! bash "$(dirname -- "${BASH_SOURCE[0]}")/check-middle-image.sh" "$image"; then
    if [[ -n $old_image_id ]]; then docker tag "$old_image_id" "$image"; fi
    exit 1
fi

if [[ -n $old_image_id ]]; then
    rollback_tag="${image%:*}:rollback-$(date +%Y%m%d%H%M%S)"
    docker tag "$old_image_id" "$rollback_tag"
    echo "Предыдущий образ сохранён как $rollback_tag"
fi

updated=0
while IFS= read -r -d '' compose; do
    grep -Fq "image: $image" "$compose" || continue
    trap_id=$(basename -- "$(dirname -- "$compose")")
    project_name="hf-${trap_id//-/}"
    docker compose --project-name "$project_name" --file "$compose" up -d --force-recreate
    updated=$((updated + 1))
done < <(find "$trap_root" -mindepth 2 -maxdepth 2 -type f -name compose.yaml -print0 2>/dev/null)

if (( updated == 0 )); then
    echo "Middle image обновлён; действующих Middle-контейнеров в $trap_root нет. Новые ловушки используют этот образ."
    exit 0
fi
echo "Middle image обновлён; пересоздано контейнеров: $updated"
