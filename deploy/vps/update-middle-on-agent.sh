#!/usr/bin/env bash
set -Eeuo pipefail

[[ $EUID -eq 0 ]] || { echo 'Запусти от root на сервере агента.' >&2; exit 1; }
archive=${1:-/tmp/middle.tar}
image=${2:-honeyforge-pritvoryashka:local}
trap_root=${HF_STATE_DIR:-/var/lib/honeyforge}/traps
[[ -s $archive ]] || { echo "Не найден архив Middle: $archive" >&2; exit 1; }
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
    echo "Образ загружен, но Middle compose-проекты с $image не найдены в $trap_root." >&2
    exit 1
fi
echo "Middle image обновлён; пересоздано контейнеров: $updated"
