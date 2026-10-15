#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

bundle_dir=${1:-/tmp/mellcore-middle-binary-update}
state_dir=${HF_STATE_DIR:-}
trap_root=${HF_TRAP_ROOT:-}
if [[ -r /etc/honeyforge/agent.env ]]; then
    if [[ -z $state_dir ]]; then
        state_dir=$(awk -F= '$1 == "HF_STATE_DIR" { sub(/^[^=]*=/, ""); gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; exit }' /etc/honeyforge/agent.env)
    fi
    if [[ -z $trap_root ]]; then
        trap_root=$(awk -F= '$1 == "HF_TRAP_ROOT" { sub(/^[^=]*=/, ""); gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; exit }' /etc/honeyforge/agent.env)
    fi
    if [[ -z ${HF_TELEMETRY_INGEST_TOKEN:-} ]]; then
        telemetry_token=$(awk -F= '$1 == "HF_TELEMETRY_INGEST_TOKEN" { sub(/^[^=]*=/, ""); print; exit }' /etc/honeyforge/agent.env)
        [[ -z $telemetry_token ]] || export HF_TELEMETRY_INGEST_TOKEN=$telemetry_token
    fi
fi
state_dir=${state_dir:-/var/lib/honeyforge}
trap_root=${trap_root:-$state_dir/traps}

[[ $EUID -eq 0 ]] || { echo 'Запусти скрипт от root на сервере агента.' >&2; exit 1; }
[[ -d $bundle_dir ]] || { echo "Не найден пакет Middle: $bundle_dir" >&2; exit 1; }
bundle_dir=$(realpath "$bundle_dir")
for file in pritvoryashka docker-entrypoint.sh config-schema-probe.json; do
    [[ -s $bundle_dir/$file ]] || { echo "Не найден файл: $bundle_dir/$file" >&2; exit 1; }
done
if [[ -s $bundle_dir/SHA256SUMS ]]; then
    (cd "$bundle_dir" && sha256sum --check SHA256SUMS)
fi
command -v docker >/dev/null 2>&1 || { echo 'Не найден Docker.' >&2; exit 1; }
docker info >/dev/null

middle_compose=()
middle_images=(honeyforge-pritvoryashka:local)
declare -A seen_images=()
declare -A seen_compose=()
declare -A compose_projects=()
seen_images["honeyforge-pritvoryashka:local"]=1
add_middle_compose() {
    local compose=$1 project=${2:-} compose_image
    [[ -f $compose ]] || return 1
    compose=$(realpath "$compose")
    if [[ -n ${seen_compose[$compose]+present} ]]; then
        [[ -z $project ]] || compose_projects[$compose]=$project
        return 0
    fi
    compose_image=$(awk '$1 == "image:" { gsub(/["\047]/, "", $2); if ($2 ~ /(^|\/)honeyforge-pritvoryashka(:|$)/) { print $2; exit } }' "$compose")
    [[ -n $compose_image ]] || return 1
    middle_compose+=("$compose")
    seen_compose[$compose]=1
    [[ -z $project ]] || compose_projects[$compose]=$project
    if [[ -z ${seen_images[$compose_image]+present} ]]; then
        middle_images+=("$compose_image")
        seen_images[$compose_image]=1
    fi
}
while IFS= read -r -d '' compose; do
    add_middle_compose "$compose" || true
done < <(if [[ -d $trap_root ]]; then find -L "$trap_root" -type f \( -name compose.yaml -o -name compose.yml -o -name docker-compose.yaml -o -name docker-compose.yml \) -print0; fi)

# Compose labels point to the actual project file even when HF_STATE_DIR differs
# from the path guessed by the update script.
while IFS= read -r container_id; do
    [[ -n $container_id ]] || continue
    container_image=$(docker inspect --format '{{.Config.Image}}' "$container_id" 2>/dev/null || true)
    project=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$container_id" 2>/dev/null || true)
    [[ $container_image == *pritvoryashka* && $project == hf-* ]] || continue
    compose_files=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project.config_files"}}' "$container_id" 2>/dev/null || true)
    found_compose=0
    IFS=',' read -r -a files <<< "$compose_files"
    for compose in "${files[@]}"; do
        if add_middle_compose "$compose" "$project"; then found_compose=1; fi
    done
    if (( ! found_compose )); then
        echo "Middle-контейнер $container_id ($container_image) найден, но его Compose-файл недоступен: $compose_files" >&2
        exit 1
    fi
done < <(docker ps -aq)

if (( ${#middle_compose[@]} == 0 )); then
    echo "Middle Compose-проекты под $trap_root не найдены; обновлю honeyforge-pritvoryashka:local для следующих запусков."
fi

middle_image_ids=()
for middle_image in "${middle_images[@]}"; do
    old_id=$(docker image inspect --format '{{.Id}}' "$middle_image" 2>/dev/null || true)
    if [[ -z $old_id && $middle_image != honeyforge-pritvoryashka:local ]]; then
        echo "Образ из Compose не найден локально: $middle_image" >&2
        exit 1
    fi
    middle_image_ids+=("$old_id")
done

stamp=$(date +%Y%m%d%H%M%S)
build_image="honeyforge-pritvoryashka:binary-update-$stamp"
work_dir=$(mktemp -d /tmp/hf-middle-binary-update.XXXXXX)
cleanup() {
    docker image rm "$build_image" >/dev/null 2>&1 || true
    rm -rf "$work_dir"
}
trap cleanup EXIT

install -m 0755 "$bundle_dir/pritvoryashka" "$work_dir/pritvoryashka"
install -m 0755 "$bundle_dir/docker-entrypoint.sh" "$work_dir/docker-entrypoint.sh"
install -m 0644 "$bundle_dir/config-schema-probe.json" "$work_dir/config-schema-probe.json"
cat > "$work_dir/Dockerfile" <<'DOCKERFILE'
FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client ca-certificates wget \
    && wget -q https://packages.microsoft.com/config/debian/13/packages-microsoft-prod.deb -O /tmp/packages-microsoft-prod.deb \
    && dpkg -i /tmp/packages-microsoft-prod.deb \
    && apt-get update \
    && apt-get install -y --no-install-recommends powershell \
    && rm -f /tmp/packages-microsoft-prod.deb \
    && rm -rf /var/lib/apt/lists/*
COPY pritvoryashka /usr/local/bin/pritvoryashka
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint
COPY config-schema-probe.json /tmp/hf-middle-config-schema-probe.json
RUN chmod 0755 /usr/local/bin/pritvoryashka /usr/local/bin/docker-entrypoint \
    && /usr/local/bin/pritvoryashka --check-config /tmp/hf-middle-config-schema-probe.json \
    && /usr/local/bin/pritvoryashka --check-windows-parser \
    && rm -f /tmp/hf-middle-config-schema-probe.json
ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
CMD ["/etc/honeyforge/pritvoryashka.json"]
DOCKERFILE

docker build --file "$work_dir/Dockerfile" --tag "$build_image" "$work_dir"
rollback_images=()
for index in "${!middle_images[@]}"; do
    middle_image=${middle_images[$index]}
    old_id=${middle_image_ids[$index]}
    if [[ -z $old_id ]]; then
        rollback_images+=("")
        docker tag "$build_image" "$middle_image"
        continue
    fi
    image_repo=$middle_image
    image_last_component=${middle_image##*/}
    if [[ $image_last_component == *:* ]]; then
        image_repo=${middle_image%:*}
    fi
    rollback_image="$image_repo:rollback-$stamp-$index"
    rollback_images+=("$rollback_image")
    docker tag "$old_id" "$rollback_image"
    docker tag "$build_image" "$middle_image"
    echo "Прежний $middle_image сохранён как $rollback_image"
done

failed=0
recreate_middle() {
    local compose=$1 trap_id project container_id state logs
    trap_id=$(basename -- "$(dirname -- "$compose")")
    project=${compose_projects[$compose]:-hf-${trap_id//-/}}
    if ! docker compose --project-name "$project" --file "$compose" up -d --force-recreate; then
        echo "Не удалось пересоздать Middle: $compose" >&2
        failed=1
        return
    fi
    container_id=$(docker compose --project-name "$project" --file "$compose" ps --all -q honeypot | head -n 1) || true
    if [[ -z $container_id ]]; then
        echo "Контейнер honeypot не найден после запуска: $compose" >&2
        failed=1
        return
    fi
    sleep 2
    state=$(docker inspect --format '{{.State.Status}}' "$container_id" 2>/dev/null || true)
    logs=$(docker logs --tail 50 --timestamps "$container_id" 2>&1 || true)
    printf '%s\n' "$logs"
    if [[ $state != running ]] || grep -Fq 'unknown field' <<<"$logs"; then
        echo "Middle не прошёл проверку запуска: $compose ($state)" >&2
        failed=1
    fi
}

for compose in "${middle_compose[@]}"; do recreate_middle "$compose"; done
if (( failed )); then
    echo 'Возвращаю прежний Middle image и пересоздаю контейнеры.' >&2
    for index in "${!middle_images[@]}"; do
        if [[ -n ${middle_image_ids[$index]} ]]; then
            docker tag "${rollback_images[$index]}" "${middle_images[$index]}"
        else
            docker image rm "${middle_images[$index]}" >/dev/null 2>&1 || true
        fi
    done
    for compose in "${middle_compose[@]}"; do
        trap_id=$(basename -- "$(dirname -- "$compose")")
        project=${compose_projects[$compose]:-hf-${trap_id//-/}}
        docker compose --project-name "$project" --file "$compose" up -d --force-recreate || true
    done
    exit 1
fi

echo "Middle обновлён и проверен; пересоздано контейнеров: ${#middle_compose[@]}."
echo "Старые образы сохранены под rollback-тегами. hf-agent и остальные ловушки не перезапускались."
