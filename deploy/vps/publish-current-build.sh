#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
images=${1:?Usage: publish-current-build.sh /root/mellcore-trap-images-YYYYMMDD}
[[ $EUID -eq 0 ]] || { echo 'Запустите от root на центральном сервере.' >&2; exit 1; }

for binary in \
    "$repo/target/release/hf-center" \
    "$repo/target/release/hf-agent" \
    "$repo/target/release/hf-dispatcher" \
    "$repo/backend/target/release/honeyforge-backend"; do
    [[ -s $binary && -x $binary ]] || { echo "Не найден Cargo-бинарник: $binary" >&2; exit 1; }
done
[[ -s $repo/frontend/dist/index.html ]] || { echo 'Сначала соберите frontend: npm run build в frontend/.' >&2; exit 1; }
[[ -d /opt/mellcore/artifacts && -s /etc/honeyforge/center.env ]] || {
    echo 'Не найдены установленные артефакты Центра или /etc/honeyforge/center.env.' >&2
    exit 1
}
grep -Fxq 'HF_KOZYAVKA_IMAGE_ARCHIVE=/opt/mellcore/artifacts/low.tar' /etc/honeyforge/center.env
grep -Fxq 'HF_PRITVORYASHKA_IMAGE_ARCHIVE=/opt/mellcore/artifacts/middle.tar' /etc/honeyforge/center.env
for name in low.tar middle.tar SHA256SUMS; do
    [[ -s $images/$name ]] || { echo "Не найден артефакт: $images/$name" >&2; exit 1; }
done
(cd "$images" && sha256sum --check SHA256SUMS)

install -m 0755 "$repo/target/release/hf-center" /tmp/hf-center
install -m 0755 "$repo/target/release/hf-agent" /tmp/hf-agent
install -m 0755 "$repo/target/release/hf-dispatcher" /tmp/hf-dispatcher
install -m 0755 "$repo/backend/target/release/honeyforge-backend" /tmp/honeyforge-backend
tar -czf /tmp/mellcore-frontend-dist.tar.gz -C "$repo/frontend/dist" .

echo 'Устанавливаю бинарники и frontend; сервисы Центра будут перезапущены.'
bash "$repo/deploy/vps/deploy-uploaded-artifacts.sh"

echo 'Публикую Low/Middle для bootstrap новых агентов и архив Middle для обновления.'
bash "$repo/deploy/vps/publish-middle-image-update.sh" "$images"

echo 'Проверяю, что bootstrap-хранилище содержит те же образы.'
cmp -s "$images/low.tar" /opt/mellcore/artifacts/low.tar
cmp -s "$images/middle.tar" /opt/mellcore/artifacts/middle.tar
echo 'Bootstrap archives match the built Low and Middle images.'

release=$(readlink -f /var/www/mellcore/current)
[[ -s $release/index.html && -s $release/downloads/mellcore-middle-agent-update.tar.gz ]] || {
    echo 'Frontend release или Middle update не найден в активной раздаче.' >&2
    exit 1
}
echo "Активный релиз: $release"
echo "Middle update: https://yourpasswordforemail.ru/downloads/mellcore-middle-agent-update.tar.gz"
