#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

[[ $EUID -eq 0 ]] || { echo 'Запустите от root на центральном сервере.' >&2; exit 1; }
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
images=${1:-/root/mellcore-trap-images-20261014-013500}
[[ -s $images/low.tar && -s $images/middle.tar && -s $images/SHA256SUMS ]] || {
    echo "Не найдены собранные образы Low и Middle: $images" >&2
    exit 1
}
(cd "$images" && sha256sum --check SHA256SUMS)
bash "$repo/deploy/vps/install-trap-images-for-bootstrap.sh" "$images"

release=$(readlink -f /var/www/mellcore/current)
[[ -s $release/index.html ]] || { echo 'Активный frontend release не найден.' >&2; exit 1; }
destination=$release/downloads
install -d -m 0755 "$destination"
work=$(mktemp -d /tmp/mellcore-middle-publish.XXXXXX)
trap 'rm -rf "$work"' EXIT
bundle=$work/mellcore-middle-agent-update
install -d -m 0755 "$bundle"
install -m 0644 "$images/middle.tar" "$bundle/middle.tar"
install -m 0755 "$repo/deploy/vps/update-middle-on-agent.sh" "$bundle/update-middle-on-agent.sh"
install -m 0755 "$repo/deploy/vps/check-middle-image.sh" "$bundle/check-middle-image.sh"
install -m 0644 "$repo/honeypots/pritvoryashka/config-schema-probe.json" "$bundle/config-schema-probe.json"
(cd "$bundle" && sha256sum middle.tar update-middle-on-agent.sh check-middle-image.sh config-schema-probe.json > SHA256SUMS)

filename=mellcore-middle-agent-update.tar.gz
tar -C "$work" -czf "$destination/.$filename.tmp" mellcore-middle-agent-update
chmod 0644 "$destination/.$filename.tmp"
mv "$destination/.$filename.tmp" "$destination/$filename"
echo "Middle update: https://yourpasswordforemail.ru/downloads/$filename"
sha256sum "$destination/$filename"
echo 'На агенте скачайте архив, распакуйте его в /tmp и выполните:'
echo "  curl --fail --location https://yourpasswordforemail.ru/downloads/$filename --output /tmp/$filename"
echo "  tar -xzf /tmp/$filename -C /tmp"
echo '  cd /tmp/mellcore-middle-agent-update && sha256sum --check SHA256SUMS && bash update-middle-on-agent.sh middle.tar'
