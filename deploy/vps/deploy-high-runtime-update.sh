#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Update the High runtime, Center telemetry receiver and all bundled High recipes.
# Run as root on the Center VPS after `cargo build --release --workspace --bins`.

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
artifact_dir=/opt/mellcore/artifacts
install_dir=/usr/local/lib/honeyforge
recipe_names=(high-ubuntu-ssh high-debian-ssh high-arch-ssh high-windows-rdp high-custom-iso hf-image-builder)

[[ $EUID -eq 0 ]] || { echo 'Run this script as root on the Center VPS.' >&2; exit 1; }
command -v systemctl >/dev/null || { echo 'systemctl is required.' >&2; exit 1; }

for service in hf-center.service hf-agent.service; do
    systemctl is-active --quiet "$service" || {
        echo "$service must be active before deployment; no files were changed." >&2
        exit 1
    }
done

for name in hf-agent hf-center; do
    binary="$repo/target/release/$name"
    [[ -s $binary && -x $binary ]] || { echo "Missing release binary: $binary" >&2; exit 1; }
    file "$binary" | grep -q 'ELF 64-bit.*x86-64' || { echo "Expected x86-64 ELF: $binary" >&2; exit 1; }
    if ldd "$binary" | grep -q 'not found'; then
        echo "A shared library required by $name is missing on this VPS." >&2
        exit 1
    fi
    "$binary" --help >/dev/null
done

agent_help=$("$repo/target/release/hf-agent" --help)
grep -Fq -- '--high-acceleration' <<<"$agent_help" || {
    echo 'hf-agent does not expose the High acceleration option.' >&2
    exit 1
}

[[ -d $artifact_dir/bin && -d $install_dir ]] || {
    echo 'MellCore artifact or recipe directory is missing; no files were changed.' >&2
    exit 1
}
for name in hf-agent hf-center; do
    [[ -f /usr/local/bin/$name && -f $artifact_dir/bin/$name ]] || {
        echo "Installed binary or bootstrap artifact is missing: $name" >&2
        exit 1
    }
done
[[ -f $artifact_dir/hf-high-ubuntu-ssh.tar.gz && -f $artifact_dir/SHA256SUMS ]] || {
    echo 'Installed High archive or checksum file is missing.' >&2
    exit 1
}
[[ -f $artifact_dir/low.tar && -f $artifact_dir/middle.tar ]] || {
    echo 'Installed Low/Middle archives are missing; cannot safely refresh artifact checksums.' >&2
    exit 1
}

stamp=$(date +%Y%m%d-%H%M%S)
backup="/root/mellcore-backups/high-runtime-$stamp"
stage=$(mktemp -d "/tmp/mellcore-high-update-$stamp.XXXXXX")
changed=0

cleanup() {
    rm -rf -- "$stage"
}

rollback() {
    local name status=$?
    trap - ERR
    if (( changed )); then
        echo 'Deployment failed; restoring previous binaries and High recipes.' >&2
        for name in hf-agent hf-center; do
            install -m 0755 "$backup/usr-local-bin/$name" "/usr/local/bin/.$name.rollback"
            mv -f "/usr/local/bin/.$name.rollback" "/usr/local/bin/$name"
            install -m 0755 "$backup/artifact-bin/$name" "$artifact_dir/bin/.$name.rollback"
            mv -f "$artifact_dir/bin/.$name.rollback" "$artifact_dir/bin/$name"
        done
        install -m 0644 "$backup/hf-high-ubuntu-ssh.tar.gz" "$artifact_dir/.hf-high-ubuntu-ssh.tar.gz.rollback"
        mv -f "$artifact_dir/.hf-high-ubuntu-ssh.tar.gz.rollback" "$artifact_dir/hf-high-ubuntu-ssh.tar.gz"
        install -m 0600 "$backup/SHA256SUMS" "$artifact_dir/.SHA256SUMS.rollback"
        mv -f "$artifact_dir/.SHA256SUMS.rollback" "$artifact_dir/SHA256SUMS"
        for name in "${recipe_names[@]}"; do
            rm -rf -- "$install_dir/$name"
            if [[ -d $backup/recipes/$name ]]; then
                cp -a "$backup/recipes/$name" "$install_dir/$name"
            fi
        done
        systemctl restart hf-center.service || true
        systemctl restart hf-agent.service || true
        echo "Previous release restored. Backup: $backup" >&2
    fi
    cleanup
    exit "$status"
}
trap rollback ERR
trap cleanup EXIT

mkdir -m 0700 -p "$backup/usr-local-bin" "$backup/artifact-bin" "$backup/recipes"
for name in hf-agent hf-center; do
    cp -a "/usr/local/bin/$name" "$backup/usr-local-bin/$name"
    cp -a "$artifact_dir/bin/$name" "$backup/artifact-bin/$name"
done
cp -a "$artifact_dir/hf-high-ubuntu-ssh.tar.gz" "$backup/"
cp -a "$artifact_dir/SHA256SUMS" "$backup/"
for name in "${recipe_names[@]}"; do
    [[ ! -e $install_dir/$name ]] || cp -a "$install_dir/$name" "$backup/recipes/$name"
done

sh "$repo/honeypots/high-ubuntu-ssh/scripts/package-recipe.sh" "$stage/hf-high-ubuntu-ssh.tar.gz"
python3 - "$stage/hf-high-ubuntu-ssh.tar.gz" <<'PY'
import sys
import tarfile

allowed = {
    'high-ubuntu-ssh', 'high-debian-ssh', 'high-arch-ssh',
    'high-windows-rdp', 'high-custom-iso', 'hf-image-builder',
}
expected = {f'{name}/scripts/launch.sh' for name in allowed if name in {
    'high-ubuntu-ssh', 'high-debian-ssh', 'high-arch-ssh', 'high-windows-rdp'
}}
expected.add('high-ubuntu-ssh/scripts/launch-local.sh')
expected.add('high-custom-iso/scripts/launch-iso.sh')
expected.update({
    'hf-image-builder/hf-image-builder',
    'hf-image-builder/builder.py',
    'hf-image-builder/windows-server-2022.pkr.hcl',
    'hf-image-builder/templates/Autounattend.xml',
    'hf-image-builder/windows/bootstrap.ps1',
    'hf-image-builder/windows/configure.ps1',
    'hf-image-builder/windows/finalize.ps1',
    'hf-image-builder/windows/verify.ps1',
    'high-windows-rdp/scripts/launch-prepared.sh',
    'high-windows-rdp/scripts/ensure-prepared-image.sh',
    'high-windows-rdp/scripts/verify-prepared-image.sh',
    'high-windows-rdp/scripts/publish-service.sh',
    'high-windows-rdp/scripts/unpublish-service.sh',
    'high-windows-rdp/scripts/check-publication.sh',
})
with tarfile.open(sys.argv[1], 'r:gz') as archive:
    members = archive.getmembers()
    names = {member.name for member in members}
    for member in members:
        parts = member.name.split('/')
        if (member.name.startswith('/') or '..' in parts
                or not any(member.name == root or member.name.startswith(root + '/') for root in allowed)
                or not (member.isfile() or member.isdir())):
            raise SystemExit(f'Unsafe High recipe archive member: {member.name}')
    if not expected.issubset(names):
        raise SystemExit('High recipe archive is missing a launch script.')
    builder = next((member for member in members if member.name == 'hf-image-builder/hf-image-builder'), None)
    if builder is None or not builder.mode & 0o111:
        raise SystemExit('High recipe archive is missing an executable Windows image builder.')
PY

mkdir -m 0700 "$stage/extracted"
tar --no-same-owner --no-same-permissions -xzf "$stage/hf-high-ubuntu-ssh.tar.gz" -C "$stage/extracted"
for name in "${recipe_names[@]}"; do
    [[ -d $stage/extracted/$name ]] || { echo "Recipe missing from archive: $name" >&2; exit 1; }
    [[ ! -d $stage/extracted/$name/cloud-init ]] || chmod -R a-w "$stage/extracted/$name/cloud-init"
    [[ ! -d $stage/extracted/$name/scripts ]] || find "$stage/extracted/$name/scripts" -type f -exec chmod 0755 {} +
done
chmod 0755 "$stage/extracted/hf-image-builder/hf-image-builder"

changed=1
for name in hf-agent hf-center; do
    install -m 0755 "$repo/target/release/$name" "/usr/local/bin/.$name.new"
    mv -f "/usr/local/bin/.$name.new" "/usr/local/bin/$name"
    install -m 0755 "$repo/target/release/$name" "$artifact_dir/bin/.$name.new"
    mv -f "$artifact_dir/bin/.$name.new" "$artifact_dir/bin/$name"
done
install -m 0644 "$stage/hf-high-ubuntu-ssh.tar.gz" "$artifact_dir/.hf-high-ubuntu-ssh.tar.gz.new"
mv -f "$artifact_dir/.hf-high-ubuntu-ssh.tar.gz.new" "$artifact_dir/hf-high-ubuntu-ssh.tar.gz"

for name in "${recipe_names[@]}"; do
    rm -rf -- "$install_dir/$name"
    mv "$stage/extracted/$name" "$install_dir/$name"
done

cd "$artifact_dir"
sha256sum bin/* *.tar* > .SHA256SUMS.new
chmod 0600 .SHA256SUMS.new
mv -f .SHA256SUMS.new SHA256SUMS

systemctl restart hf-center.service
systemctl is-active --quiet hf-center.service
systemctl restart hf-agent.service
systemctl is-active --quiet hf-agent.service
ln -sfn /usr/local/bin/hf-agent /usr/local/bin/hf

changed=0
trap - ERR
echo 'High runtime deployed: hf-center, hf-agent, High OS recipes and Windows image builder are active.'
echo "Rollback backup: $backup"
echo 'TCG remains standalone-only; the agent service acceleration setting was not changed.'
