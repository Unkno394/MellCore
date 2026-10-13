#!/usr/bin/env python3
"""Reject incomplete, wrong-architecture or incorrectly tagged uploaded artifacts."""
import json
from pathlib import Path, PurePosixPath
import struct
import subprocess
import sys
import tarfile

root = Path(sys.argv[1]).resolve(strict=True)
required = [
    root / 'bin/hf-center', root / 'bin/hf-agent', root / 'bin/hf-dispatcher',
    root / 'bin/honeyforge-backend', root / 'low.tar', root / 'middle.tar',
    root / 'hf-high-ubuntu-ssh.tar.gz',
]
for path in required:
    if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
        raise SystemExit(f'Артефакт отсутствует или недопустим: {path.name}')
for path in required[:4]:
    if not path.stat().st_mode & 0o111:
        raise SystemExit(f'Нет права запуска: {path.name}')
    with path.open('rb') as binary:
        elf = binary.read(20)
    if len(elf) < 20 or elf[:5] != b'\x7fELF\x02' or struct.unpack_from('<H', elf, 18)[0] != 62:
        raise SystemExit(f'{path.name} не является ELF x86-64')

# These switches are part of the repository's host installation. Catch laptop binaries built
# before the matching source changes before replacing any system executable or starting services.
center_help = subprocess.run([str(root / 'bin/hf-center'), '--help'], check=True,
                             capture_output=True, text=True, timeout=10).stdout
if 'HF_CENTER_CREDENTIALS_FILE' not in center_help:
    raise SystemExit('hf-center устарел: соберите его из текущего crates/hf-center и замените бинарник.')
if 'HF_HYSTERIA_STATS_URL' not in center_help:
    raise SystemExit('hf-center устарел: отсутствует отзыв активной Hysteria-сессии.')
agent_binary = (root / 'bin/hf-agent').read_bytes()
if b'HF_TELEMETRY_PUBLIC_ENDPOINT' not in agent_binary or b'HF_TELEMETRY_INGEST_TOKEN' not in agent_binary:
    raise SystemExit('hf-agent устарел: соберите его из текущего crates/hf-agent и замените бинарник.')
if b'final trap telemetry queued before removal' not in agent_binary:
    raise SystemExit('hf-agent устарел: отсутствует безопасное удаление ловушки.')

for filename, tag in [('low.tar', 'honeyforge-low:local'),
                      ('middle.tar', 'honeyforge-pritvoryashka:local')]:
    with tarfile.open(root / filename) as archive:
        try:
            manifest = json.load(archive.extractfile('manifest.json'))
            if len(manifest) != 1 or tag not in manifest[0]['RepoTags']:
                raise ValueError('tag mismatch')
            config = json.load(archive.extractfile(manifest[0]['Config']))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise SystemExit(f'{filename}: некорректный Docker archive: {error}') from None
        if config.get('os') != 'linux' or config.get('architecture') != 'amd64':
            raise SystemExit(f'{filename}: нужен linux/amd64 Docker image')

with tarfile.open(root / 'hf-high-ubuntu-ssh.tar.gz') as archive:
    members = archive.getmembers()
    allowed_roots = ('high-ubuntu-ssh', 'high-arch-ssh', 'high-windows-rdp')
    if not members or any(
        not any(member.name == recipe or member.name.startswith(recipe + '/') for recipe in allowed_roots)
        for member in members
    ) or any(
        member.name.startswith('/') or '..' in PurePosixPath(member.name).parts
        or member.issym() or member.islnk() or not (member.isfile() or member.isdir())
        for member in members
    ):
        raise SystemExit('High archive содержит неожиданные пути или типы файлов')
    required_recipe = {
        'high-ubuntu-ssh/scripts/launch.sh', 'high-ubuntu-ssh/scripts/reset.sh',
        'high-ubuntu-ssh/scripts/create-overlay.sh', 'high-ubuntu-ssh/cloud-init/user-data',
        'high-arch-ssh/scripts/launch.sh', 'high-arch-ssh/scripts/download-base-image.sh',
        'high-arch-ssh/cloud-init/user-data',
        'high-windows-rdp/scripts/launch.sh', 'high-windows-rdp/scripts/download-base-image.sh',
        'high-windows-rdp/autounattend.xml',
    }
    if not required_recipe.issubset({member.name for member in members}):
        raise SystemExit('В High archive отсутствуют файлы recipe')

print(f'Артефакты проверены: {root}')
