#!/usr/bin/env python3
"""Enable Center's backend trap registry and PostgreSQL event mirror."""

import json
import os
import secrets
import shutil
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path


CONFIG = Path('/etc/honeyforge')
BACKUP_ROOT = Path('/root/mellcore-backups')
FILES = (CONFIG / 'mellcore-secrets.json', CONFIG / 'backend.env', CONFIG / 'center.env')


def replace_preserving_metadata(path: Path, content: str) -> None:
    original = path.stat()
    with tempfile.NamedTemporaryFile('w', dir=path.parent, prefix=f'.{path.name}.', delete=False) as temporary:
        temporary.write(content)
        temporary.flush()
        os.fsync(temporary.fileno())
        temporary_path = Path(temporary.name)
    try:
        os.chown(temporary_path, original.st_uid, original.st_gid)
        os.chmod(temporary_path, stat.S_IMODE(original.st_mode))
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def update_env(path: Path, additions: dict[str, str]) -> None:
    lines = path.read_text().splitlines()
    seen = set()
    updated = []
    for line in lines:
        key = line.partition('=')[0] if '=' in line and not line.lstrip().startswith('#') else ''
        if key in additions:
            if key not in seen:
                updated.append(f'{key}={additions[key]}')
                seen.add(key)
        else:
            updated.append(line)
    updated.extend(f'{key}={value}' for key, value in additions.items() if key not in seen)
    replace_preserving_metadata(path, '\n'.join(updated) + '\n')


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit('Run as root on the central VPS')
    for path in FILES:
        if not path.is_file():
            raise SystemExit(f'Missing configuration file: {path}')
    backup = BACKUP_ROOT / ('registry-' + datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S'))
    backup.mkdir(mode=0o700, parents=True)
    for path in FILES:
        shutil.copy2(path, backup / path.name)

    secret_path, backend_path, center_path = FILES
    values = json.loads(secret_path.read_text())
    token = values.get('center_graph_token')
    if not token:
        token = secrets.token_hex(32)
        values['center_graph_token'] = token
        replace_preserving_metadata(secret_path, json.dumps(values, indent=2) + '\n')
    if not isinstance(token, str) or len(token) < 32:
        raise SystemExit('Invalid center_graph_token in existing secrets file')

    update_env(backend_path, {'CENTER_INGEST_TOKEN': token})
    update_env(center_path, {
        'HF_CENTER_REGISTRY_URL': 'http://127.0.0.1:18080/internal/v1/center/traps',
        'HF_CENTER_POSTGRES_TELEMETRY_URL': 'http://127.0.0.1:18080/internal/v1/center/events',
        'HF_CENTER_POSTGRES_TELEMETRY_TOKEN': token,
    })
    print('Center registry and event mirror configured; backup:', backup)
    print('Restart honeyforge-backend, then hf-center to activate it.')


if __name__ == '__main__':
    main()
