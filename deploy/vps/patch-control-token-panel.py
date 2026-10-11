#!/usr/bin/env python3
"""Remove manual Control token entry and configure nginx to inject it server-side."""
import json
import sys
from pathlib import Path


def replace_once(path: Path, old: str, new: str) -> None:
    content = path.read_text()
    if new in content:
        return
    if old not in content:
        raise SystemExit(f"Не найден ожидаемый фрагмент в {path}; файл оставлен без изменений.")
    path.write_text(content.replace(old, new, 1))


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"Использование: {sys.argv[0]} /путь/к/MellCore")
    repo = Path(sys.argv[1]).expanduser().resolve()
    panel = repo / "deploy/dev-panel/index.html"
    installer = repo / "deploy/vps/install.sh"
    if not panel.is_file() or not installer.is_file():
        raise SystemExit(f"Не найден MellCore в {repo}")

    replace_once(
        panel,
        '<p class="hint">После bootstrap подожди пока агент зарегистрируется. Для dev control-plane введи <code>HF_CONTROL_TOKEN</code>; он не сохраняется.</p>',
        '<p class="hint">После bootstrap подожди пока агент зарегистрируется, затем выбери уровень ловушки и порт.</p>',
    )
    replace_once(
        panel,
        '        <label>Control token<input id="control-token" type="password" required></label>\n',
        "",
    )
    replace_once(
        panel,
        "headers:{'content-type':'application/json','x-honeyforge-control-token':$('control-token').value}",
        "headers:{'content-type':'application/json'}",
    )

    injector = '''python3 - <<'PY'
import json
from pathlib import Path

secrets = json.loads(Path('/etc/honeyforge/mellcore-secrets.json').read_text())
token = secrets['control_token']
if not token or any(ch not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for ch in token):
    raise SystemExit('Некорректный control token')
snippet = Path('/etc/nginx/snippets/mellcore-control-token.conf')
snippet.parent.mkdir(parents=True, exist_ok=True)
temporary = snippet.with_suffix('.conf.tmp')
temporary.write_text(f'proxy_set_header X-Honeyforge-Control-Token {token};\\n')
temporary.chmod(0o600)
temporary.replace(snippet)
PY
'''
    replace_once(
        installer,
        'python3 "$repo/deploy/vps/configure.py"\n',
        'python3 "$repo/deploy/vps/configure.py"\n' + injector,
    )
    replace_once(
        installer,
        '    location / {\n        proxy_pass http://127.0.0.1:18081;\n',
        '    location / {\n        proxy_pass http://127.0.0.1:18081;\n'
        '        include /etc/nginx/snippets/mellcore-control-token.conf;\n',
    )
    readme = repo / "deploy/vps/README.md"
    if readme.is_file():
        replace_once(
            readme,
            '* nginx: HTTPS/TCP 443 на том же домене, операторская панель защищена HTTP Basic.\n',
            '* nginx: HTTPS/TCP 443 на том же домене, операторская панель защищена HTTP Basic. Control token\n'
            '  хранится на VPS и автоматически передаётся nginx центру для команд панели; оператор его не вводит.\n',
        )
    print("Готово: панель больше не просит Control token; nginx передаст его центру автоматически.")


if __name__ == "__main__":
    main()
