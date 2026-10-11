#!/usr/bin/env python3
"""Exercise PostgreSQL, HTTPS, authenticated Kazik commands, Dispatcher and telemetry."""
import json
from pathlib import Path
import socket
import ssl
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request
import uuid

CONFIG = Path('/etc/honeyforge')
STATE = Path('/var/lib/honeyforge/mellcore-local-agent')
secrets = json.loads((CONFIG / 'mellcore-secrets.json').read_text())
backend = 'http://127.0.0.1:18080'
token = None


def request(url, body=None, headers=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                 headers={'Content-Type': 'application/json', **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read()
            return json.loads(content) if content else None
    except urllib.error.HTTPError as error:
        # Backend errors contain request IDs, never echo submitted credentials.
        raise RuntimeError(f'{url}: HTTP {error.code}: {error.read().decode()}') from None


def api(path, body=None):
    return request(backend + path, body, {'Authorization': 'Bearer ' + token})


def wait_for(check, description, seconds=120):
    deadline = time.monotonic() + seconds
    last_error = None
    while time.monotonic() < deadline:
        try:
            result = check()
            if result:
                print(description + ': OK', flush=True)
                return result
        except (OSError, RuntimeError, ValueError) as error:
            last_error = error
        time.sleep(2)
    raise RuntimeError(description + ': timeout; ' + str(last_error))


def queue(command):
    result_path = STATE / 'traps' / 'commands' / (command['command_id'] + '.json')
    request(f"http://127.0.0.1:18081/v1/agents/{secrets['agent_id']}/commands", command,
            {'x-honeyforge-control-token': secrets['control_token']})
    def completed():
        if not result_path.exists():
            return None
        result = json.loads(result_path.read_text())
        if not result['success']:
            raise RuntimeError(result['detail'])
        return result
    wait_for(completed, 'Команда через Hysteria: ' + command['type'], seconds=180)


def ssh_banner(port):
    with socket.create_connection(('127.0.0.1', port), timeout=5) as connection:
        banner = connection.recv(256)
        if not banner.startswith(b'SSH-2.0-'):
            raise RuntimeError(f'Порт {port}: отсутствует SSH banner')
        return True


def main():
    global token
    wait_for(lambda: request(backend + '/health/ready') is not None, 'Backend + PostgreSQL')
    login = request(backend + '/api/v1/auth/login', {'email': secrets['admin_email'], 'password': secrets['admin_password']})
    token = login['access_token']
    print('Вход backend Admin: OK', flush=True)
    with socket.create_connection(('127.0.0.1', 443), timeout=10) as connection:
        with ssl.create_default_context().wrap_socket(connection, server_hostname=secrets['domain']):
            print('HTTPS: сертификат и домен проверены', flush=True)
    resource_path = CONFIG / 'mellcore-resources.json'
    resources = json.loads(resource_path.read_text()) if resource_path.exists() else {}
    servers = api('/api/v1/servers')['items']
    server = next((server for server in servers if server['name'] == 'MellCore local VPS'), None)
    if server is None:
        server = api('/api/v1/servers', {'name': 'MellCore local VPS', 'host': secrets['domain'],
                     'ssh_user': 'root', 'ssh_port': 22, 'dispatcher_port': 2222, 'settings': {}})
    server_id = server['server_id']
    profiles = api('/api/v1/profiles')['items']
    traps = api('/api/v1/traps?server_id=' + server_id)['items']
    for kind, name, port in [('kozyavka', 'MellCore Low SSH', 31001), ('pritvoryashka', 'MellCore Middle SSH', 31002)]:
        trap = next((trap for trap in traps if trap['name'] == name), None)
        if trap is None:
            profile = next(profile for profile in profiles if profile['honeypot_type'] == kind)
            trap = api('/api/v1/traps', {'server_id': server_id, 'trap': {
                'name': name, 'profile_id': profile['id'], 'config': {}, 'desired_state': 'running',
                'ports': [{'transport': 'tcp', 'host_port': port, 'target_port': 2222, 'route_mode': 'dispatcher_backend'}]
            }})
        resources[kind] = trap['trap_id']
    resources['server_id'] = server_id
    for name in ['low_command', 'middle_command', 'dispatcher_command']:
        resources[name] = str(uuid.uuid4())
    temporary = resource_path.with_suffix('.tmp')
    temporary.write_text(json.dumps(resources, indent=2))
    temporary.chmod(0o600)
    temporary.replace(resource_path)
    queue({'type': 'deploy_kozyavka', 'command_id': resources['low_command'], 'trap_id': resources['kozyavka'],
           'host_port': 31001, 'container_port': 2222, 'banner': 'SSH-2.0-OpenSSH_9.6', 'publish_address': '127.0.0.1'})
    queue({'type': 'deploy_pritvoryashka', 'command_id': resources['middle_command'], 'trap_id': resources['pritvoryashka'],
           'server_id': server_id, 'host_port': 31002, 'publish_address': '127.0.0.1', 'hostname': 'srv-app-01', 'max_connections': 64})
    queue({'type': 'reconcile_tcp_port_group', 'command_id': resources['dispatcher_command'], 'listener_port': 2222,
           'members': [{'trap_id': resources[kind], 'backend_port': port, 'weight': 50, 'trap_kind': kind}
                       for kind, port in [('kozyavka', 31001), ('pritvoryashka', 31002)]]})
    for name, port in [('Low SSH', 31001), ('Middle SSH', 31002), ('Dispatcher SSH', 2222)]:
        wait_for(lambda port=port: ssh_banner(port), name)
    wait_for(lambda: api('/api/v1/traps/' + resources['pritvoryashka'] + '/events')['items'],
             'Middle → HTTPS ingestion → PostgreSQL events', seconds=60)
    def outbox_drained():
        with sqlite3.connect('file:' + str(STATE / 'kazik-outbox.sqlite') + '?mode=ro', uri=True) as database:
            return database.execute('SELECT COUNT(*) FROM kazik_outbox').fetchone()[0] == 0
    wait_for(outbox_drained, 'Ответные ACK через Hysteria: SQLite outbox очищен', seconds=60)
    for service in ['honeyforge-backend', 'hf-center', 'hf-agent', 'hf-hysteria-client', 'hysteria-server', 'hf-dispatcher', 'nginx']:
        subprocess.run(['systemctl', 'is-active', '--quiet', service], check=True)
    print('Все доступные сервисы активны. Секреты в /root/mellcore-access.txt', flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Проверка не завершена: ' + str(error), flush=True)
        subprocess.run(['journalctl', '-u', 'hf-agent', '-u', 'hf-center', '-u', 'hysteria-server', '-n', '50', '--no-pager'])
        raise SystemExit(1)
