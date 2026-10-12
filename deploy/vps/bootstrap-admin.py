#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess

config = json.loads(Path('/etc/honeyforge/mellcore-secrets.json').read_text())
query = subprocess.run([
    'docker', 'exec', 'mellcore-vps-postgres-1', 'psql', '-U', 'honeyforge', '-d', 'honeyforge', '-Atc',
    "SELECT COUNT(*) FROM users WHERE role='admin'"
], check=True, text=True, capture_output=True)
if int(query.stdout.strip()) == 0:
    env = dict(os.environ, BOOTSTRAP_USERNAME='admin', BOOTSTRAP_EMAIL=config['admin_email'],
               BOOTSTRAP_PASSWORD=config['admin_password'])
    subprocess.run(['/usr/local/bin/honeyforge-backend', 'bootstrap-admin'], env=env, check=True)
