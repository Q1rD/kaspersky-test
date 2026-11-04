#!/usr/bin/env python3
"""Local health evidence; external alerting is a deployment-specific integration."""
import json
from pathlib import Path
import shutil
import subprocess
import time
failures = []
containers = json.loads(subprocess.check_output(['docker', 'inspect', 'threat-postgres-1', 'threat-api-1', 'threat-caddy-1']))
for container in containers:
    state = container['State']
    if not state['Running'] or state.get('Health', {}).get('Status', 'healthy') != 'healthy':
        failures.append(container['Name'] + ' not healthy')
archive_failed = subprocess.check_output(['docker', 'exec', 'threat-postgres-1', 'psql', '-U', 'postgres', '-d', 'postgres', '-Atqc', "SELECT COALESCE(last_failed_time > last_archived_time, last_failed_time IS NOT NULL) FROM pg_stat_archiver"]).decode().strip()
if archive_failed != 'f':
    failures.append('WAL archive has an unresolved failure')
space = shutil.disk_usage('/var/lib/threat-service')
if space.free < max(2 * 1024**3, space.total * 0.1):
    failures.append('data disk free space below reserve')
last = Path('/var/lib/threat-service/releases/last-backup.json')
if not last.exists() or time.time() - json.loads(last.read_text())['completed_at'] > 36 * 3600:
    failures.append('successful backup older than 36 hours or absent')
if failures:
    raise SystemExit('; '.join(failures))
print('Containers healthy; disk reserve and backup age are within limits.')
