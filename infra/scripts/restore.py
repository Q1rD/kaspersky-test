#!/usr/bin/env python3
"""Admin-only restore into an EMPTY data directory; never deletes existing data."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
p = argparse.ArgumentParser()
p.add_argument('--release', required=True)
p.add_argument('--target-name', required=True)
a = p.parse_args()
if not re.fullmatch('[a-f0-9]{64}', a.release) or not re.fullmatch('[a-zA-Z0-9_-]{1,63}', a.target_name):
    raise SystemExit('invalid restore parameters')
root = Path('/var/lib/threat-service/postgres')
if any(root.iterdir()):
    raise SystemExit('refusing restore: data directory is not empty')
policy = json.loads(Path('/etc/threat-service/deploy.json').read_text())
if policy.get('archive_enabled', True):
    raise SystemExit('restore host must disable archive writes until promotion/fencing is approved')
spec = importlib.util.spec_from_file_location('broker', '/usr/local/libexec/threat/release-broker.py')
broker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker)
images = json.loads((broker.ROOT / (a.release + '.json')).read_text())['images']
broker.compose(images, 'create', 'postgres')
subprocess.run(['docker', 'run', '--rm', '--name', 'threat-restore-worker', '--user', '999:999',
 '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--security-opt=apparmor:docker-default',
 '--pids-limit=128', '--memory=512m', '--cpus=1', '--network=threat_egress', '--ip=172.30.40.3',
 '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,uid=999,gid=999,mode=0700',
 '-v', '/var/lib/threat-service/postgres:/var/lib/postgresql/data',
 '-v', '/run/threat-service/pgbackrest.conf:/etc/pgbackrest/pgbackrest.conf:ro',
 '-v', '/etc/threat-service/backup-ca.crt:/etc/ssl/backup-ca.crt:ro',
 '--entrypoint=pgbackrest', images['postgres'], '--stanza=main', '--type=name',
 '--target=' + a.target_name, '--target-action=promote', '--archive-mode=off', 'restore'], check=True)
print('Restore files ready. Deploy the signed release to replay WAL and promote at the named target.')
