#!/usr/bin/env python3
"""Admin/systemd fixed stack actions; not exposed on the deploy socket."""
import importlib.util
import json
from pathlib import Path
import sys
import time
spec = importlib.util.spec_from_file_location('broker', Path(__file__).with_name('release-broker.py'))
broker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker)
current = broker.ROOT / 'current.json'
if not current.exists():
    raise SystemExit(0)
images = json.loads(current.read_text())['images']
action = sys.argv[1]
if action == 'start':
    broker.compose(images, 'up', '-d', '--wait', '--wait-timeout', '120', 'postgres', 'api', 'caddy')
elif action == 'database':
    broker.compose(images, 'up', '-d', '--force-recreate', '--wait', '--wait-timeout', '120', 'postgres')
elif action == 'recreate':
    broker.compose(images, 'up', '-d', '--force-recreate', '--wait', '--wait-timeout', '120', 'api', 'caddy')
elif action == 'stop':
    broker.compose(images, 'stop', '--timeout', '60', 'caddy', 'api', 'postgres')
elif action == 'backup':
    broker.compose(images, '--profile', 'tools', 'run', '--rm', '--no-deps', 'backup', '--stanza=main', 'stanza-create')
    broker.compose(images, '--profile', 'tools', 'run', '--rm', '--no-deps', 'backup', '--stanza=main', '--type=full', 'backup')
    broker.atomic(broker.ROOT / 'last-backup.json', {'completed_at': int(time.time())})
else:
    raise SystemExit('unknown fixed action')
