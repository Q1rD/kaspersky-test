#!/usr/bin/env python3
"""Trusted builder signs immutable image identities; deploy never has this key."""
import argparse
import json
from pathlib import Path
import subprocess
import time
p = argparse.ArgumentParser()
p.add_argument('--key', required=True)
p.add_argument('--out', required=True)
p.add_argument('--version', type=int, default=int(time.time()))
p.add_argument('--api', required=True)
p.add_argument('--caddy', required=True)
p.add_argument('--postgres', required=True)
a = p.parse_args()
manifest = {'schema': 1, 'version': a.version, 'images': {'api': a.api, 'caddy': a.caddy, 'postgres': a.postgres}}
path = Path(a.out)
path.write_text(json.dumps(manifest, sort_keys=True, separators=(',', ':')))
subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', a.key, '-rawin', '-in', str(path), '-out', str(path) + '.sig'], check=True)
print('Signed release: ' + str(path))
