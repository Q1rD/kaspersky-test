#!/usr/bin/env python3
"""Unprivileged client; deploy.yml invokes only this bounded socket protocol."""
import argparse
import base64
import json
from pathlib import Path
import socket

p = argparse.ArgumentParser()
p.add_argument('action', choices=['install', 'plan', 'deploy', 'resume'])
p.add_argument('target', help='manifest file for install, otherwise release ID')
p.add_argument('--signature')
a = p.parse_args()
request = {'action': a.action}
if a.action == 'install':
    request.update(manifest=base64.b64encode(Path(a.target).read_bytes()).decode(),
                   signature=base64.b64encode(Path(a.signature).read_bytes()).decode())
else:
    request['id'] = a.target
raw = json.dumps(request).encode()
if len(raw) > 16384:
    raise SystemExit('request too large')
with socket.socket(socket.AF_UNIX) as connection:
    connection.settimeout(600)
    connection.connect('/run/threat-release.sock')
    connection.sendall(raw)
    connection.shutdown(socket.SHUT_WR)
    response = bytearray()
    while part := connection.recv(4096):
        response.extend(part)
        if len(response) > 65536:
            raise SystemExit('response too large')
result = json.loads(response)
print(json.dumps(result))
if not result['ok']:
    raise SystemExit(1)
