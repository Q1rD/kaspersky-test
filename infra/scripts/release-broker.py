#!/usr/bin/env python3
"""Socket-activated, fixed-operation root worker. Deploy has no shell/root API."""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import socket
import struct
import subprocess
import tempfile

ROOT = Path('/var/lib/threat-service/releases')
CONFIG = Path('/etc/threat-service')
ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root'}
ID = re.compile(r'[a-f0-9]{64}')
DIGEST = re.compile(r'(?:[a-z0-9][a-z0-9./:_-]*@)?sha256:[a-f0-9]{64}')


def run(args, *, env=None, timeout=300):
    result = subprocess.run(args, env=env or ENV, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=timeout)
    if result.returncode:
        # Logs contain fixed commands only, never secret material or environment.
        print(result.stdout.decode(errors='replace')[-8000:], file=__import__('sys').stderr)
        raise ValueError('fixed worker command failed')
    return result.stdout


def atomic(path, data):
    temp = path.with_suffix(path.suffix + '.new')
    with temp.open('w') as f:
        json.dump(data, f, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    temp.replace(path)
    fd = os.open(path.parent, os.O_DIRECTORY)
    os.fsync(fd)
    os.close(fd)


def validate_manifest(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate manifest key')
            result[key] = value
        return result
    manifest = json.loads(raw, object_pairs_hook=unique)
    if set(manifest) != {'schema', 'version', 'images'} or manifest['schema'] != 1:
        raise ValueError('invalid manifest schema')
    if type(manifest['version']) is not int or not 0 < manifest['version'] < 2**53:
        raise ValueError('invalid release version')
    if set(manifest['images']) != {'api', 'caddy', 'postgres'}:
        raise ValueError('invalid images')
    policy = json.loads((CONFIG / 'deploy.json').read_text())
    for name, image in manifest['images'].items():
        if not isinstance(image, str) or not DIGEST.fullmatch(image):
            raise ValueError('image must be pinned by digest')
        if image.startswith('sha256:'):
            if not policy['allow_local_image_ids']:
                raise ValueError('local image IDs disabled')
        elif image.split('@')[0] != policy['repositories'][name]:
            raise ValueError('repository outside allowlist')
    return manifest


def compose(images, *args):
    policy = json.loads((CONFIG / 'deploy.json').read_text())
    env = dict(ENV, API_IMAGE=images['api'], CADDY_IMAGE=images['caddy'],
               POSTGRES_IMAGE=images['postgres'], SITE_ADDRESS=policy['site_address'],
               TLS_DIRECTIVE='tls internal' if policy['local_tls'] else '',
               ARCHIVE_MODE='on' if policy.get('archive_enabled', True) else 'off')
    return run(['/usr/bin/docker', 'compose', '-f', str(CONFIG / 'compose.yml'), *args], env=env)


def deploy(release_id):
    manifest = json.loads((ROOT / (release_id + '.json')).read_text())
    current_path = ROOT / 'current.json'
    current = json.loads(current_path.read_text()) if current_path.exists() else None
    if current and manifest['version'] < current['version']:
        raise ValueError('release rollback requires a new signed version')
    if current and manifest['version'] == current['version'] and release_id != current['id']:
        raise ValueError('release version reused')
    transaction = {'id': release_id, 'version': manifest['version'], 'phase': 'images'}
    atomic(ROOT / 'pending.json', transaction)
    for image in manifest['images'].values():
        if image.startswith('sha256:'):
            run(['/usr/bin/docker', 'image', 'inspect', image])
        else:
            run(['/usr/bin/docker', 'pull', image])
    images = manifest['images']
    compose(images, 'config', '--quiet')
    transaction['phase'] = 'database'
    atomic(ROOT / 'pending.json', transaction)
    compose(images, 'up', '-d', '--wait', '--wait-timeout', '90', 'postgres')
    policy = json.loads((CONFIG / 'deploy.json').read_text())
    if policy.get('archive_enabled', True):
        compose(images, '--profile', 'tools', 'run', '--rm', '--no-deps', 'backup', '--stanza=main', 'stanza-create')
    transaction['phase'] = 'migration'
    atomic(ROOT / 'pending.json', transaction)
    compose(images, '--profile', 'tools', 'run', '--rm', '--no-deps', 'migrate')
    transaction['phase'] = 'application'
    atomic(ROOT / 'pending.json', transaction)
    compose(images, 'up', '-d', '--wait', '--wait-timeout', '90', 'api', 'caddy')
    # API readiness is checked by Docker, TLS by local curl using Caddy's CA for lab.
    policy = json.loads((CONFIG / 'deploy.json').read_text())
    args = ['/usr/bin/curl', '--fail', '--silent', '--show-error', '--max-time', '10']
    if policy['local_tls']:
        args += ['--cacert', '/var/lib/threat-service/caddy/caddy/pki/authorities/local/root.crt']
    args += ['--resolve', policy['site_address'] + ':443:127.0.0.1',
             'https://' + policy['site_address'] + '/health/ready']
    run(args)
    atomic(current_path, {'id': release_id, 'version': manifest['version'], 'images': images})
    run(['/usr/bin/systemctl', 'start', 'threat-stack.service'])
    transaction['phase'] = 'complete'
    atomic(ROOT / 'pending.json', transaction)
    return transaction


def request(data):
    action = data.get('action')
    if action == 'install' and set(data) == {'action', 'manifest', 'signature'}:
        raw = base64.b64decode(data['manifest'], validate=True)
        signature = base64.b64decode(data['signature'], validate=True)
        if len(raw) > 8192 or len(signature) != 64:
            raise ValueError('invalid signature envelope')
        with tempfile.TemporaryDirectory(prefix='threat-signature-') as directory:
            path = Path(directory)
            (path / 'manifest').write_bytes(raw)
            (path / 'signature').write_bytes(signature)
            run(['/usr/bin/openssl', 'pkeyutl', '-verify', '-pubin', '-inkey',
                 str(CONFIG / 'release-signing.pub'), '-rawin', '-in', str(path / 'manifest'),
                 '-sigfile', str(path / 'signature')])
        manifest = validate_manifest(raw)
        release_id = hashlib.sha256(raw).hexdigest()
        atomic(ROOT / (release_id + '.json'), manifest)
        return {'id': release_id, 'version': manifest['version']}
    if action in {'plan', 'deploy', 'resume'} and set(data) == {'action', 'id'}:
        release_id = data['id']
        if not isinstance(release_id, str) or not ID.fullmatch(release_id):
            raise ValueError('invalid release id')
        if not (ROOT / (release_id + '.json')).is_file():
            raise ValueError('release not installed')
        if action == 'plan':
            return json.loads((ROOT / (release_id + '.json')).read_text())
        return deploy(release_id)
    raise ValueError('unsupported request')


def main():
    os.umask(0o077)
    connection = socket.socket(fileno=0)
    connection.settimeout(15)
    _, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if uid != pwd.getpwnam('threat-deploy').pw_uid:
        raise ValueError('peer is not threat-deploy')
    buffer = bytearray()
    while True:
        part = connection.recv(16385 - len(buffer))
        if not part:
            break
        buffer.extend(part)
        if len(buffer) > 16384:
            raise ValueError('request too large')
    try:
        with open('/run/lock/threat-release.lock', 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            response = {'ok': True, 'result': request(json.loads(buffer))}
    except Exception as error:
        print(type(error).__name__ + ': ' + str(error), file=__import__('sys').stderr)
        response = {'ok': False, 'error': 'request rejected or worker failed; see broker journal'}
    connection.sendall(json.dumps(response).encode() + b'\n')

if __name__ == '__main__':
    main()
