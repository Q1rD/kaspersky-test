#!/usr/bin/env python3
"""Decrypt only on the host, in memory, and give each workload its own files."""
import json
import os
from pathlib import Path
import re
import subprocess

BASE = Path('/run/threat-service')
CONFIG = Path('/etc/threat-service')

def main():
    os.umask(0o077)
    value = subprocess.run(['/usr/local/bin/sops', '--decrypt', '--output-type', 'json',
                            str(CONFIG / 'secrets.enc.json')], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           env={'PATH': '/usr/bin:/bin', 'SOPS_AGE_KEY_FILE': str(CONFIG / 'age.key')})
    secrets = json.loads(value.stdout)
    expected = {'api_key', 'db_app_password', 'db_migrate_password', 'db_admin_password',
                'backup_access_key', 'backup_secret_key', 'backup_cipher_pass'}
    if set(secrets) != expected or any(not re.fullmatch(r'[a-f0-9]{20,64}', v) for v in secrets.values()):
        raise ValueError('invalid secrets schema')
    for name in expected - {'backup_access_key'}:
        if len(secrets[name]) != 64:
            raise ValueError('invalid secret length')
    BASE.mkdir(mode=0o700, exist_ok=True)
    def write(name, content, uid):
        path = BASE / name
        data = content.encode()
        if path.exists() and path.read_bytes() == data:
            os.chown(path, uid, uid)
            os.chmod(path, 0o400)
            return
        temporary = BASE / (name + '.new')
        with temporary.open('wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temporary, 0o400)
        os.chown(temporary, uid, uid)
        temporary.replace(path)
    for name, uid in [('api_key', 10001), ('db_app_password', 10001),
                      ('db_migrate_password', 10002), ('db_admin_password', 999)]:
        write(name, secrets[name], uid)
    write('pginit_app_password', secrets['db_app_password'], 999)
    write('pginit_migrate_password', secrets['db_migrate_password'], 999)
    backup = json.loads((CONFIG / 'backup.json').read_text())
    # Public configuration is admin-owned; exclude newlines to avoid INI injection.
    if any('\n' in str(v) or '\r' in str(v) for v in backup.values()):
        raise ValueError('invalid backup configuration')
    body = '''[global]
repo1-type=s3
repo1-s3-uri-style=path
repo1-path=/threats
repo1-s3-region=us-east-1
repo1-s3-endpoint={endpoint}
repo1-storage-port={port}
repo1-s3-bucket={bucket}
repo1-storage-ca-file=/etc/ssl/backup-ca.crt
repo1-storage-verify-tls=y
repo1-s3-key={backup_access_key}
repo1-s3-key-secret={backup_secret_key}
repo1-cipher-type=aes-256-cbc
repo1-cipher-pass={backup_cipher_pass}
repo1-retention-full=2
repo1-retention-diff=7
log-level-console=info
log-level-file=off
lock-path=/tmp/pgbackrest
start-fast=y
archive-timeout=120
process-max=1
[main]
pg1-path=/var/lib/postgresql/data/pgdata
pg1-socket-path=/var/run/postgresql
pg1-user=postgres
pg1-database=postgres
'''.format(**backup, **secrets)
    write('pgbackrest.conf', body, 999)
    socketdir = BASE / 'pgsocket'
    socketdir.mkdir(mode=0o770, exist_ok=True)
    os.chown(socketdir, 999, 999)
    os.chmod(socketdir, 0o770)

if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Do not expose sops output, decrypted values, or credentials from tracebacks.
        raise SystemExit('secret materialization failed; inspect configuration and key permissions')
