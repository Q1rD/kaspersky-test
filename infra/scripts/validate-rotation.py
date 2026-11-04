#!/usr/bin/env python3
"""Validate the candidate before downtime; backup key rotation is a separate operation."""
import json
import re
import subprocess
ENV = {'PATH': '/usr/bin:/bin', 'SOPS_AGE_KEY_FILE': '/etc/threat-service/age.key'}
def read(path):
    r = subprocess.run(['/usr/local/bin/sops', '-d', path], env=ENV, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return json.loads(r.stdout)
try:
    old = read('/etc/threat-service/secrets.enc.json')
    new = read('/etc/threat-service/secrets.next.enc.json')
    assert set(new) == set(old)
    assert all(isinstance(v, str) and re.fullmatch('[a-f0-9]{64}', v) for k, v in new.items() if k != 'backup_access_key')
    assert all(new[k] == old[k] for k in ['backup_access_key', 'backup_secret_key', 'backup_cipher_pass'])
except Exception:
    raise SystemExit('candidate invalid or backup credentials changed; service was not stopped')
print('Candidate validated; backup encryption identity preserved.')
