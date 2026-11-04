#!/usr/bin/env python3
"""Admin-only, after stopping application and materializing new SOPS secrets."""
from pathlib import Path
import re
import subprocess
roles = {'threat_app': 'db_app_password', 'threat_migrator': 'db_migrate_password', 'postgres': 'db_admin_password'}
statements = ["SET log_statement = 'none';", "SET log_min_error_statement = 'panic';", 'BEGIN;']
for role, filename in roles.items():
    password = (Path('/run/threat-service') / filename).read_text().strip()
    if not re.fullmatch('[a-f0-9]{64}', password):
        raise SystemExit('invalid password material')
    statements.append("ALTER ROLE " + role + " PASSWORD '" + password + "';")
statements.append('COMMIT;')
result = subprocess.run(['docker', 'exec', '-i', 'threat-postgres-1', 'psql', '-U', 'postgres', '-d', 'postgres', '-v', 'ON_ERROR_STOP=1'],
                        input='\n'.join(statements).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
if result.returncode:
    raise SystemExit('database password rotation failed; application remains stopped')
print('Database login passwords rotated.')
