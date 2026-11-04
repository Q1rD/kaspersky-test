#!/bin/bash
set -euo pipefail
# Passwords are transported over stdin; they never appear in argv or logs.
app_password="$(cat /run/secrets/pginit_app_password)"
migrate_password="$(cat /run/secrets/pginit_migrate_password)"
[[ "$app_password" =~ ^[0-9a-f]{64}$ && "$migrate_password" =~ ^[0-9a-f]{64}$ ]]
psql -v ON_ERROR_STOP=1 --username postgres --dbname postgres <<SQL
SET log_statement = 'none';
CREATE ROLE threat_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '$migrate_password';
CREATE ROLE threat_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '$app_password';
CREATE DATABASE threats OWNER threat_migrator;
REVOKE ALL ON DATABASE threats FROM PUBLIC;
GRANT CONNECT ON DATABASE threats TO threat_app;
SQL
psql -v ON_ERROR_STOP=1 --username postgres --dbname threats <<'SQL'
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT ALL ON SCHEMA public TO threat_migrator;
SQL
