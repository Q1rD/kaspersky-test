#!/usr/bin/env bash
# Exercise the real image entrypoint and role initialization under runtime restrictions.
set -euo pipefail
umask 077
name="threat-image-test-$(openssl rand -hex 8)"
secrets_dir="$(mktemp -d)"
cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    rm -rf "$secrets_dir"
}
trap cleanup EXIT
for secret in db_admin_password pginit_app_password pginit_migrate_password; do
    openssl rand -hex 32 > "$secrets_dir/$secret"
    # Each file is mounted separately; the host directory remains private (0700).
    chmod 0444 "$secrets_dir/$secret"
done

docker run -d --name "$name" --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges:true --pids-limit 128 --memory 512m \
    --tmpfs /var/lib/postgresql/data:rw,nosuid,nodev,size=128m,uid=999,gid=999,mode=0700 \
    --tmpfs /var/run/postgresql:rw,nosuid,nodev,size=16m,uid=999,gid=999,mode=0775 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m \
    -e PGDATA=/var/lib/postgresql/data/pgdata \
    -e POSTGRES_PASSWORD_FILE=/run/secrets/db_admin_password \
    -e 'POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=peer' \
    -v "$secrets_dir/db_admin_password:/run/secrets/db_admin_password:ro" \
    -v "$secrets_dir/pginit_app_password:/run/secrets/pginit_app_password:ro" \
    -v "$secrets_dir/pginit_migrate_password:/run/secrets/pginit_migrate_password:ro" \
    "${POSTGRES_TEST_IMAGE:-threat-postgres:local}" >/dev/null

ready=false
for _ in $(seq 1 60); do
    if docker exec "$name" pg_isready -h 127.0.0.1 -U postgres -d postgres >/dev/null 2>&1; then
        ready=true
        break
    fi
    sleep 1
done
if [[ "$ready" != true ]]; then
    docker logs "$name" >&2
    exit 1
fi
[[ "$(docker exec "$name" id -u)" == 999 ]]
docker exec "$name" sh -c '! command -v gosu'
[[ "$(docker exec "$name" psql -U postgres -d threats -Atqc "SELECT count(*) FROM pg_roles WHERE rolname IN ('threat_app','threat_migrator') AND rolcanlogin AND NOT rolsuper")" == 2 ]]
docker exec "$name" psql -U postgres -d threats -v ON_ERROR_STOP=1 -c 'CREATE TABLE startup_check(id integer PRIMARY KEY); INSERT INTO startup_check VALUES (1);' >/dev/null
docker exec "$name" pgbackrest --version
printf 'PostgreSQL initialized as UID 999 with read-only rootfs and dropped capabilities.\n'
