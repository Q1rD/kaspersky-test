#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
name="threat-test-$(date +%s)-$$"
cleanup(){ docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
password="$(openssl rand -hex 24)"
docker run -d --name "$name" -e POSTGRES_PASSWORD="$password" -e POSTGRES_DB=threats -p 127.0.0.1::5432 postgres:17-bookworm@sha256:839fbb5a4942a7758dd93e18b42ea5649807491a0545b5eeeb8f0b8bb11857a5 >/dev/null
ready=false
for i in $(seq 1 60); do
    if docker exec "$name" pg_isready -h 127.0.0.1 -U postgres -d threats >/dev/null 2>&1; then
        ready=true
        break
    fi
    sleep 1
done
if [[ "$ready" != true ]]; then
    echo 'PostgreSQL did not become ready within 60 seconds.' >&2
    docker logs "$name" >&2
    exit 1
fi
port="$(docker port "$name" 5432/tcp | cut -d: -f2)"
TEST_DATABASE_URL="postgres://postgres:$password@127.0.0.1:$port/threats?sslmode=disable" go test -race -count=1 ./tests/...
