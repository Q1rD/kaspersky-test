FROM postgres:17-bookworm@sha256:839fbb5a4942a7758dd93e18b42ea5649807491a0545b5eeeb8f0b8bb11857a5
RUN apt-get update && apt-get install -y --no-install-recommends pgbackrest=2.60.0-1.pgdg12+1 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY infra/docker/init-db.sh /docker-entrypoint-initdb.d/10-roles.sh
USER 999:999
