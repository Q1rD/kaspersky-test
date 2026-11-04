FROM golang:1.25@sha256:dd7d32e19b28621cd982082397fc0510d396805b717d5e77466aa2dd692340de AS build
ENV GOTOOLCHAIN=go1.26.10
WORKDIR /src
COPY infra/docker/caddy/go.mod infra/docker/caddy/go.sum ./
RUN go mod download
COPY infra/docker/caddy/main.go .
COPY cmd/probe/main.go probe/main.go
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /caddy . && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /probe ./probe
FROM scratch
COPY --from=build /caddy /caddy
COPY --from=build /probe /probe
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENV HOME=/data XDG_DATA_HOME=/data XDG_CONFIG_HOME=/config
USER 10003:10003
ENTRYPOINT ["/caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
