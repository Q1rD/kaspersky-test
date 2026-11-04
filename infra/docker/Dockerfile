FROM golang:1.25@sha256:dd7d32e19b28621cd982082397fc0510d396805b717d5e77466aa2dd692340de AS build
ENV GOTOOLCHAIN=go1.26.10
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/migrate ./cmd/migrate && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/probe ./cmd/probe
FROM scratch
COPY --from=build /out/ /
COPY config/config.yaml /config/config.yaml
USER 10001:10001
ENTRYPOINT ["/server"]
