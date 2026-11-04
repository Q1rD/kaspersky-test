#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
temp="$(mktemp)"
config="$(mktemp)"
trap 'rm -f "$temp" "$config"' EXIT
sed "s|^output:.*|output: $temp|" transport/http/api/codegen.yaml > "$config"
go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.5.1 --config "$config" openapi.yml
cmp "$temp" transport/http/api/api.gen.go
