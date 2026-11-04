SHELL := /bin/bash
.DEFAULT_GOAL := help
export GOTOOLCHAIN := go1.26.10
ANSIBLE_PLAYBOOK ?= ansible-playbook
INVENTORY ?= inventory.yml
VARS ?= deploy-vars.yml
.PHONY: help images generate check-config bootstrap deploy rotate-secrets

help:
	@echo 'Requirements: Docker + Compose v2; Go for generation; Ansible, SOPS and age for bootstrap.'
	@echo 'make images        Build API, Caddy and PostgreSQL images (:local).'
	@echo 'make generate      Generate HTTP models/server from openapi.yml.'
	@echo 'make check-config  Validate Compose configuration.'
	@echo 'Copy infra/ansible/{inventory,vars}.example.yml to inventory.yml and deploy-vars.yml; fill in your values.'
	@echo 'Encrypt the fields in infra/ansible/secrets.example.json with SOPS+age; keep private keys outside Git.'
	@echo 'make bootstrap INVENTORY=inventory.yml VARS=deploy-vars.yml'
	@echo 'Publish images; sign repository@sha256 references using infra/scripts/sign-release.py --help.'
	@echo 'On the server as threat-deploy: make deploy MANIFEST=/path/release.json SIGNATURE=/path/release.json.sig'

images:
	docker build -f infra/docker/Dockerfile -t threat-api:local .
	docker build -f infra/docker/caddy/Dockerfile -t threat-caddy:local .
	docker build -f infra/docker/postgres.Dockerfile -t threat-postgres:local .

generate:
	go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.5.1 --config transport/http/api/codegen.yaml openapi.yml

check-config:
	API_IMAGE=threat-api:local CADDY_IMAGE=threat-caddy:local POSTGRES_IMAGE=threat-postgres:local SITE_ADDRESS=localhost docker compose -f infra/docker/compose.yml config --quiet

bootstrap:
	$(ANSIBLE_PLAYBOOK) -i "$(INVENTORY)" infra/ansible/bootstrap.yml -e "@$(VARS)"

deploy:
	@test -n "$(MANIFEST)" -a -n "$(SIGNATURE)" || { echo 'Set MANIFEST and SIGNATURE to the signed release files.'; exit 1; }
	/opt/threat-ansible/bin/ansible-playbook /usr/local/libexec/threat/deploy.yml -e "release_manifest=$(MANIFEST)" -e "release_signature=$(SIGNATURE)"

rotate-secrets:
	@test -n "$(SECRETS)" || { echo 'Set SECRETS to the new SOPS-encrypted JSON file.'; exit 1; }
	$(ANSIBLE_PLAYBOOK) -i "$(INVENTORY)" infra/ansible/rotate-secrets.yml -e "secrets_file=$(SECRETS)"
