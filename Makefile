# DOTS 2.0 developer entry points.
#   make check      lint + format check + type check
#   make unit       unit and integration tests (starts a throwaway Postgres)
#   make test       unit tests, then the end-to-end lab (Milestone 3+)

SHELL := /bin/bash
PG_CONTAINER ?= dots-test-pg
PG_PORT ?= 54329
export DOTS_TEST_PG_DSN ?= postgresql://dots:dots@localhost:$(PG_PORT)/postgres
# Set EXTRA_CA to a CA bundle when building behind a TLS-intercepting proxy.
EXTRA_CA ?=
BUILD_SECRET := $(if $(EXTRA_CA),--secret id=extra_ca$(comma)src=$(EXTRA_CA),)
comma := ,

.PHONY: sync check lint typecheck unit pg-up pg-down images lab-build lab-up lab-e2e lab-down test clean

sync:
	uv sync --frozen

lint:
	uv run ruff check services lab
	uv run ruff format --check services lab

typecheck:
	uv run mypy services/common/src services/receipts/src services/settlement/src lab/src

check: lint typecheck

pg-up:
	@docker inspect $(PG_CONTAINER) >/dev/null 2>&1 || \
	  docker run -d --name $(PG_CONTAINER) -e POSTGRES_USER=dots -e POSTGRES_PASSWORD=dots \
	    -p $(PG_PORT):5432 postgres:17-alpine >/dev/null
	@for i in $$(seq 1 30); do docker exec $(PG_CONTAINER) pg_isready -U dots >/dev/null 2>&1 && exit 0; sleep 1; done; \
	  echo "postgres did not start"; exit 1

pg-down:
	-docker rm -f $(PG_CONTAINER) >/dev/null 2>&1

unit: pg-up
	uv run pytest -q

images:
	docker build $(BUILD_SECRET) -f services/Dockerfile -t dots-services:dev .

# ---------------------------------------------------------------- lab
export EXTRA_CA

lab-build:
	docker compose --profile test build

lab-up: lab-build
	docker compose up -d --wait

lab-e2e:
	python3 lab/run_e2e.py

lab-down:
	docker compose --profile test down -v

# unit tests, then a fresh lab end to end
test: unit
	$(MAKE) lab-down
	$(MAKE) lab-up
	$(MAKE) lab-e2e
