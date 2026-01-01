# =============================================================================
# AngelaMos | 2025
# Justfile
# =============================================================================

set dotenv-load
set export
set shell := ["bash", "-uc"]
set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

project := file_name(justfile_directory())
version := `git describe --tags --always 2>/dev/null || echo "dev"`

# =============================================================================
# Default
# =============================================================================

default:
    @just --list --unsorted

# =============================================================================
# Linting and Formatting
# =============================================================================

[group('lint')]
ruff *ARGS:
    ruff check backend/ {{ARGS}}

[group('lint')]
ruff-fix:
    ruff check backend/ --fix
    ruff format backend/

[group('lint')]
ruff-format:
    ruff format backend/

[group('lint')]
pylint *ARGS:
    pylint backend/src {{ARGS}}

[group('lint')]
lint: ruff pylint

# =============================================================================
# Frontend Linting
# =============================================================================

[group('frontend')]
biome *ARGS:
    cd frontend && pnpm biome check . {{ARGS}}

[group('frontend')]
biome-fix:
    cd frontend && pnpm biome check --write .

[group('frontend')]
stylelint *ARGS:
    cd frontend && pnpm stylelint '**/*.scss' {{ARGS}}

[group('frontend')]
stylelint-fix:
    cd frontend && pnpm stylelint '**/*.scss' --fix

[group('frontend')]
tsc *ARGS:
    cd frontend && pnpm tsc --noEmit {{ARGS}}

# =============================================================================
# Type Checking
# =============================================================================

[group('types')]
mypy *ARGS:
    mypy backend/src {{ARGS}}

[group('types')]
ty *ARGS:
    cd backend && ty check {{ARGS}}

[group('types')]
typecheck: mypy

# =============================================================================
# Testing
# =============================================================================

[group('test')]
pytest *ARGS:
    pytest backend/tests {{ARGS}}

[group('test')]
test: pytest

[group('test')]
test-cov:
    pytest backend/tests --cov=backend/src --cov-report=term-missing --cov-report=html

# =============================================================================
# CI / Quality
# =============================================================================

[group('ci')]
ci: lint typecheck test

[group('ci')]
check: ruff mypy

# =============================================================================
# Docker Compose (Production)
# =============================================================================

[group('docker')]
up *ARGS:
    docker compose up {{ARGS}}

[group('docker')]
start *ARGS:
    docker compose up -d {{ARGS}}

[group('docker')]
down *ARGS:
    docker compose down {{ARGS}}

[group('docker')]
stop:
    docker compose stop

[group('docker')]
build *ARGS:
    docker compose build {{ARGS}}

[group('docker')]
rebuild:
    docker compose build --no-cache

[group('docker')]
logs *SERVICE:
    docker compose logs -f {{SERVICE}}

[group('docker')]
ps:
    docker compose ps

[group('docker')]
shell service='backend':
    docker compose exec -it {{service}} /bin/bash

# =============================================================================
# Docker Compose (Dev)
# =============================================================================

[group('dev')]
dev-up *ARGS:
    docker compose -f dev.compose.yml up {{ARGS}}

[group('dev')]
dev-start *ARGS:
    docker compose -f dev.compose.yml up -d {{ARGS}}

[group('dev')]
dev-down *ARGS:
    docker compose -f dev.compose.yml down {{ARGS}}

[group('dev')]
dev-stop:
    docker compose -f dev.compose.yml stop

[group('dev')]
dev-build *ARGS:
    docker compose -f dev.compose.yml build {{ARGS}}

[group('dev')]
dev-rebuild:
    docker compose -f dev.compose.yml build --no-cache

[group('dev')]
dev-logs *SERVICE:
    docker compose -f dev.compose.yml logs -f {{SERVICE}}

[group('dev')]
dev-ps:
    docker compose -f dev.compose.yml ps

[group('dev')]
dev-shell service='backend':
    docker compose -f dev.compose.yml exec -it {{service}} /bin/bash

# =============================================================================
# Database (Docker)
# =============================================================================

[group('db')]
migrate *ARGS:
    docker compose exec backend alembic upgrade {{ARGS}}

[group('db')]
migration message:
    docker compose exec backend alembic revision --autogenerate -m "{{message}}"

[group('db')]
rollback:
    docker compose exec backend alembic downgrade -1

[group('db')]
db-history:
    docker compose exec backend alembic history --verbose

[group('db')]
db-current:
    docker compose exec backend alembic current

# =============================================================================
# Database (Local - no Docker)
# =============================================================================

[group('db-local')]
migrate-local *ARGS:
    cd backend && uv run alembic upgrade {{ARGS}}

[group('db-local')]
migration-local message:
    cd backend && uv run alembic revision --autogenerate -m "{{message}}"

[group('db-local')]
rollback-local:
    cd backend && uv run alembic downgrade -1

[group('db-local')]
db-history-local:
    cd backend && uv run alembic history --verbose

[group('db-local')]
db-current-local:
    cd backend && uv run alembic current

# =============================================================================
# Setup
# =============================================================================

[group('setup')]
setup:
    @chmod +x setup.sh && ./setup.sh

[group('setup')]
clean-templates:
    @rm -rf docs/templates && echo "Removed docs/templates/"

# =============================================================================
# Utilities
# =============================================================================

[group('util')]
info:
    @echo "Project: {{project}}"
    @echo "Version: {{version}}"
    @echo "OS: {{os()}} ({{arch()}})"

[group('util')]
clean:
    -rm -rf backend/.mypy_cache
    -rm -rf backend/.pytest_cache
    -rm -rf backend/.ruff_cache
    -rm -rf backend/htmlcov
    -rm -rf backend/.coverage
    @echo "Cache directories cleaned"
