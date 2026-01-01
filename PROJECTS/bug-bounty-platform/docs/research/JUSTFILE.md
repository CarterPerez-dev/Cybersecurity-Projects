# Justfile patterns for production full-stack development in 2025

The `just` command runner (currently at **version 1.43.1** as of November 2025) has matured into an excellent choice for full-stack monorepo orchestration, offering native module support for organizing multi-service commands, **parallel dependency execution** via the new `[parallel]` attribute, and robust cross-platform compatibility through shell configuration. For your FastAPI + React + Docker Compose stack, the recommended architecture uses a root justfile with service-specific modules (`backend.just`, `frontend.just`, `db.just`), enabling clean namespaced commands like `just backend::test` while keeping orchestration commands at the root level. This approach eliminates the complexity of Makefiles while providing significantly more power than npm scripts.

## Current just features and 2024-2025 additions

Just has seen substantial feature additions over the past year that directly benefit full-stack development workflows. The **module system** (`mod` statement) was stabilized in version 1.31.0, enabling proper monorepo organization with namespaced recipes. Version 1.42.0 introduced the **`[parallel]` attribute** for concurrent dependency execution and **cross-submodule dependencies**, allowing recipes to depend on recipes in other modules (`deploy: utils::build`). The **`[script]` attribute** (1.33.0) enables writing recipes in any language without shebang workarounds, and the **`[group]` attribute** (1.27.0) organizes recipes into logical categories in help output.

New built-in functions added in 2024-2025 include `which()` and `require()` for finding executables (with `require()` erroring if not found), `read()` for file contents, and path constants `PATH_SEP` and `PATH_VAR_SEP` for cross-platform path handling. The `dotenv-override` setting now allows `.env` files to override existing environment variables, useful for Docker-based development where container environment variables might conflict with local configuration.

```just
# Core settings block for a 2025 production justfile
set dotenv-load                                    # Auto-load .env
set export                                         # Export all variables
set shell := ["bash", "-uc"]                       # Bash with error checking
set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]
```

## Monorepo organization with the module system

The recommended structure for a full-stack monorepo uses a **root justfile for orchestration** combined with **service modules** for domain-specific commands. Just searches for module files in a specific order: `foo.just`, `foo/mod.just`, `foo/justfile`, or `foo/.justfile`, giving you flexibility in organizing your project.

```
project/
├── justfile           # Root orchestration (dev, build, test-all, deploy)
├── backend.just       # Backend module (migrations, backend tests, lint)
├── frontend.just      # Frontend module (build, dev server, frontend tests)
├── db.just            # Database module (backup, restore, shell)
├── docker.just        # Shared Docker utilities (imported, not modularized)
├── backend/
├── frontend/
└── docker-compose.yml
```

The distinction between `mod` and `import` is critical: **`mod` creates namespaced recipes** accessed via `just backend::test`, while **`import` merges recipes** into the current namespace without prefixes. For service-specific commands, modules provide cleaner organization; for shared utilities like Docker helpers, imports work better.

```just
# Root justfile
mod backend                      # Creates just backend::* namespace
mod frontend
mod db
import 'docker.just'             # Merges into root namespace

# Start everything
dev:
    docker compose up

# Run all tests across services
test:
    just backend::test
    just frontend::test
```

Module recipes should use the **`[no-cd]` attribute** to ensure they execute from the project root rather than the module file's directory, since Docker Compose commands need access to the root `docker-compose.yml`:

```just
# backend.just
[no-cd]
test *ARGS:
    docker compose exec backend pytest {{ARGS}}
```

## Docker Compose integration patterns

Docker Compose integration forms the backbone of full-stack development workflows. The key patterns involve **variadic arguments for passthrough** (`*ARGS`), **parameterized compose files** for environment switching, and **service-specific exec commands**.

```just
# Essential Docker Compose recipes
@up *ARGS:
    docker compose up {{ARGS}}

@start *ARGS:
    docker compose up -d {{ARGS}}

@down *ARGS:
    docker compose down {{ARGS}}

@build *ARGS:
    docker compose build {{ARGS}}

@logs *SERVICE:
    docker compose logs -f {{SERVICE}}

# Execute in running container
@exec service *CMD:
    docker compose exec {{service}} {{CMD}}

# One-off command (new container)
@run service *CMD:
    docker compose run --rm {{service}} {{CMD}}

# Interactive shell access
shell service='backend':
    docker compose exec -it {{service}} /bin/bash
```

For **environment-specific deployments**, parameterize the compose file selection:

```just
# Parameterized environment handling
up-dev:
    docker compose -f docker-compose.yml -f docker-compose.dev.yml up

up-prod:
    docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Or with a parameter
deploy env='staging':
    docker compose -f docker-compose.yml -f docker-compose.{{env}}.yml up -d
```

**Docker Compose profiles** integrate naturally with environment variables:

```just
export COMPOSE_PROFILES := env_var_or_default('COMPOSE_PROFILES', 'default')

# Usage: COMPOSE_PROFILES=workers just up
```

## Recipe parameters and dependency patterns

Just offers sophisticated parameter handling including **required parameters**, **optional with defaults**, and **variadic parameters** (both mandatory `+` and optional `*`). Default values can be expressions, enabling dynamic defaults based on environment or other variables.

```just
# Required parameter
deploy environment:
    echo "Deploying to {{environment}}"

# Optional with default
serve port='8000' host='0.0.0.0':
    uvicorn main:app --host {{host}} --port {{port}}

# Variadic (one or more required)
backup +tables:
    pg_dump {{tables}}

# Variadic (zero or more optional)
test *ARGS:
    pytest {{ARGS}}

# Mixed parameters with expression default
arch := 'amd64'
build target os=os() architecture=arch:
    docker build --platform {{os}}/{{architecture}} -t {{target}} .
```

Dependencies between recipes can now execute **in parallel** using the `[parallel]` attribute introduced in version 1.42.0:

```just
[parallel]
ci: lint typecheck test build
    @echo "All checks passed"

lint:
    just backend::lint
    just frontend::lint

typecheck:
    just backend::typecheck
    just frontend::typecheck

test:
    just backend::test
    just frontend::test

build:
    docker compose build
```

**Cross-submodule dependencies** allow recipes to depend on recipes in other modules:

```just
# Root justfile
mod backend
mod frontend

deploy: backend::build frontend::build
    docker compose -f docker-compose.prod.yml up -d
```

## Variables, conditionals, and platform handling

Just's expression system supports **conditionals**, **environment variable access**, **command substitution**, and **platform detection**. These features enable cross-platform justfiles that work on Windows, macOS, and Linux.

```just
# Platform-specific commands using conditionals
browse := if os() == "linux" { "xdg-open" } else if os() == "macos" { "open" } else { "start" }
sed_inplace := if os() == "linux" { "sed -i" } else { "sed -i '' -e" }

# Environment variables with fallbacks
db_host := env('DATABASE_HOST', 'localhost')
db_port := env('DATABASE_PORT', '5432')

# Command substitution via backticks
git_hash := `git rev-parse --short HEAD`
current_branch := `git branch --show-current 2>/dev/null || echo "main"`

# Dynamic values based on environment
build_mode := if env('CI', '') == 'true' { 'release' } else { 'debug' }
```

For **platform-specific recipes**, use the OS attributes:

```just
[linux]
install-deps:
    sudo apt install postgresql-client

[macos]
install-deps:
    brew install postgresql

[windows]
install-deps:
    choco install postgresql
```

## Built-in functions for production workflows

Just provides an extensive function library. The most useful for full-stack development include path manipulation, environment access, system information, and the new executable-finding functions.

| Category | Functions | Use Case |
|----------|-----------|----------|
| **Path** | `justfile_directory()`, `parent_directory()`, `join()` | Constructing paths relative to project root |
| **Environment** | `env(key, default)`, `require()`, `which()` | Configuration and dependency checking |
| **System** | `os()`, `arch()`, `os_family()`, `num_cpus()` | Cross-platform logic |
| **Files** | `path_exists()`, `read()`, `sha256_file()` | File validation and checksums |
| **Strings** | `replace()`, `trim()`, `kebabcase()` | String manipulation |

```just
# Practical examples
project_root := justfile_directory()
scripts_dir := project_root / "scripts"
config_file := project_root / "config" / "settings.yaml"

# Validate required tools exist
cargo := require('cargo')
docker := require('docker')

# Generate cache keys
config_hash := sha256_file('requirements.txt')
```

## Error handling and user feedback

Just provides several mechanisms for **controlling error behavior** and **user feedback**. The `-` prefix ignores command failures, the `[confirm]` attribute requires user confirmation for dangerous operations, and `[no-exit-message]` suppresses error messages for wrapper recipes.

```just
# Continue on error (useful for cleanup)
clean:
    -rm -rf build/
    -rm -rf dist/
    -rm -rf .cache/
    @echo "Cleanup complete"

# Require confirmation for destructive operations
[confirm("This will DELETE the production database. Are you sure?")]
[group('danger')]
db-drop-prod:
    docker compose -f docker-compose.prod.yml exec db dropdb production

# Suppress just's error message (the tool's own message is enough)
[no-exit-message]
git *args:
    git {{args}}
```

For **validation at parse time**, use the `error()` function in expressions:

```just
required_env := if env('API_KEY', '') == '' { error("API_KEY environment variable is required") } else { env('API_KEY') }
```

## Documentation and help organization

Self-documenting justfiles use **comments above recipes** (shown in `just --list`), the **`[doc()]` attribute** for custom descriptions, and **`[group()]`** for logical organization. Private helper recipes use the **underscore prefix**.

```just
# Show available commands (default recipe)
default:
    @just --list --unsorted

# Build Docker images for all services
[group('build')]
build:
    docker compose build

# Run database migrations
[group('database')]
migrate *ARGS:
    docker compose exec backend alembic upgrade {{ARGS}}

# Create a new migration file
[doc("Generate migration from model changes")]
[group('database')]
migration message:
    docker compose exec backend alembic revision --autogenerate -m "{{message}}"

# Internal helper (hidden from --list)
[private]
_ensure-docker:
    @docker info > /dev/null 2>&1 || (echo "Docker not running" && exit 1)
```

Running `just --list` with groups produces organized output:

```
Available recipes:
    default

[build]
    build   # Build Docker images for all services

[database]
    migrate *ARGS     # Run database migrations
    migration message # Generate migration from model changes
```

## CI/CD integration with GitHub Actions

Installing just in CI pipelines uses either the **official setup-just action** or the **install script with version pinning**. Pin versions in CI to avoid unexpected breakage.

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: extractions/setup-just@v3
        with:
          just-version: '1.43.1'
      
      - name: Run CI checks
        run: just ci
```

Create a dedicated **CI recipe** that runs all checks:

```just
# CI-specific recipe that fails fast on any issue
ci: lint typecheck test build
    @echo "✅ All CI checks passed"

# Local development doesn't need all checks
dev:
    docker compose up
```

For **environment variable handling** in CI, rely on the `env()` function with defaults rather than assuming variables exist:

```just
# Works both locally (with .env) and in CI (with secrets)
set dotenv-load
db_url := env('DATABASE_URL', 'postgresql://localhost/dev')
```

## Complete production justfile template

This template incorporates all the patterns discussed for a FastAPI + React + PostgreSQL + Docker Compose stack:

```just
# =============================================================================
# Full-Stack Development Commands
# =============================================================================
set dotenv-load
set export
set shell := ["bash", "-uc"]
set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

# Service modules
mod backend 'backend.just'
mod frontend 'frontend.just'
mod db 'db.just'

# Project info
project := file_name(justfile_directory())
version := `git describe --tags --always 2>/dev/null || echo "dev"`

# =============================================================================
# Core Commands
# =============================================================================

# List available commands
default:
    @just --list --unsorted

# Start development environment
dev:
    docker compose up

# Start services in background
start:
    docker compose up -d

# Stop all services
stop:
    docker compose down

# Stop and remove volumes (fresh start)
[confirm("Remove all volumes and data?")]
clean:
    docker compose down -v --remove-orphans

# View service logs
logs *SERVICE:
    docker compose logs -f {{SERVICE}}

# Open shell in service container
shell service='backend':
    docker compose exec -it {{service}} /bin/bash

# =============================================================================
# Build and Deploy
# =============================================================================

# Build all Docker images
[group('build')]
build *ARGS:
    docker compose build {{ARGS}}

# Rebuild from scratch (no cache)
[group('build')]
rebuild:
    docker compose build --no-cache

# Build production images
[group('build')]
build-prod:
    docker compose -f docker-compose.yml -f docker-compose.prod.yml build

# Deploy to staging
[group('deploy')]
[confirm("Deploy to staging?")]
deploy-staging: ci build-prod
    docker compose -f docker-compose.yml -f docker-compose.staging.yml up -d

# Deploy to production
[group('deploy')]
[confirm("Deploy to PRODUCTION?")]
deploy-prod: ci build-prod
    docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# =============================================================================
# Testing and Quality
# =============================================================================

# Run all tests
[group('test')]
test:
    just backend::test
    just frontend::test

# Run linters
[group('test')]
lint:
    just backend::lint
    just frontend::lint

# Type checking
[group('test')]
typecheck:
    just backend::typecheck
    just frontend::typecheck

# Format all code
[group('test')]
format:
    just backend::format
    just frontend::format

# CI pipeline (runs all checks)
[group('test')]
[parallel]
ci: lint typecheck test
    @echo "✅ All checks passed"

# =============================================================================
# Database
# =============================================================================

# Run migrations
[group('database')]
migrate *ARGS:
    just db::migrate {{ARGS}}

# Create new migration
[group('database')]
migration message:
    just db::migration "{{message}}"

# Reset database (dangerous)
[group('database')]
[confirm("Reset the database? All data will be lost.")]
db-reset:
    just db::reset
    just migrate

# =============================================================================
# Setup
# =============================================================================

# First-time project setup
setup:
    @echo "Setting up {{project}}..."
    cp -n .env.example .env || true
    docker compose build
    docker compose up -d
    just migrate
    @echo "✅ Setup complete. Run 'just dev' to start."

# =============================================================================
# Utilities
# =============================================================================

# Show running containers
ps:
    docker compose ps

# Docker system cleanup
[private]
docker-prune:
    docker system prune -f

# Print project info
info:
    @echo "Project: {{project}}"
    @echo "Version: {{version}}"
    @echo "OS: {{os()}} ({{arch()}})"
```

```just
# backend.just - Backend service commands
[no-cd]

# Run backend tests
test *ARGS:
    docker compose exec backend pytest {{ARGS}}

# Run specific test file
test-file file:
    docker compose exec backend pytest {{file}} -v

# Lint backend code
lint:
    docker compose exec backend ruff check .
    docker compose exec backend ruff format --check .

# Type checking
typecheck:
    docker compose exec backend mypy src/

# Format backend code
format:
    docker compose exec backend ruff format .
    docker compose exec backend ruff check --fix .

# Python REPL
repl:
    docker compose exec backend python

# Install new dependency
add package:
    docker compose exec backend pip install {{package}}
    docker compose exec backend pip freeze > requirements.txt
```

```just
# db.just - Database commands
[no-cd]

DATABASE_URL := env('DATABASE_URL', 'postgresql://postgres:postgres@db/app')

# Run migrations
migrate *ARGS='head':
    docker compose exec backend alembic upgrade {{ARGS}}

# Create new migration
migration message:
    docker compose exec backend alembic revision --autogenerate -m "{{message}}"

# Rollback last migration
rollback:
    docker compose exec backend alembic downgrade -1

# PostgreSQL shell
psql:
    docker compose exec db psql -U postgres app

# Create database backup
backup:
    #!/usr/bin/env bash
    timestamp=$(date +%Y%m%d_%H%M%S)
    docker compose exec db pg_dump -U postgres app > "backups/db_${timestamp}.sql"
    echo "Backup created: backups/db_${timestamp}.sql"

# Restore from backup
restore file:
    docker compose exec -T db psql -U postgres app < {{file}}

# Reset database (drop and recreate)
reset:
    docker compose exec db dropdb -U postgres --if-exists app
    docker compose exec db createdb -U postgres app
```

## Common pitfalls to avoid

Several patterns consistently cause problems in production justfiles. **Avoid relative paths with `../`**—use `justfile_directory()` instead, as relative paths break when the working directory changes. **Always set `windows-shell`** if your team includes Windows users, since the default `sh` isn't available natively on Windows. **Don't set `fallback := true` in the root justfile**, as this can accidentally invoke user-level justfile recipes. **Keep recipes focused**—if a recipe exceeds 10-15 lines, split it into smaller dependent recipes or use a shebang script. **Pin versions in CI** to avoid breaking changes from automatic just updates.

The `error()` function evaluates at **parse time, not runtime**, so conditional error messages based on runtime state won't work as expected. For runtime validation, use shell conditionals within recipes instead.

## Debugging justfiles effectively

Just provides several tools for troubleshooting. Use `just --dry-run recipe` to see commands without executing them, `just --evaluate` to print all variable values, `just --show recipe` to display a recipe's source, and `just -vv recipe` for verbose execution. The `just --dump --dump-format json` command outputs the parsed justfile as JSON, useful for debugging complex expression evaluation.

```bash
# See what would run without executing
just --dry-run deploy-prod

# Check variable values
just --evaluate

# Debug a specific recipe
just --show migrate

# Maximum verbosity
just -vv ci
```

For cross-platform testing, test on all target platforms or use CI matrix builds to catch platform-specific issues early. The combination of OS-specific attributes (`[linux]`, `[macos]`, `[windows]`) and conditional expressions provides comprehensive cross-platform support when used correctly.
