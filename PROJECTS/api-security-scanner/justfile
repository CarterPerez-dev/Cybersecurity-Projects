# API Security Scanner - Development Commands
# AngelaMos | 2025

set dotenv-load
set export
set shell := ["bash", "-uc"]
set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

mod backend 'backend/backend.just'

# Show available commands
default:
    @just --list --unsorted

# =============================================================================
# Development
# =============================================================================

# Start development environment
[group('dev')]
dev:
    docker compose -f dev.compose.yml up

# Build and start development environment
[group('dev')]
dev-build:
    docker compose -f dev.compose.yml up --build

# Stop development environment
[group('dev')]
dev-down:
    docker compose -f dev.compose.yml down

# View development logs (follow mode)
[group('dev')]
dev-logs *SERVICE:
    docker compose -f dev.compose.yml logs -f {{SERVICE}}

# Shell into a dev container
[group('dev')]
dev-shell service='backend':
    docker compose -f dev.compose.yml exec -it {{service}} /bin/bash

# =============================================================================
# Production
# =============================================================================

# Start production environment (detached)
[group('prod')]
prod:
    docker compose up -d

# Build and start production environment
[group('prod')]
prod-build:
    docker compose up --build -d

# Stop production environment
[group('prod')]
prod-down:
    docker compose down

# View production logs (follow mode)
[group('prod')]
prod-logs *SERVICE:
    docker compose logs -f {{SERVICE}}

# =============================================================================
# Cleanup
# =============================================================================

# Stop all containers and remove volumes
[group('cleanup')]
clean:
    docker compose -f dev.compose.yml down -v
    docker compose down -v

# Clean + remove all Docker images/cache
[group('cleanup')]
[confirm("This will remove all Docker images and cache. Continue?")]
clean-all: clean
    docker system prune -af --volumes

# =============================================================================
# Utilities
# =============================================================================

# Show running containers
ps:
    docker compose ps
    docker compose -f dev.compose.yml ps

# Execute command in running backend container
exec *CMD:
    docker compose -f dev.compose.yml exec backend {{CMD}}

# Run one-off command in backend (new container)
run *CMD:
    docker compose -f dev.compose.yml run --rm backend {{CMD}}
