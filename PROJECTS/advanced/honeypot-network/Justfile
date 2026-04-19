# ©AngelaMos | 2026
# Justfile

set export
set shell := ["bash", "-uc"]

project := file_name(justfile_directory())
version := `git describe --tags --always 2>/dev/null || echo "dev"`
binary := "hive"

# =============================================================================
# Default
# =============================================================================

default:
    @just --list --unsorted

# =============================================================================
# Linting and Formatting
# =============================================================================

[group('lint')]
lint *ARGS:
    golangci-lint run --timeout=5m {{ARGS}}

[group('lint')]
lint-fix:
    golangci-lint run --timeout=5m --fix

[group('lint')]
format:
    golangci-lint fmt

[group('lint')]
tidy:
    go mod tidy

[group('lint')]
vet:
    go vet ./...

# =============================================================================
# Testing
# =============================================================================

[group('test')]
test *ARGS:
    go test -race ./... {{ARGS}}

[group('test')]
test-v *ARGS:
    go test -race -v ./... {{ARGS}}

[group('test')]
cover:
    go test -race -cover ./...

# =============================================================================
# CI / Quality
# =============================================================================

[group('ci')]
ci: lint test
    @echo "All checks passed."

[group('ci')]
check: lint vet

# =============================================================================
# Development
# =============================================================================

[group('dev')]
run *ARGS:
    go run ./cmd/hive {{ARGS}}

[group('dev')]
dev-serve:
    go run ./cmd/hive serve --config config.yaml

[group('dev')]
dev-serve-verbose:
    go run ./cmd/hive serve --config config.yaml --verbose

[group('dev')]
dev-keygen:
    go run ./cmd/hive keygen

[group('dev')]
dev-version:
    go run ./cmd/hive version

# =============================================================================
# Build (Production)
# =============================================================================

[group('prod')]
build:
    go build -ldflags="-s -w" -o bin/{{binary}} ./cmd/hive
    @echo "Built: bin/{{binary}} ($(du -h bin/{{binary}} | cut -f1))"

[group('prod')]
build-static:
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o bin/{{binary}} ./cmd/hive
    @echo "Built static: bin/{{binary}} ($(du -h bin/{{binary}} | cut -f1))"

[group('prod')]
build-debug:
    go build -o bin/{{binary}} ./cmd/hive

[group('prod')]
install:
    go install ./cmd/hive

# =============================================================================
# Database
# =============================================================================

[group('db')]
migrate *ARGS:
    go run ./cmd/hive migrate up {{ARGS}}

[group('db')]
migrate-down:
    go run ./cmd/hive migrate down

[group('db')]
migrate-status:
    go run ./cmd/hive migrate status

# =============================================================================
# Docker
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
logs *SERVICE:
    docker compose logs -f {{SERVICE}}

[group('docker')]
ps:
    docker compose ps

[group('docker')]
dev-up *ARGS:
    docker compose -f dev.compose.yml up {{ARGS}}

[group('docker')]
dev-start *ARGS:
    docker compose -f dev.compose.yml up -d {{ARGS}}

[group('docker')]
dev-down *ARGS:
    docker compose -f dev.compose.yml down {{ARGS}}

[group('docker')]
dev-logs *SERVICE:
    docker compose -f dev.compose.yml logs -f {{SERVICE}}

[group('docker')]
dev-shell service='backend':
    docker compose -f dev.compose.yml exec -it {{service}} /bin/sh

# =============================================================================
# Cloudflare Tunnel
# =============================================================================

[group('tunnel')]
tunnel-up *ARGS:
    docker compose -f compose.yml -f cloudflared.compose.yml up {{ARGS}}

[group('tunnel')]
tunnel-start *ARGS:
    docker compose -f compose.yml -f cloudflared.compose.yml up -d {{ARGS}}

[group('tunnel')]
tunnel-down *ARGS:
    docker compose -f compose.yml -f cloudflared.compose.yml down {{ARGS}}

[group('tunnel')]
tunnel-logs:
    docker compose -f compose.yml -f cloudflared.compose.yml logs -f cloudflared

# =============================================================================
# Utilities
# =============================================================================

[group('util')]
info:
    @echo "Project:  {{project}}"
    @echo "Version:  {{version}}"
    @echo "Go:       $(go version | cut -d' ' -f3)"
    @echo "OS:       {{os()}} ({{arch()}})"
    @echo "Module:   $(head -1 go.mod | cut -d' ' -f2)"

[group('util')]
clean:
    -rm -rf bin/
    @echo "Cleaned build artifacts."
