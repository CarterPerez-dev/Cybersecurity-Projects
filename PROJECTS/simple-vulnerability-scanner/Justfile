# =============================================================================
# AngelaMos | 2026
# Justfile
# =============================================================================
# angela — Python dependency updater and vulnerability scanner
# =============================================================================

set export
set shell := ["bash", "-uc"]

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
lint *ARGS:
    golangci-lint run --timeout=5m {{ARGS}}

[group('lint')]
lint-fix:
    golangci-lint run --timeout=5m --fix

[group('lint')]
fmt:
    gofumpt -w .
    golines -w --max-len=80 .

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
    go run ./cmd/angela {{ARGS}}

[group('dev')]
dev-check:
    go run ./cmd/angela check --file testdata/pyproject.toml

[group('dev')]
dev-update:
    go run ./cmd/angela update --file testdata/pyproject.toml

[group('dev')]
dev-scan:
    go run ./cmd/angela scan --file testdata/pyproject.toml

[group('dev')]
dev-full:
    go run ./cmd/angela update --vulns --file testdata/pyproject.toml

# =============================================================================
# Build (Production)
# =============================================================================

[group('prod')]
build:
    go build -ldflags="-s -w" -o bin/angela ./cmd/angela
    @echo "Built: bin/angela ($(du -h bin/angela | cut -f1))"

[group('prod')]
build-debug:
    go build -o bin/angela ./cmd/angela

[group('prod')]
install:
    go install ./cmd/angela

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

[group('util')]
reset-cache:
    rm -rf ~/.angela/cache/
    @echo "Cache cleared."
