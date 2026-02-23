# =============================================================================
# AngelaMos | 2026
# Justfile
# =============================================================================
# portia — Secrets scanner for codebases and git repositories
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

[group('test')]
cover-html:
    go test -race -coverprofile=coverage.out ./...
    go tool cover -html=coverage.out -o coverage.html
    @echo "Coverage report: coverage.html"

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
    go run ./cmd/portia {{ARGS}}

[group('dev')]
dev-scan:
    go run ./cmd/portia scan testdata/

[group('dev')]
dev-git:
    go run ./cmd/portia git .

[group('dev')]
dev-json:
    go run ./cmd/portia scan --format json testdata/

[group('dev')]
dev-sarif:
    go run ./cmd/portia scan --format sarif testdata/

[group('dev')]
dev-rules:
    go run ./cmd/portia config rules

# =============================================================================
# Build (Production)
# =============================================================================

[group('prod')]
build:
    go build -ldflags="-s -w" -o bin/portia ./cmd/portia
    @echo "Built: bin/portia ($(du -h bin/portia | cut -f1))"

[group('prod')]
build-debug:
    go build -o bin/portia ./cmd/portia

[group('prod')]
install:
    go install ./cmd/portia

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
update:
    go get -u ./...
    go mod tidy

[group('util')]
clean:
    -rm -rf bin/ coverage.out coverage.html
    @echo "Cleaned build artifacts."
