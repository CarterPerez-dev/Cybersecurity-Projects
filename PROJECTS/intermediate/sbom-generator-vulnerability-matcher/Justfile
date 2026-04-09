# ©AngelaMos | 2026
# Justfile

set export
set shell := ["bash", "-uc"]

project := file_name(justfile_directory())
version := `git describe --tags --always 2>/dev/null || echo "dev"`

default:
    @just --list --unsorted

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

[group('ci')]
ci: lint test
    @echo "All checks passed."

[group('ci')]
check: lint vet

[group('dev')]
run *ARGS:
    go run ./cmd/bomber {{ARGS}}

[group('dev')]
dev-scan:
    go run ./cmd/bomber scan .

[group('dev')]
dev-generate:
    go run ./cmd/bomber generate . --format cyclonedx

[group('dev')]
dev-vuln:
    go run ./cmd/bomber vuln .

[group('dev')]
dev-check:
    go run ./cmd/bomber check . --policy policy.yaml

[group('prod')]
build:
    go build -ldflags="-s -w" -o bin/bomber ./cmd/bomber
    @echo "Built: bin/bomber ($(du -h bin/bomber | cut -f1))"

[group('prod')]
build-debug:
    go build -o bin/bomber ./cmd/bomber

[group('prod')]
install:
    go install ./cmd/bomber

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
