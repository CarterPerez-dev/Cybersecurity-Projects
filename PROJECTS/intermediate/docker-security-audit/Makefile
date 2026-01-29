# docksec Makefile
# CarterPerez-dev | 2025
# MakeFile instead of Justfile so its more compabitle and no need to intsall Just

BINARY_NAME := docksec
MODULE := github.com/CarterPerez-dev/docksec
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -ldflags "-s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.buildDate=$(BUILD_DATE)"

GO := go
GOFLAGS := -trimpath

.PHONY: all build clean test lint fmt vet install run help \
	tools format imports check

all: build

build:
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/docksec

build-all: build-linux build-darwin build-windows

build-linux:
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-amd64 ./cmd/docksec
	GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-arm64 ./cmd/docksec

build-darwin:
	GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-amd64 ./cmd/docksec
	GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-arm64 ./cmd/docksec

build-windows:
	GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/$(BINARY_NAME)-windows-amd64.exe ./cmd/docksec

install:
	$(GO) install $(GOFLAGS) $(LDFLAGS) ./cmd/docksec

clean:
	rm -rf bin/
	$(GO) clean -cache -testcache

test:
	$(GO) test -v -race -cover ./...

test-short:
	$(GO) test -v -short ./...

test-coverage:
	$(GO) test -v -race -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

tools:
	@echo "Installing formatting and linting tools..."
	go install github.com/segmentio/golines@latest
	go install mvdan.cc/gofumpt@latest
	go install github.com/daixiang0/gci@latest
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b $$(go env GOPATH)/bin v2.7.2
	@echo "Tools installed successfully"

format:
	@which golines > /dev/null || (echo "Run 'make tools' first" && exit 1)
	golines . -w --max-len=80 --reformat-tags --shorten-comments --formatter=gofumpt

imports:
	@which gci > /dev/null || (echo "Run 'make tools' first" && exit 1)
	gci write . --skip-generated -s standard -s default -s "prefix(github.com/CarterPerez-dev/docksec)"

lint:
	@which golangci-lint > /dev/null || (echo "Run 'make tools' first" && exit 1)
	golangci-lint run ./...

check: format imports lint
	@echo "All checks passed"

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

tidy:
	$(GO) mod tidy

verify: fmt vet lint test

run:
	$(GO) run ./cmd/docksec $(ARGS)

run-scan:
	$(GO) run ./cmd/docksec scan

docker-build:
	docker build -t $(BINARY_NAME):$(VERSION) -t $(BINARY_NAME):latest .

docker-run:
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock $(BINARY_NAME):latest scan

help:
	@echo "docksec - Docker Security Audit Tool"
	@echo ""
	@echo "Usage:"
	@echo "  make build        Build binary for current platform"
	@echo "  make build-all    Build binaries for all platforms"
	@echo "  make install      Install to GOPATH/bin"
	@echo "  make clean        Remove build artifacts"
	@echo ""
	@echo "Testing:"
	@echo "  make test         Run tests with race detection"
	@echo "  make test-coverage Generate coverage report"
	@echo ""
	@echo "Code Quality (run 'make tools' first):"
	@echo "  make tools        Install golines, gofumpt, gci, golangci-lint"
	@echo "  make format       Format code (golines + gofumpt, max-len=80)"
	@echo "  make imports      Organize imports (gci)"
	@echo "  make lint         Run golangci-lint"
	@echo "  make check        Run format + imports + lint"
	@echo ""
	@echo "Legacy/Quick:"
	@echo "  make fmt          Run go fmt"
	@echo "  make vet          Run go vet"
	@echo "  make tidy         Run go mod tidy"
	@echo "  make verify       Run fmt, vet, lint, and test"
	@echo ""
	@echo "Run:"
	@echo "  make run          Run with ARGS='...'"
	@echo "  make run-scan     Run scan command"
	@echo "  make docker-build Build Docker image"
	@echo "  make docker-run   Run scan in Docker"
	@echo ""
	@echo "  make help         Show this help"
