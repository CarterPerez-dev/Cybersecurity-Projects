#!/usr/bin/env bash
# ©AngelaMos | 2026
# install.sh

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
DIM='\033[2m'
NC='\033[0m'

info()  { printf "${CYAN}▸${NC} %s\n" "$1"; }
ok()    { printf "${GREEN}✓${NC} %s\n" "$1"; }
fail()  { printf "${RED}✗${NC} %s\n" "$1"; exit 1; }

MIN_GO="1.25"

check_go() {
    if ! command -v go &>/dev/null; then
        fail "Go is not installed. Get it at https://go.dev/dl/"
    fi

    local ver
    ver=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+')

    if ! printf '%s\n%s\n' "$MIN_GO" "$ver" \
        | sort -V | head -n1 | grep -qx "$MIN_GO"; then
        fail "Go $MIN_GO+ required (found $ver)"
    fi

    ok "Go $ver"
}

check_just() {
    if command -v just &>/dev/null; then
        ok "just $(just --version 2>/dev/null | head -1)"
    else
        info "just not found (optional). Install: curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin"
    fi
}

build() {
    info "Building sentinel..."
    go build -ldflags="-s -w" -o bin/sentinel ./cmd/sentinel
    local size
    size=$(du -h bin/sentinel | cut -f1)
    ok "Built bin/sentinel ($size)"
}

run_tests() {
    info "Running tests..."
    if go test -race ./... >/dev/null 2>&1; then
        ok "All tests passed"
    else
        fail "Tests failed. Run 'go test -v ./...' for details."
    fi
}

main() {
    printf "\n${CYAN}sentinel${NC} ${DIM}installer${NC}\n\n"

    check_go
    check_just

    info "Downloading dependencies..."
    go mod download
    ok "Dependencies ready"

    build
    run_tests

    printf "\n${GREEN}Done.${NC} Run ${CYAN}./bin/sentinel scan${NC} to start scanning.\n\n"
}

main "$@"
