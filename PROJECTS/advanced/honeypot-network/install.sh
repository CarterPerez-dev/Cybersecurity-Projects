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
MIN_NODE="20"

banner() {
    printf "\n"
    printf "${CYAN}"
    cat <<'EOF'
  ██╗  ██╗██╗██╗   ██╗███████╗
  ██║  ██║██║██║   ██║██╔════╝
  ███████║██║██║   ██║█████╗
  ██╔══██║██║╚██╗ ██╔╝██╔══╝
  ██║  ██║██║ ╚████╔╝ ███████╗
  ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝
EOF
    printf "${NC}"
    printf "  ${DIM}honeypot network installer${NC}\n"
    printf "\n"
}

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

check_node() {
    if ! command -v node &>/dev/null; then
        fail "Node.js is not installed. Get it at https://nodejs.org/"
    fi

    local ver
    ver=$(node -v | sed 's/^v//' | cut -d. -f1)

    if [ "$ver" -lt "$MIN_NODE" ]; then
        fail "Node $MIN_NODE+ required (found v$ver)"
    fi

    ok "Node $(node -v)"
}

check_pnpm() {
    if ! command -v pnpm &>/dev/null; then
        info "pnpm not found. Installing via corepack..."
        corepack enable
        corepack prepare pnpm@latest --activate
    fi
    ok "pnpm $(pnpm -v 2>/dev/null)"
}

check_docker() {
    if command -v docker &>/dev/null; then
        ok "Docker $(docker --version 2>/dev/null | grep -oP '[0-9]+\.[0-9]+\.[0-9]+')"
    else
        info "Docker not found (optional). Install: https://docs.docker.com/get-docker/"
    fi
}

check_just() {
    if command -v just &>/dev/null; then
        ok "just $(just --version 2>/dev/null | head -1)"
    else
        info "just not found (optional). Install: curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin"
    fi
}

build_and_install() {
    info "Building hive binary..."
    go mod tidy
    go build -ldflags="-s -w" -o bin/hive ./cmd/hive
    local size
    size=$(du -h bin/hive | cut -f1)
    ok "Built bin/hive ($size)"

    info "Installing hive to GOPATH..."
    go install -ldflags="-s -w" ./cmd/hive
    ok "Installed hive → $(go env GOPATH)/bin/hive"
}

install_frontend() {
    info "Installing frontend dependencies..."
    cd frontend
    pnpm install --frozen-lockfile 2>/dev/null || pnpm install
    ok "Frontend dependencies installed"
    cd ..
}

run_tests() {
    info "Running Go tests..."
    if go test -race ./... >/dev/null 2>&1; then
        ok "All Go tests passed"
    else
        fail "Tests failed. Run 'go test -v ./...' for details."
    fi
}

main() {
    banner

    info "Checking dependencies..."
    check_go
    check_node
    check_pnpm
    check_docker
    check_just

    printf "\n"

    build_and_install
    install_frontend
    run_tests

    printf "\n"
    ok "Setup complete"
    printf "\n"
    printf "  ${DIM}Verify:${NC}            hive version\n"
    printf "  ${DIM}Run with Docker:${NC}   just dev-up\n"
    printf "  ${DIM}Run locally:${NC}       just dev-serve\n"
    printf "  ${DIM}Run frontend:${NC}      cd frontend && pnpm dev\n"
    printf "\n"
}

main "$@"
