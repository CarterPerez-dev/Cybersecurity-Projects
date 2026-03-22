#!/usr/bin/env bash
# ©AngelaMos | 2026
# install.sh

set -euo pipefail

GREEN='\033[32m'
CYAN='\033[36m'
RED='\033[31m'
BOLD='\033[1m'
RESET='\033[0m'

info() { echo -e "${CYAN}[*]${RESET} $1"; }
success() { echo -e "${GREEN}[✔]${RESET} $1"; }
fail() { echo -e "${RED}[✖]${RESET} $1"; exit 1; }

install_deps() {
    if command -v apt-get &>/dev/null; then
        info "Detected apt (Debian/Ubuntu)"
        sudo apt-get update -qq
        sudo apt-get install -y -qq g++ cmake ninja-build libssl-dev libboost-program-options-dev
    elif command -v dnf &>/dev/null; then
        info "Detected dnf (Fedora/RHEL)"
        sudo dnf install -y gcc-c++ cmake ninja-build openssl-devel boost-program-options
    elif command -v pacman &>/dev/null; then
        info "Detected pacman (Arch)"
        sudo pacman -S --needed --noconfirm gcc cmake ninja openssl boost
    elif command -v brew &>/dev/null; then
        info "Detected brew (macOS)"
        brew install cmake ninja openssl boost
    else
        fail "Unsupported package manager. Install manually: g++, cmake, ninja, libssl-dev, libboost-program-options-dev"
    fi
}

build_project() {
    info "Configuring release build..."
    cmake --preset release

    info "Building..."
    cmake --build build/release
}

info "Installing dependencies..."
install_deps

info "Building hashcracker..."
build_project

echo ""
success "hashcracker built successfully!"
echo ""
echo -e "${BOLD}Usage:${RESET}"
echo "  ./build/release/hashcracker --hash <hash> --wordlist <path>"
echo "  ./build/release/hashcracker --hash <hash> --bruteforce --charset lower,digits"
echo "  ./build/release/hashcracker --hash <hash> --wordlist <path> --rules"
echo ""
echo -e "${BOLD}Or use just:${RESET}"
echo "  just run -- --hash <hash> --wordlist <path>"
echo ""
