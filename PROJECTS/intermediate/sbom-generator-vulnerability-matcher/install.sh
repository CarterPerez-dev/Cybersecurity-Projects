#!/usr/bin/env bash
# ©AngelaMos | 2026
# install.sh

set -euo pipefail

REPO_OWNER="CarterPerez-dev"
REPO_NAME="bomber"
BINARY="bomber"
INSTALL_DIR="${BOMBER_INSTALL_DIR:-$HOME/.bomber/bin}"
VERSION="${BOMBER_VERSION:-}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

info()   { echo -e "  ${GREEN}+${NC} $1"; }
warn()   { echo -e "  ${YELLOW}!${NC} $1"; }
fail()   { echo -e "  ${RED}x${NC} $1"; exit 1; }
header() { echo -e "\n${BOLD}${CYAN}--- $1 ---${NC}\n"; }

TMP_DIR=""
cleanup() { [[ -n "$TMP_DIR" ]] && rm -rf "$TMP_DIR"; }
trap cleanup EXIT

echo -e "${BOLD}"
echo -e "  ${RED} ██▄ ▄▀▄ █▄ ▄█ ██▄ ██▀ █▀▄ ${NC}"
echo -e "  ${CYAN} █▄█ ▀▄▀ █ ▀ █ █▄█ █▄▄ █▀▄ ${NC}"
echo -e "${NC}"
echo -e "  ${DIM}SBOM generator & vulnerability matcher${NC}"

header "Detecting system"

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)  OS="linux" ;;
    Darwin) OS="darwin" ;;
    MINGW*|MSYS*|CYGWIN*) fail "Windows is not supported. Use: go install github.com/${REPO_OWNER}/${REPO_NAME}/cmd/bomber@latest" ;;
    *) fail "Unsupported OS: $OS" ;;
esac

case "$ARCH" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) fail "Unsupported architecture: $ARCH" ;;
esac

info "System: ${OS}/${ARCH}"

if [[ -z "$VERSION" ]]; then
    header "Fetching latest release"

    if command -v curl &>/dev/null; then
        VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest" 2>/dev/null \
            | grep '"tag_name":' \
            | sed -E 's/.*"([^"]+)".*/\1/') || true
    elif command -v wget &>/dev/null; then
        VERSION=$(wget -qO- "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest" 2>/dev/null \
            | grep '"tag_name":' \
            | sed -E 's/.*"([^"]+)".*/\1/') || true
    fi
fi

INSTALLED=false

if [[ -n "$VERSION" ]]; then
    info "Version: ${VERSION}"
    header "Downloading pre-built binary"

    ARCHIVE="${BINARY}_${VERSION#v}_${OS}_${ARCH}.tar.gz"
    URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${VERSION}/${ARCHIVE}"

    TMP_DIR=$(mktemp -d)

    DOWNLOAD_OK=false
    if command -v curl &>/dev/null; then
        curl -fsSL "$URL" -o "$TMP_DIR/archive.tar.gz" 2>/dev/null && DOWNLOAD_OK=true
    elif command -v wget &>/dev/null; then
        wget -q "$URL" -O "$TMP_DIR/archive.tar.gz" 2>/dev/null && DOWNLOAD_OK=true
    else
        fail "Neither curl nor wget found"
    fi

    if [[ "$DOWNLOAD_OK" == "true" ]]; then
        tar -xzf "$TMP_DIR/archive.tar.gz" -C "$TMP_DIR"
        mkdir -p "$INSTALL_DIR"
        mv "$TMP_DIR/$BINARY" "$INSTALL_DIR/"
        chmod +x "$INSTALL_DIR/$BINARY"
        INSTALLED=true
        info "Installed to ${INSTALL_DIR}/${BINARY}"
    else
        warn "Pre-built binary not available for ${OS}/${ARCH}"
    fi
fi

if [[ "$INSTALLED" == "false" ]]; then
    if command -v go &>/dev/null; then
        GO_VER=$(go version | awk '{print $3}')
        header "Building from source (${GO_VER})"
        info "Running go install..."
        GOBIN="$INSTALL_DIR" go install "github.com/${REPO_OWNER}/${REPO_NAME}/cmd/bomber@latest"
        INSTALLED=true
        info "Installed to ${INSTALL_DIR}/${BINARY}"
    else
        echo ""
        fail "No pre-built binary and Go is not installed.

  Option 1 — Install Go, then:
    go install github.com/${REPO_OWNER}/${REPO_NAME}/cmd/bomber@latest

  Option 2 — Install Go:
    https://go.dev/dl/"
    fi
fi

header "Configuring PATH"

PATH_UPDATED=false

case ":$PATH:" in
    *":${INSTALL_DIR}:"*)
        info "${INSTALL_DIR} already in PATH"
        PATH_UPDATED=true
        ;;
esac

if [[ "$PATH_UPDATED" == "false" ]]; then
    CURRENT_SHELL="$(basename "${SHELL:-/bin/bash}")"
    TARGET=""

    case "$CURRENT_SHELL" in
        zsh)
            [[ -f "$HOME/.zshrc" ]] && TARGET="$HOME/.zshrc"
            ;;
        bash)
            if [[ -f "$HOME/.bashrc" ]]; then
                TARGET="$HOME/.bashrc"
            elif [[ -f "$HOME/.bash_profile" ]]; then
                TARGET="$HOME/.bash_profile"
            fi
            ;;
        fish)
            mkdir -p "$HOME/.config/fish/conf.d"
            echo "set -gx PATH \"$INSTALL_DIR\" \$PATH" > "$HOME/.config/fish/conf.d/bomber.fish"
            info "Added to ~/.config/fish/conf.d/bomber.fish"
            PATH_UPDATED=true
            ;;
    esac

    if [[ "$PATH_UPDATED" == "false" && -z "${TARGET:-}" ]]; then
        [[ -f "$HOME/.profile" ]] && TARGET="$HOME/.profile"
    fi

    if [[ "$PATH_UPDATED" == "false" && -n "${TARGET:-}" ]]; then
        if ! grep -q "$INSTALL_DIR" "$TARGET" 2>/dev/null; then
            printf '\nexport PATH="%s:$PATH"\n' "$INSTALL_DIR" >> "$TARGET"
            info "Added to ${TARGET}"
        else
            info "Already configured in ${TARGET}"
        fi
    fi
fi

echo ""
echo -e "  ${GREEN}${BOLD}bomber installed successfully${NC}"
echo ""

if ! command -v bomber &>/dev/null; then
    warn "Restart your shell or run:"
    echo -e "    ${BOLD}export PATH=\"${INSTALL_DIR}:\$PATH\"${NC}"
    echo ""
fi

echo -e "  ${DIM}Quick start:${NC}"
echo ""
echo -e "    ${CYAN}bomber scan [path]${NC}                  Scan dependencies"
echo -e "    ${CYAN}bomber generate [path] --format spdx${NC} Generate SPDX SBOM"
echo -e "    ${CYAN}bomber vuln [path]${NC}                  Check for vulnerabilities"
echo -e "    ${CYAN}bomber check [path] --policy p.yaml${NC} CI/CD policy gate"
echo ""
echo -e "  ${DIM}Docs: https://github.com/${REPO_OWNER}/Cybersecurity-Projects${NC}"
echo ""
