#!/usr/bin/env bash
# ©AngelaMos | 2026
# install.sh

set -euo pipefail

REPO_OWNER="CarterPerez-dev"
REPO_NAME="credential-enumeration"
BINARY="credenum"
INSTALL_DIR="${CREDENUM_INSTALL_DIR:-$HOME/.credenum/bin}"
VERSION="${CREDENUM_VERSION:-}"
MIN_NIM_MAJOR=2
MIN_NIM_MINOR=2

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
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
echo -e "  ${RED} ▄▀▀ █▀▄ ██▀ █▀▄ ██▀ █▄ █ █ █ █▄▄▀▄${NC}"
echo -e "  ${CYAN} ▀▄▄ █▀▄ █▄▄ █▄▀ █▄▄ █ ▀█ ▀▄█ █  ▀▄${NC}"
echo -e "${NC}"
echo -e "  ${DIM}Post-access credential exposure detection for Linux${NC}"

header "Detecting system"

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)  OS="linux" ;;
    Darwin) OS="darwin" ;;
    MINGW*|MSYS*|CYGWIN*) fail "Windows is not supported. This tool targets Linux credential stores." ;;
    *) fail "Unsupported OS: $OS" ;;
esac

case "$ARCH" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) fail "Unsupported architecture: $ARCH" ;;
esac

info "System: ${OS}/${ARCH}"

header "Checking Nim"

if ! command -v nim &>/dev/null; then
    fail "Nim is not installed.

  Install via choosenim:
    curl https://nim-lang.org/choosenim/init.sh -sSf | sh

  Or visit: https://nim-lang.org/install.html"
fi

NIM_VER=$(nim --version | head -1 | grep -oP '\d+\.\d+\.\d+')
NIM_MAJOR=$(echo "$NIM_VER" | cut -d. -f1)
NIM_MINOR=$(echo "$NIM_VER" | cut -d. -f2)

if [[ "$NIM_MAJOR" -lt "$MIN_NIM_MAJOR" ]] || { [[ "$NIM_MAJOR" -eq "$MIN_NIM_MAJOR" ]] && [[ "$NIM_MINOR" -lt "$MIN_NIM_MINOR" ]]; }; then
    fail "Nim ${MIN_NIM_MAJOR}.${MIN_NIM_MINOR}+ required (found ${NIM_VER}).
  Run: choosenim stable"
fi

info "Nim ${NIM_VER}"

header "Building from source"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR"

if [[ ! -f "$SRC_DIR/credential-enumeration.nimble" ]]; then
    fail "Run install.sh from the project root directory."
fi

info "Compiling credenum..."

mkdir -p "$SRC_DIR/bin"

STATIC_FLAGS=""
if command -v musl-gcc &>/dev/null; then
    STATIC_FLAGS="-d:musl"
    info "Using musl for static binary"
fi

nim c -d:release ${STATIC_FLAGS} --opt:size -o:"$SRC_DIR/bin/credenum" "$SRC_DIR/src/harvester.nim"
strip -s "$SRC_DIR/bin/credenum" 2>/dev/null || true

info "Built: bin/credenum ($(du -h "$SRC_DIR/bin/credenum" | cut -f1))"

header "Installing"

mkdir -p "$INSTALL_DIR"
cp "$SRC_DIR/bin/credenum" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/$BINARY"
info "Installed to ${INSTALL_DIR}/${BINARY}"

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
            echo "set -gx PATH \"$INSTALL_DIR\" \$PATH" > "$HOME/.config/fish/conf.d/credenum.fish"
            info "Added to ~/.config/fish/conf.d/credenum.fish"
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
echo -e "  ${GREEN}${BOLD}credenum installed successfully${NC}"
echo ""

if ! command -v credenum &>/dev/null; then
    warn "Restart your shell or run:"
    echo -e "    ${BOLD}export PATH=\"${INSTALL_DIR}:\$PATH\"${NC}"
    echo ""
fi

echo -e "  ${DIM}Quick start:${NC}"
echo ""
echo -e "    ${CYAN}credenum${NC}                   Scan current user"
echo -e "    ${CYAN}credenum --format json${NC}      JSON output"
echo -e "    ${CYAN}credenum --modules ssh,git${NC}  Scan specific modules"
echo -e "    ${CYAN}credenum --dry-run${NC}          Preview scan paths"
echo ""
echo -e "  ${DIM}Docs: https://github.com/${REPO_OWNER}/Cybersecurity-Projects${NC}"
echo ""
