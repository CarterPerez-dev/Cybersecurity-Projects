#!/usr/bin/env bash
# ©AngelaMos | 2026
# install.sh

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
fail()    { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }

PROJECT="cisaudit"
INSTALL_DIR="${HOME}/.local/bin"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BOLD}${CYAN}"
cat << 'BANNER'
   _____ ___ ____    _             _ _ _
  / ____|_ _/ ___|  / \  _   _  __| (_) |_
 | |     | |\___ \ / _ \| | | |/ _` | | __|
 | |___  | | ___) / ___ \ |_| | (_| | | |_
  \____|___|____/_/   \_\__,_|\__,_|_|\__|

  CIS Benchmark Compliance Auditor
BANNER
echo -e "${NC}"

check_bash_version() {
    if (( BASH_VERSINFO[0] < 4 )); then
        fail "Bash 4+ required (found ${BASH_VERSION})"
    fi
    success "Bash ${BASH_VERSION}"
}

check_dependencies() {
    local deps=(grep awk sed stat date hostname)
    local missing=()

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        fail "Missing required tools: ${missing[*]}"
    fi
    success "All dependencies found"
}

install_shellcheck() {
    if command -v shellcheck &> /dev/null; then
        success "shellcheck found (optional, for development)"
        return
    fi

    info "shellcheck not found (optional, for linting)"
    read -rp "Install shellcheck for development? [y/N] " answer
    if [[ "${answer,,}" != "y" ]]; then
        return
    fi

    if command -v apt-get &> /dev/null; then
        sudo apt-get install -y shellcheck
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y ShellCheck
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm shellcheck
    elif command -v brew &> /dev/null; then
        brew install shellcheck
    else
        warn "Could not detect package manager — install shellcheck manually"
        return
    fi
    success "shellcheck installed"
}

make_executable() {
    find "${SCRIPT_DIR}/src" -name "*.sh" -exec chmod +x {} \;
    success "All scripts marked executable"
}

install_binary() {
    mkdir -p "${INSTALL_DIR}"
    ln -sf "${SCRIPT_DIR}/src/cisaudit.sh" "${INSTALL_DIR}/${PROJECT}"
    success "Linked ${PROJECT} to ${INSTALL_DIR}/${PROJECT}"
}

ensure_path() {
    if echo "$PATH" | grep -q "${INSTALL_DIR}"; then
        return
    fi

    warn "${INSTALL_DIR} is not in your PATH"

    SHELL_NAME=$(basename "${SHELL:-bash}")
    case "${SHELL_NAME}" in
        zsh)  RC_FILE="${HOME}/.zshrc" ;;
        fish) RC_FILE="${HOME}/.config/fish/config.fish" ;;
        *)    RC_FILE="${HOME}/.bashrc" ;;
    esac

    if [[ "${SHELL_NAME}" == "fish" ]]; then
        PATH_LINE="fish_add_path ${INSTALL_DIR}"
    else
        PATH_LINE="export PATH=\"${INSTALL_DIR}:\$PATH\""
    fi

    if [[ -f "${RC_FILE}" ]] && grep -q "${INSTALL_DIR}" "${RC_FILE}" 2>/dev/null; then
        info "PATH entry already in ${RC_FILE}"
    else
        echo "${PATH_LINE}" >> "${RC_FILE}"
        success "Added ${INSTALL_DIR} to PATH in ${RC_FILE}"
        warn "Run 'source ${RC_FILE}' or restart your shell"
    fi

    export PATH="${INSTALL_DIR}:${PATH}"
}

verify_install() {
    if command -v "${PROJECT}" &> /dev/null; then
        VERSION=$("${PROJECT}" --version 2>/dev/null || echo "unknown")
        success "Verification passed: ${VERSION}"
    else
        warn "Installed but not found in PATH"
        info "Run: ${INSTALL_DIR}/${PROJECT} --version"
    fi
}

check_bash_version
check_dependencies
make_executable
install_binary
ensure_path
install_shellcheck
verify_install

echo ""
echo -e "${GREEN}${BOLD}Installation complete!${NC}"
echo ""
echo -e "${BOLD}Usage:${NC}"
echo "  sudo cisaudit"
echo "  sudo cisaudit -l 1 -f json -o report.json"
echo "  sudo cisaudit -f html -o report.html"
echo "  cisaudit -t testdata/fixtures -f terminal"
echo "  cisaudit --list-controls"
echo ""
echo -e "${BOLD}Run tests:${NC}"
echo "  just test"
echo ""
