#!/usr/bin/env bash
# ©AngelaMos | 2026
# install.sh

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
fail() { echo -e "${RED}[-]${NC} $1"; exit 1; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        warn "Some steps require root. You may be prompted for sudo."
    fi
}

check_kernel() {
    local version
    version=$(uname -r | cut -d. -f1-2)
    local major minor
    major=$(echo "$version" | cut -d. -f1)
    minor=$(echo "$version" | cut -d. -f2)

    if [[ $major -lt 5 ]] || { [[ $major -eq 5 ]] && [[ $minor -lt 8 ]]; }; then
        fail "Kernel $version detected. Requires Linux 5.8+ for ring buffer support."
    fi
    info "Kernel version $(uname -r) meets requirements (5.8+)"
}

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}

install_system_deps() {
    local distro
    distro=$(detect_distro)

    case "$distro" in
        ubuntu|debian|pop|linuxmint|kali)
            info "Detected Debian-based system ($distro)"
            sudo apt-get update -qq
            sudo apt-get install -y -qq \
                bpfcc-tools \
                python3-bpfcc \
                libbpfcc-dev \
                linux-headers-"$(uname -r)" \
                2>/dev/null || true
            ;;
        fedora)
            info "Detected Fedora"
            sudo dnf install -y \
                bcc-tools \
                python3-bcc \
                bcc-devel \
                kernel-headers \
                kernel-devel \
                2>/dev/null || true
            ;;
        rhel|centos|rocky|alma)
            info "Detected RHEL-based system ($distro)"
            sudo yum install -y \
                bcc-tools \
                python3-bcc \
                bcc-devel \
                kernel-headers \
                kernel-devel \
                2>/dev/null || true
            ;;
        arch|manjaro|endeavouros)
            info "Detected Arch-based system ($distro)"
            sudo pacman -Sy --noconfirm \
                bcc \
                bcc-tools \
                python-bcc \
                linux-headers \
                2>/dev/null || true
            ;;
        *)
            warn "Unknown distro: $distro"
            warn "Install manually: bcc-tools, python3-bcc, linux-headers"
            ;;
    esac
}

install_python_deps() {
    if ! command -v uv &>/dev/null; then
        info "Installing uv..."
        curl -LsSf https://astral.sh/uv/install.sh | sh
        export PATH="$HOME/.local/bin:$PATH"
    fi

    info "Installing Python dependencies with uv..."
    uv sync
}

verify_install() {
    info "Verifying installation..."

    if python3 -c "import bcc" 2>/dev/null; then
        info "BCC Python bindings: OK"
    else
        warn "BCC Python bindings not found in system Python"
        warn "Make sure python3-bpfcc (Debian) or python3-bcc (Fedora/Arch) is installed"
    fi

    if [[ -d /sys/kernel/debug/tracing ]]; then
        info "Tracing filesystem: OK"
    else
        warn "Tracing filesystem not mounted. Try: sudo mount -t debugfs debugfs /sys/kernel/debug"
    fi
}

main() {
    info "eBPF Security Tracer - Installation"
    echo ""
    check_root
    check_kernel
    install_system_deps
    install_python_deps
    verify_install
    echo ""
    info "Installation complete. Run with: sudo uv run ebpf-tracer"
}

main "$@"
