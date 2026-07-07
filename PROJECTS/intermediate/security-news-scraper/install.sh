#!/usr/bin/env bash
# ©AngelaMos | 2026
# install.sh
#
# One-shot installer for nadezhda. Takes a fresh machine to `nadezhda` runnable
# by its bare name, with zero further steps, whether run from a clone or piped
# from a domain via curl. Prefers a prebuilt release binary (no Go needed);
# falls back to building from source (auto-installs the Go toolchain if absent).

set -euo pipefail

# ============================================================================
# CONFIG
# ============================================================================
REPO_OWNER="CarterPerez-dev"
REPO_NAME="nadezhda"
BINARY="nadezhda"
TAGLINE="Security news + CVE intelligence in your terminal. Keyless by default."
REPO_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}.git"
INSTALL_DIR="${NADEZHDA_INSTALL_DIR:-$HOME/.local/bin}"
DEFAULT_BRANCH="main"
GO_MIN="1.21"
PREBUILT=1

# ============================================================================
# Colors
# ============================================================================
if [ -t 2 ] && [ -z "${NO_COLOR:-}" ]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GREEN=$'\033[32m'
    YELLOW=$'\033[33m'; CYAN=$'\033[36m'; RESET=$'\033[0m'
else
    BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; CYAN=""; RESET=""
fi

info() { printf '%s\n' "  ${CYAN}+${RESET} $*" >&2; }
ok()   { printf '%s\n' "  ${GREEN}+${RESET} $*" >&2; }
warn() { printf '%s\n' "  ${YELLOW}!${RESET} $*" >&2; }
die()  { printf '%s\n' "  ${RED}x $*${RESET}" >&2; exit 1; }
header(){ printf '\n%s\n\n' "${BOLD}${CYAN}--- $* ---${RESET}" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

trap 'printf "%s\n" "${RED}x install failed${RESET}" >&2' ERR
TMP_DIR=""
cleanup() { [ -n "$TMP_DIR" ] && rm -rf "$TMP_DIR"; return 0; }
trap cleanup EXIT

banner() {
    printf '%s' "${CYAN}${BOLD}" >&2
    cat >&2 <<'ART'
   ╭───────────────────────╮
   │    n a d e z h d a    │
   ╰───────────────────────╯
ART
    printf '%s\n' "${RESET}" >&2
    printf '%s\n' "  ${DIM}${TAGLINE}${RESET}" >&2
}

# ============================================================================
# Privilege + package-manager fan
# ============================================================================
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if have sudo; then SUDO="sudo"; fi
fi

pkg_install() {
    if   have apt-get; then $SUDO apt-get update -y || warn "apt update had errors; continuing"
                            $SUDO apt-get install -y --no-install-recommends "$@"
    elif have dnf;     then $SUDO dnf install -y "$@"
    elif have pacman;  then $SUDO pacman -S --needed --noconfirm "$@"
    elif have zypper;  then $SUDO zypper install -y "$@"
    elif have apk;     then $SUDO apk add "$@"
    elif have brew;    then brew install "$@"
    else die "no known package manager. Install manually: $*"; fi
}

download() {
    if   have curl; then curl -fsSL "$1" -o "$2" || return 1
    elif have wget; then wget -qO "$2" "$1" || return 1
    else die "need curl or wget"; fi
}

# ============================================================================
# Args
# ============================================================================
usage() {
    cat >&2 <<USAGE
install.sh — install ${BINARY}

  ./install.sh [options]
  curl -fsSL https://angelamos.com/${BINARY}/install.sh | bash

options:
  --prefix DIR   install dir (default: ${INSTALL_DIR})
  -h, --help     this help
USAGE
}
while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) INSTALL_DIR="$2"; shift 2 ;;
        --prefix=*) INSTALL_DIR="${1#*=}"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
done

# ============================================================================
# OS / arch
# ============================================================================
OS="$(uname -s)"; ARCH="$(uname -m)"
case "$OS" in
    Linux) OS="linux" ;; Darwin) OS="darwin" ;;
    MINGW*|MSYS*|CYGWIN*) die "Windows unsupported. Use WSL, or: go install github.com/${REPO_OWNER}/${REPO_NAME}/cmd/${BINARY}@latest" ;;
    *) die "unsupported OS: $OS" ;;
esac
case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;; aarch64|arm64) ARCH="arm64" ;;
    *) die "unsupported arch: $ARCH" ;;
esac

# ============================================================================
# Bootstrap
# ============================================================================
resolve_repo() {
    if [ -f "./go.mod" ]; then pwd; return; fi
    have git || { warn "git missing — installing it"; pkg_install git; }
    have git || die "could not install git; install it then re-run"
    local cache="${XDG_CACHE_HOME:-$HOME/.cache}/${BINARY}"
    if [ -d "$cache/.git" ]; then
        info "updating cached clone at $cache"
        git -C "$cache" pull --ff-only --quiet 2>/dev/null || warn "pull failed; using existing clone"
    else
        info "cloning ${REPO_URL}"
        git clone --depth 1 --branch "$DEFAULT_BRANCH" --quiet "$REPO_URL" "$cache" \
            || die "clone failed from ${REPO_URL}"
    fi
    printf '%s\n' "$cache"
}

# ============================================================================
# Toolchain (Go) + build from source
# ============================================================================
install_go() {
    info "installing a current Go toolchain"
    local latest tgz
    latest="$(download "https://go.dev/VERSION?m=text" /dev/stdout 2>/dev/null | head -n1)" || latest=""
    case "$latest" in go*) ;; *) latest="go1.25.5" ;; esac
    tgz="${latest}.${OS}-${ARCH}.tar.gz"
    TMP_DIR="${TMP_DIR:-$(mktemp -d)}"
    download "https://go.dev/dl/${tgz}" "$TMP_DIR/go.tgz" || die "failed to download ${tgz} from go.dev/dl"
    rm -rf "$HOME/.local/go"
    mkdir -p "$HOME/.local"
    tar -C "$HOME/.local" -xzf "$TMP_DIR/go.tgz" || die "failed to extract Go"
    export PATH="$HOME/.local/go/bin:$PATH"
    export GOTOOLCHAIN=auto
    have go || die "Go toolchain install failed"
    ok "go $(go env GOVERSION 2>/dev/null | sed 's/^go//') at ~/.local/go"
}

need_toolchain() {
    local cur
    if have go; then
        cur="$(go env GOVERSION 2>/dev/null | sed 's/^go//')"
        if [ -n "$cur" ] && [ "$(printf '%s\n%s\n' "$GO_MIN" "$cur" | sort -V | head -n1)" = "$GO_MIN" ]; then
            export GOTOOLCHAIN=auto
            ok "go $cur (auto-toolchain fetches the go.mod-pinned version if newer)"
            return
        fi
        warn "go ${cur:-unknown} predates toolchain auto-download; installing a current Go"
    fi
    install_go
}

build_from_source() {
    info "building ${BINARY} (compiles the pure-Go SQLite driver; give it a minute)"
    mkdir -p "$INSTALL_DIR"
    GOBIN="$INSTALL_DIR" go install ./cmd/nadezhda || die "go install failed"
    ok "installed ${BINARY} -> ${INSTALL_DIR}/${BINARY}"
}

try_prebuilt() {
    [ "$PREBUILT" = "1" ] || return 1
    local ver archive url
    ver="$(download "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest" /dev/stdout 2>/dev/null \
          | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')" || true
    [ -n "$ver" ] || return 1
    archive="${BINARY}_${ver#v}_${OS}_${ARCH}.tar.gz"
    url="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${ver}/${archive}"
    TMP_DIR="$(mktemp -d)"
    download "$url" "$TMP_DIR/a.tgz" || { warn "no prebuilt for ${OS}/${ARCH}; will build from source"; return 1; }
    tar -xzf "$TMP_DIR/a.tgz" -C "$TMP_DIR" || return 1
    mkdir -p "$INSTALL_DIR"; install -m 0755 "$TMP_DIR/$BINARY" "$INSTALL_DIR/$BINARY"
    ok "installed prebuilt ${ver} -> ${INSTALL_DIR}/${BINARY}"
}

# ============================================================================
# PATH wiring
# ============================================================================
wire_path() {
    case ":$PATH:" in *":$INSTALL_DIR:"*) ok "$INSTALL_DIR already on PATH"; return ;; esac
    local shell rc=""
    shell="$(basename "${SHELL:-bash}")"
    case "$shell" in
        zsh)  rc="$HOME/.zshrc" ;;
        fish) mkdir -p "$HOME/.config/fish/conf.d"
              echo "fish_add_path $INSTALL_DIR" > "$HOME/.config/fish/conf.d/${BINARY}.fish"
              ok "added to fish conf.d" ;;
        bash) rc="$HOME/.bashrc"; [ -f "$rc" ] || rc="$HOME/.bash_profile" ;;
        *)    rc="$HOME/.profile" ;;
    esac
    if [ -n "$rc" ] && ! grep -q "$INSTALL_DIR" "$rc" 2>/dev/null; then
        printf '\nexport PATH="%s:$PATH"\n' "$INSTALL_DIR" >> "$rc"
        ok "added $INSTALL_DIR to PATH in $rc"
    fi
    export PATH="$INSTALL_DIR:$PATH"
}

# ============================================================================
# Main
# ============================================================================
main() {
    banner
    have "$BINARY" && info "existing install at $(command -v "$BINARY") — updating"

    REPO=""
    if ! try_prebuilt; then
        header "Building from source"
        REPO="$(resolve_repo)"; cd "$REPO"
        need_toolchain
        build_from_source
    fi

    wire_path

    header "Verify"
    if have "$BINARY"; then
        ok "$BINARY -> $(command -v "$BINARY")"
        "$BINARY" version 2>/dev/null || true
    else
        warn "installed to $INSTALL_DIR but not yet on PATH — open a new shell"
    fi

    printf '\n%s\n\n' "  ${GREEN}${BOLD}${BINARY} is ready.${RESET}" >&2
    if have just && [ -n "$REPO" ] && [ -f "${REPO}/justfile" ]; then
        printf '%s\n' "  ${DIM}dev commands:${RESET}  just" >&2
    fi
    cat >&2 <<FOOTER
  ${DIM}quick start:${RESET}
    ${CYAN}${BINARY} scrape${RESET}   pull the latest security news and enrich CVEs
    ${CYAN}${BINARY} tui${RESET}      browse the ranked dossier
    ${CYAN}${BINARY} ai${RESET}       optional: set up an AI provider for content ideation
    ${CYAN}${BINARY} watch${RESET}    optional: run as a daemon with webhook alerts

  ${DIM}docs: https://github.com/${REPO_OWNER}/${REPO_NAME}${RESET}
FOOTER
    return 0
}

main "$@" </dev/null
