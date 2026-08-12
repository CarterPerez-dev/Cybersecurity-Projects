#!/usr/bin/env bash
# ©AngelaMos | 2026
# uninstall.sh

set -euo pipefail

BINARY="lisdex"
INSTALL_DIR="${LISDEX_INSTALL_DIR:-$HOME/.local/bin}"
KEEP_AFL=1

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

usage() {
    cat >&2 <<USAGE
uninstall.sh — remove ${BINARY}

  ./uninstall.sh [options]

options:
  --prefix DIR   install dir to clean (default: ${INSTALL_DIR})
  -h, --help     this help

AFL++ and libclang are left installed: other tools use them, and this script
will not remove a system package it did not certainly put there.
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

remove_binary() {
    if [ -f "${INSTALL_DIR}/${BINARY}" ]; then
        rm -f "${INSTALL_DIR}/${BINARY}"
        ok "removed ${INSTALL_DIR}/${BINARY}"
    else
        info "no binary at ${INSTALL_DIR}/${BINARY}"
    fi
    if have cargo && cargo install --list 2>/dev/null | grep -q "^${BINARY} "; then
        cargo uninstall "$BINARY" >/dev/null 2>&1 || true
        ok "removed the cargo-installed ${BINARY}"
    fi
}

remove_path_line() {
    local rc
    for rc in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile"; do
        [ -f "$rc" ] || continue
        if grep -q "$INSTALL_DIR" "$rc" 2>/dev/null; then
            local tmp
            tmp="$(mktemp)"
            grep -v "^export PATH=\"${INSTALL_DIR}:\$PATH\"$" "$rc" > "$tmp" || true
            if cmp -s "$rc" "$tmp"; then
                warn "$rc mentions $INSTALL_DIR but not as a line this installer wrote; left alone"
            else
                cat "$tmp" > "$rc"
                ok "removed the PATH line from $rc"
            fi
            rm -f "$tmp"
        fi
    done
    local fish="$HOME/.config/fish/conf.d/${BINARY}.fish"
    if [ -f "$fish" ]; then
        rm -f "$fish"
        ok "removed $fish"
    fi
}

remove_cache() {
    local cache="${XDG_CACHE_HOME:-$HOME/.cache}/${BINARY}"
    if [ -d "$cache" ]; then
        rm -rf "$cache"
        ok "removed the cached clone at $cache"
    fi
}

main() {
    header "Removing ${BINARY}"
    remove_binary
    remove_path_line
    remove_cache

    if [ "$KEEP_AFL" = "1" ] && have afl-fuzz; then
        info "AFL++ left installed at $(command -v afl-fuzz)"
    fi

    printf '\n%s\n' "  ${GREEN}${BOLD}${BINARY} removed.${RESET}" >&2
    printf '%s\n\n' "  ${DIM}campaign databases and findings directories were not touched${RESET}" >&2
    return 0
}

main "$@" </dev/null
