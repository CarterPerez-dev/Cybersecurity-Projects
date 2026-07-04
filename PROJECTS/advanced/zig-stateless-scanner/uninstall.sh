#!/usr/bin/env bash
# ©AngelaMos | 2026
# uninstall.sh

set -euo pipefail

BINARY="zingela"
INSTALL_DIR="${ZINGELA_INSTALL_DIR:-$HOME/.local/bin}"
CACHE_SRC="${XDG_CACHE_HOME:-$HOME/.cache}/${BINARY}-src"
CACHE_ZIG="${XDG_CACHE_HOME:-$HOME/.cache}/${BINARY}-zig"

if [ -t 2 ] && [ -z "${NO_COLOR:-}" ]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; GREEN=$'\033[32m'
    YELLOW=$'\033[33m'; VIOLET=$'\033[38;2;139;92;246m'; RESET=$'\033[0m'
else
    BOLD=""; DIM=""; GREEN=""; YELLOW=""; VIOLET=""; RESET=""
fi
info() { printf '%s\n' "  ${VIOLET}+${RESET} $*" >&2; }
ok()   { printf '%s\n' "  ${GREEN}+${RESET} $*" >&2; }
warn() { printf '%s\n' "  ${YELLOW}!${RESET} $*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
    cat >&2 <<USAGE
uninstall.sh - remove ${BINARY}

  ./uninstall.sh [--prefix DIR]
USAGE
}
while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) INSTALL_DIR="$2"; shift 2 ;;
        --prefix=*) INSTALL_DIR="${1#*=}"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) warn "unknown option: $1"; shift ;;
    esac
done

main() {
    printf '\n%s\n\n' "${BOLD}${VIOLET}--- removing ${BINARY} ---${RESET}" >&2

    local dest="$INSTALL_DIR/$BINARY"
    if [ -e "$dest" ]; then rm -f "$dest"; ok "removed $dest"; else info "no binary at $dest"; fi

    for c in "$CACHE_SRC" "$CACHE_ZIG"; do
        if [ -d "$c" ]; then rm -rf "$c"; ok "removed cache $c"; fi
    done

    warn "if you want to drop it from PATH, delete this line from your shell rc:"
    printf '%s\n' "      ${DIM}export PATH=\"${INSTALL_DIR}:\$PATH\"${RESET}" >&2

    printf '\n%s\n\n' "  ${GREEN}${BOLD}${BINARY} removed.${RESET}" >&2
    return 0
}

main "$@" </dev/null
