#!/usr/bin/env bash
# ©AngelaMos | 2026
# install.sh

set -euo pipefail

# --- config ---------------------------------------------------------------
REPO_OWNER="CarterPerez-dev"
REPO_NAME="Cybersecurity-Projects"
PROJECT_SUBDIR="PROJECTS/advanced/zig-stateless-scanner"
BINARY="zingela"
TAGLINE="stateless mass TCP/UDP scanner - single static Zig binary"
REPO_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}.git"
INSTALL_DIR="${ZINGELA_INSTALL_DIR:-$HOME/.local/bin}"
DEFAULT_BRANCH="main"
ZIG_VER="0.16.0"
ZIG_MIN="0.16.0"
DO_SETCAP=1

# --- colors (gated so `| bash`, logs and CI stay clean) -------------------
if [ -t 2 ] && [ -z "${NO_COLOR:-}" ]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GREEN=$'\033[32m'
    YELLOW=$'\033[33m'; VIOLET=$'\033[38;2;139;92;246m'; RESET=$'\033[0m'
else
    BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; VIOLET=""; RESET=""
fi

info() { printf '%s\n' "  ${VIOLET}+${RESET} $*" >&2; }
ok()   { printf '%s\n' "  ${GREEN}+${RESET} $*" >&2; }
warn() { printf '%s\n' "  ${YELLOW}!${RESET} $*" >&2; }
die()  { printf '%s\n' "  ${RED}x $*${RESET}" >&2; exit 1; }
header(){ printf '\n%s\n\n' "${BOLD}${VIOLET}--- $* ---${RESET}" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

trap 'printf "%s\n" "${RED}x install failed${RESET}" >&2' ERR
TMP_DIR=""
cleanup() { [ -n "$TMP_DIR" ] && rm -rf "$TMP_DIR"; return 0; }
trap cleanup EXIT

banner() {
    printf '%s' "${VIOLET}${BOLD}" >&2
    cat >&2 <<'ART'
    ____  _                 _
   |_  /(_) _ _   __ _  ___| | __ _
    / / | || ' \ / _` |/ -_) |/ _` |
   /___||_||_||_|\__, |\___|_|\__,_|
                 |___/
ART
    printf '%s\n' "${RESET}" >&2
    printf '%s\n' "  ${DIM}${TAGLINE}${RESET}" >&2
}

# --- privilege + package manager fan --------------------------------------
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
    else die "no known package manager. Install manually: $*"; fi
}

download() {
    if   have curl; then curl -fsSL "$1" -o "$2" || return 1
    elif have wget; then wget -qO "$2" "$1" || return 1
    else die "need curl or wget"; fi
}

version_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

# --- args -----------------------------------------------------------------
usage() {
    cat >&2 <<USAGE
install.sh - install ${BINARY}

  ./install.sh [options]
  curl -fsSL https://angelamos.com/${BINARY}/install.sh | bash

options:
  --prefix DIR   install dir (default: ${INSTALL_DIR})
  --no-setcap    skip granting raw-socket capabilities (use sudo or --connect instead)
  -h, --help     this help
USAGE
}
while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) INSTALL_DIR="$2"; shift 2 ;;
        --prefix=*) INSTALL_DIR="${1#*=}"; shift ;;
        --no-setcap) DO_SETCAP=0; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
done

# --- OS / arch (Linux only: raw AF_PACKET + std.os.linux) -----------------
OS="$(uname -s)"; ARCH="$(uname -m)"
case "$OS" in
    Linux) ;;
    Darwin) die "${BINARY} is Linux-only (raw AF_PACKET / XDP). Run it in a Linux VM or WSL2." ;;
    MINGW*|MSYS*|CYGWIN*) die "${BINARY} is Linux-only. Use WSL2." ;;
    *) die "unsupported OS: $OS (${BINARY} is Linux-only)" ;;
esac
case "$ARCH" in
    x86_64|amd64) MUSL_ARCH="x86_64" ;;
    aarch64|arm64) MUSL_ARCH="aarch64" ;;
    *) die "unsupported arch: $ARCH (${BINARY} builds for x86_64 and aarch64)" ;;
esac

# --- bootstrap: works in-clone OR piped from a domain ---------------------
clone_repo() {
    local cache="$1"
    if git clone --depth 1 --filter=blob:none --sparse --branch "$DEFAULT_BRANCH" --quiet "$REPO_URL" "$cache" 2>/dev/null \
       && git -C "$cache" sparse-checkout set "$PROJECT_SUBDIR" 2>/dev/null; then
        return 0
    fi
    rm -rf "$cache"
    git clone --depth 1 --branch "$DEFAULT_BRANCH" --quiet "$REPO_URL" "$cache"
}

resolve_project_dir() {
    if [ -f "./build.zig" ] && [ -d "./src" ]; then pwd; return; fi
    if [ -f "./${PROJECT_SUBDIR}/build.zig" ]; then printf '%s\n' "$(pwd)/${PROJECT_SUBDIR}"; return; fi
    local self="${BASH_SOURCE[0]:-}"
    if [ -n "$self" ] && [ -f "$(dirname "$self")/build.zig" ]; then (cd "$(dirname "$self")" && pwd); return; fi
    if ! have git; then warn "git missing - installing it"; pkg_install git; fi
    have git || die "could not install git; install it then re-run"
    local cache="${XDG_CACHE_HOME:-$HOME/.cache}/${BINARY}-src"
    if [ -d "$cache/.git" ]; then
        info "updating cached clone at $cache"
        git -C "$cache" pull --ff-only --quiet 2>/dev/null || warn "pull failed; using existing clone"
    else
        info "cloning ${REPO_URL} (sparse: ${PROJECT_SUBDIR})"
        clone_repo "$cache"
    fi
    printf '%s\n' "$cache/${PROJECT_SUBDIR}"
}

# --- toolchain: Zig 0.16, auto-fetched if missing/too old -----------------
need_toolchain() {
    if have zig; then
        local v; v="$(zig version 2>/dev/null | head -1)"
        if version_ge "$v" "$ZIG_MIN"; then ok "zig $v"; return; fi
        warn "zig $v is older than ${ZIG_MIN}; fetching a private ${ZIG_VER}"
    else
        info "zig not found; fetching ${ZIG_VER}"
    fi
    local zroot="zig-${MUSL_ARCH}-linux-${ZIG_VER}"
    local zdir="${XDG_CACHE_HOME:-$HOME/.cache}/${BINARY}-zig"
    if [ ! -x "$zdir/$zroot/zig" ]; then
        mkdir -p "$zdir"
        TMP_DIR="${TMP_DIR:-$(mktemp -d)}"
        info "downloading https://ziglang.org/download/${ZIG_VER}/${zroot}.tar.xz"
        download "https://ziglang.org/download/${ZIG_VER}/${zroot}.tar.xz" "$TMP_DIR/zig.tar.xz" \
            || die "could not download Zig ${ZIG_VER}"
        if ! tar -xf "$TMP_DIR/zig.tar.xz" -C "$zdir" 2>/dev/null; then
            pkg_install xz-utils 2>/dev/null || pkg_install xz 2>/dev/null || true
            tar -xf "$TMP_DIR/zig.tar.xz" -C "$zdir" || die "could not extract Zig (need tar + xz)"
        fi
    fi
    export PATH="$zdir/$zroot:$PATH"
    have zig || die "zig still not on PATH after fetch"
    ok "zig $(zig version)"
}

build_from_source() {
    info "zig build --release=safe (compiling ${BINARY}; this can take a minute)"
    zig build --release=safe
    [ -x "zig-out/bin/${BINARY}" ] || die "build did not produce zig-out/bin/${BINARY}"
    mkdir -p "$INSTALL_DIR"
    install -m 0755 "zig-out/bin/${BINARY}" "$INSTALL_DIR/$BINARY"
    ok "built + installed ${INSTALL_DIR}/${BINARY}"
}

try_prebuilt() {
    local tag asset url
    tag="$(download "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases" /dev/stdout 2>/dev/null \
          | grep '"tag_name":' | grep -o '"zingela-[^"]*"' | head -1 | tr -d '"')" || true
    [ -n "$tag" ] || { info "no published ${BINARY} release yet - building from source"; return 1; }
    asset="zingela-${MUSL_ARCH}-linux-musl"
    url="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${tag}/${asset}"
    TMP_DIR="${TMP_DIR:-$(mktemp -d)}"
    info "downloading prebuilt ${tag} (${asset})"
    download "$url" "$TMP_DIR/$BINARY" || { warn "no prebuilt ${asset} in ${tag}; building from source"; return 1; }
    mkdir -p "$INSTALL_DIR"
    install -m 0755 "$TMP_DIR/$BINARY" "$INSTALL_DIR/$BINARY"
    ok "installed prebuilt ${tag} -> ${INSTALL_DIR}/${BINARY}"
    return 0
}

# --- PATH wiring ----------------------------------------------------------
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

# --- raw-socket capabilities (so `zingela scan` needs no sudo) ------------
grant_caps() {
    local dest="$INSTALL_DIR/$BINARY"
    if [ "$DO_SETCAP" -ne 1 ]; then
        warn "skipping setcap (--no-setcap). Raw scans need: ${SUDO:+sudo }setcap cap_net_raw,cap_net_admin=eip \"$dest\""
        return 0
    fi
    if ! have setcap; then
        warn "setcap not found. For raw scans, install libcap then grant caps:"
        warn "    ${SUDO:+sudo }apt-get install -y libcap2-bin   (or dnf/pacman equivalent)"
        warn "    ${SUDO:+sudo }setcap cap_net_raw,cap_net_admin=eip \"$dest\""
        warn "or scan unprivileged right now:  ${BINARY} scan --connect --target <cidr> --ports <list>"
        return 0
    fi
    if $SUDO setcap cap_net_raw,cap_net_admin=eip "$dest"; then
        ok "granted CAP_NET_RAW + CAP_NET_ADMIN - raw scans run WITHOUT sudo"
    else
        warn "could not setcap (needs root). Enable raw scans without sudo via:"
        warn "    ${SUDO:+sudo }setcap cap_net_raw,cap_net_admin=eip \"$dest\""
        warn "until then: run under sudo, or use  ${BINARY} scan --connect  (no caps needed)"
    fi
    return 0
}

# --- main -----------------------------------------------------------------
# main() runs only after bash has read the whole file, and `</dev/null`
# denies children the pipe, so `curl ... | bash` never stops early.
main() {
    banner
    if have "$BINARY"; then info "existing install at $(command -v "$BINARY") - updating"; fi

    if ! try_prebuilt; then
        header "Build from source"
        PROJECT_DIR="$(resolve_project_dir)"
        cd "$PROJECT_DIR"
        need_toolchain
        build_from_source
    fi

    wire_path
    grant_caps

    header "Verify"
    if have "$BINARY"; then
        ok "$BINARY -> $(command -v "$BINARY")"
        "$BINARY" --version 2>/dev/null || true
    else
        warn "installed to $INSTALL_DIR but not on PATH yet - open a new shell"
    fi

    printf '\n%s\n\n' "  ${GREEN}${BOLD}${BINARY} is ready.${RESET}" >&2
    cat >&2 <<FOOTER
  ${DIM}quick start:${RESET}
    ${VIOLET}${BINARY} --help${RESET}
    ${VIOLET}${BINARY} scan --target 192.0.2.0/24 --ports 80,443 --rate 20000${RESET}
    ${VIOLET}${BINARY} scan --connect --target 192.0.2.0/24 --ports 22${RESET}   ${DIM}(no caps needed)${RESET}

  ${DIM}the example target 192.0.2.0/24 is a reserved documentation range that ${BINARY}
        skips by design; replace it with a range you are authorized to scan.${RESET}
  ${DIM}note: capabilities are cleared whenever the binary is replaced, so re-run this
        installer (or the setcap line) after every upgrade.${RESET}
  ${DIM}docs: https://github.com/${REPO_OWNER}/${REPO_NAME}/tree/main/${PROJECT_SUBDIR}${RESET}
FOOTER
    return 0
}

main "$@" </dev/null
