#!/usr/bin/env bash
# ©AngelaMos | 2026
# install.sh

set -euo pipefail

BINARY=khaos
REPO_URL="${KHAOS_REPO_URL:-https://github.com/CarterPerez-dev/khaos.git}"
RELEASE_URL="${KHAOS_RELEASE_URL:-https://github.com/CarterPerez-dev/khaos/releases}"
INSTALL_DIR="${KHAOS_INSTALL_DIR:-${HOME:?HOME must be set}/.local/bin}"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/khaos/install"
VERSION="${KHAOS_VERSION:-latest}"
SOURCE_REF="${KHAOS_REF:-main}"
SOURCE_DIR="${KHAOS_SOURCE_DIR:-}"
GO_VERSION="${KHAOS_GO_VERSION:-}"
ORIGINAL_PATH="$PATH"
BUILD_SOURCE=0
SETUP_DOCKER=1
TMP_DIR=""
LINK_DIR=""
OS=""
ARCH=""
GO_BIN=""
ROOT=()

if [ -t 2 ] && [ -z "${NO_COLOR:-}" ]; then
    BOLD=$'\033[1m'
    CYAN=$'\033[36m'
    GREEN=$'\033[32m'
    YELLOW=$'\033[33m'
    RED=$'\033[31m'
    RESET=$'\033[0m'
else
    BOLD="" CYAN="" GREEN="" YELLOW="" RED="" RESET=""
fi

info() { printf '%s\n' "  ${CYAN}+${RESET} $*" >&2; }
ok() { printf '%s\n' "  ${GREEN}+${RESET} $*" >&2; }
warn() { printf '%s\n' "  ${YELLOW}!${RESET} $*" >&2; }
die() { printf '%s\n' "  ${RED}x${RESET} $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
        rm -rf -- "$TMP_DIR"
    fi
    return 0
}

trap 'printf "%s\n" "${RED}Installation failed at line ${LINENO}.${RESET}" >&2' ERR
trap cleanup EXIT

usage() {
    cat >&2 <<USAGE
khaos installer

  curl -fsSL https://angelamos.com/khaos/install.sh | bash
  bash install.sh [options]

Options:
  --prefix DIR     Binary directory (default: ~/.local/bin)
  --version TAG    Install a particular release, such as v0.1.0
  --source         Build from source instead of downloading a binary
  --no-docker      Install only Khaos; leave Docker setup to the operator
  -h, --help       Show this help

Supports Linux AMD64 and ARM64 with native Docker Engine networking.
Installs Docker and Compose when absent. Administrative setup may use sudo.
Existing Docker endpoints and running services are preserved.

Environment: KHAOS_INSTALL_DIR, KHAOS_VERSION, KHAOS_SOURCE_DIR,
KHAOS_REF, KHAOS_REPO_URL, KHAOS_RELEASE_URL, KHAOS_GO_VERSION,
XDG_CACHE_HOME, NO_COLOR.
USAGE
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --prefix|--version)
                if [ "$#" -lt 2 ] || [ -z "$2" ]; then die "$1 needs a value"; fi
                case "$2" in --*) die "$1 needs a value" ;; esac
                if [ "$1" = --prefix ]; then INSTALL_DIR="$2"; else VERSION="$2"; fi
                shift 2
                ;;
            --prefix=*) INSTALL_DIR="${1#*=}"; shift ;;
            --version=*) VERSION="${1#*=}"; shift ;;
            --source) BUILD_SOURCE=1; shift ;;
            --no-docker) SETUP_DOCKER=0; shift ;;
            -h|--help) usage; exit 0 ;;
            *) die "Unknown option: $1 (try --help)" ;;
        esac
    done
    case "$INSTALL_DIR" in
        /*) ;;
        *) die "--prefix must be an absolute directory" ;;
    esac
    case "$INSTALL_DIR" in
        *:*|*$'\n'*|*$'\r'*) die "The install directory cannot contain colons or newlines" ;;
    esac
    [[ "$VERSION" == latest || "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.-]+)?$ ]] ||
        die "--version must be latest or a release tag such as v0.1.0"
}

banner() {
    printf '\n%s%s' "$BOLD" "$CYAN" >&2
    cat >&2 <<'ART'
  _  ___   _    _    ___  ___
 | |/ / | | |  /_\  / _ \/ __|
 | ' <| |_| | / _ \| (_) \__ \
 |_|\_\\___/ /_/ \_\\___/|___/
ART
    printf '%s\n  Security chaos engineering\n\n' "$RESET" >&2
}

platform() {
    case "$(uname -s)" in
        Linux) OS=linux ;;
        Darwin) die "Khaos requires Linux Docker networking. Run this installer inside a Linux VM." ;;
        MINGW*|MSYS*|CYGWIN*) die "Run this installer inside a Linux VM or WSL2 with a native Docker Engine." ;;
        *) die "Unsupported operating system: $(uname -s)" ;;
    esac
    case "$(uname -m)" in
        x86_64|amd64) ARCH=amd64 ;;
        aarch64|arm64) ARCH=arm64 ;;
        *) die "Unsupported architecture: $(uname -m). Supported: AMD64, ARM64." ;;
    esac
}

root_access() {
    if [ "$(id -u)" -eq 0 ]; then
        ROOT=()
    elif have sudo; then
        ROOT=(sudo)
        sudo -v || die "Administrative access is required for this installation step"
    else
        die "This step needs root or sudo. A writable PATH directory and --no-docker avoid system setup."
    fi
}

pkg_install() {
    root_access
    if have apt-get; then
        "${ROOT[@]}" apt-get update -q
        "${ROOT[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"
    elif have dnf; then
        "${ROOT[@]}" dnf install -y "$@"
    elif have pacman; then
        "${ROOT[@]}" pacman -S --needed --noconfirm "$@"
    elif have zypper; then
        "${ROOT[@]}" zypper --non-interactive install "$@"
    elif have apk; then
        "${ROOT[@]}" apk add --no-cache "$@"
    elif have brew; then
        brew install "$@"
    else
        die "No supported package manager found; required packages: $*"
    fi
}

download() {
    if have curl; then
        curl --fail --silent --show-error --location --retry 3 \
            --connect-timeout 15 --max-time 300 "$1" --output "$2"
    elif have wget; then
        wget --quiet --timeout=30 --tries=3 --output-document="$2" "$1"
    else
        die "curl or wget is required to download installation files"
    fi
}

digest() {
    if have sha256sum; then
        sha256sum "$1" | awk '{print $1}'
    elif have shasum; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        die "No SHA-256 verifier found; install coreutils or perl-Digest-SHA"
    fi
}

verify_checksum() {
    local expected="$1" actual
    [[ "$expected" =~ ^[a-fA-F0-9]{64}$ ]] || die "Missing or invalid SHA-256 checksum for $2"
    actual="$(digest "$2")"
    [ "${actual,,}" = "${expected,,}" ] || die "Checksum mismatch for $2; refusing this download"
}

prebuilt() {
    local base asset expected
    asset="${BINARY}_${OS}_${ARCH}.tar.gz"
    if [ "$VERSION" = latest ]; then
        base="$RELEASE_URL/latest/download"
    else
        base="$RELEASE_URL/download/$VERSION"
    fi
    info "Looking for a verified $OS/$ARCH release"
    if ! download "$base/$asset" "$TMP_DIR/$asset"; then
        warn "Release download unavailable; building from source"
        return 1
    fi
    download "$base/checksums.txt" "$TMP_DIR/checksums.txt" ||
        die "The release is missing checksums.txt; refusing an unchecked binary"
    expected="$(awk -v file="$asset" '$2 == file || $2 == "*" file {print $1}' "$TMP_DIR/checksums.txt")"
    verify_checksum "$expected" "$TMP_DIR/$asset"
    tar -xzf "$TMP_DIR/$asset" -C "$TMP_DIR" --no-same-owner "$BINARY" ||
        die "Could not extract the release executable"
    if [ ! -f "$TMP_DIR/$BINARY" ] || [ -L "$TMP_DIR/$BINARY" ]; then
        die "The release does not contain a regular $BINARY executable"
    fi
    chmod 0755 "$TMP_DIR/$BINARY"
    "$TMP_DIR/$BINARY" version >&2 || die "The release executable failed its version check"
    return 0
}

is_checkout() {
    [ -f "$1/go.mod" ] && [ -f "$1/cmd/khaos/main.go" ] &&
        grep -qx 'module github.com/CarterPerez-dev/khaos' "$1/go.mod"
}

resolve_source() {
    local self cache origin
    if [ -n "$SOURCE_DIR" ]; then
        is_checkout "$SOURCE_DIR" || die "KHAOS_SOURCE_DIR is not a Khaos checkout: $SOURCE_DIR"
        SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd -P)"
        return
    fi
    if [ "$VERSION" = latest ] && is_checkout "$PWD"; then
        SOURCE_DIR="$PWD"
        return
    fi
    self="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
    if [ "$VERSION" = latest ] && is_checkout "$self"; then
        SOURCE_DIR="$self"
        return
    fi
    if ! have git; then pkg_install git ca-certificates; fi
    have git || die "Git installation did not provide git"
    if [ "$VERSION" != latest ]; then SOURCE_REF="$VERSION"; fi
    [[ "$SOURCE_REF" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "Invalid KHAOS_REF: $SOURCE_REF"
    cache="$CACHE_DIR/source/$SOURCE_REF"
    if [ -e "$cache" ]; then
        is_checkout "$cache" || die "The source cache is not a Khaos checkout: $cache"
        origin="$(git -C "$cache" remote get-url origin)"
        [ "$origin" = "$REPO_URL" ] || die "The source cache has a different origin: $cache"
        [ -z "$(git -C "$cache" status --porcelain)" ] || die "The source cache contains edits: $cache"
        if [ "$VERSION" = latest ]; then
            [ "$(git -C "$cache" branch --show-current)" = "$SOURCE_REF" ] ||
                die "The source cache is on an unexpected branch: $cache"
            git -C "$cache" pull --ff-only >&2
        fi
    else
        mkdir -p "$(dirname "$cache")"
        git clone --depth 1 --branch "$SOURCE_REF" "$REPO_URL" "$cache" >&2
    fi
    SOURCE_DIR="$cache"
}

version_at_least() {
    [ "$(printf '%s\n' "$1" "$2" | sort -V | head -n 1)" = "$2" ]
}

toolchain() {
    local current archive expected destination
    if have go; then
        current="$(GOTOOLCHAIN=local go env GOVERSION)"
        if version_at_least "${current#go}" 1.26.0; then
            GO_BIN="$(command -v go)"
            return
        fi
    fi
    if [ -z "$GO_VERSION" ]; then
        download 'https://go.dev/VERSION?m=text' "$TMP_DIR/go-version"
        IFS= read -r GO_VERSION < "$TMP_DIR/go-version"
    fi
    GO_VERSION="${GO_VERSION#go}"
    [[ "$GO_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Invalid Go version: $GO_VERSION"
    version_at_least "$GO_VERSION" 1.26.0 || die "Khaos requires Go 1.26 or newer"
    destination="$CACHE_DIR/toolchains/go$GO_VERSION-$OS-$ARCH"
    GO_BIN="$destination/go/bin/go"
    if [ -x "$GO_BIN" ]; then return; fi
    archive="go${GO_VERSION}.${OS}-${ARCH}.tar.gz"
    info "Installing Go $GO_VERSION into the private build cache"
    download 'https://go.dev/dl/?mode=json&include=all' "$TMP_DIR/go-releases.json"
    expected="$(awk -v archive="$archive" '
        /"filename":/ { wanted = index($0, "\"" archive "\"") > 0 }
        wanted && /"sha256":/ {gsub(/[",[:space:]]/, ""); sub(/^sha256:/, ""); print; exit}
    ' "$TMP_DIR/go-releases.json")"
    download "https://go.dev/dl/$archive" "$TMP_DIR/$archive"
    verify_checksum "$expected" "$TMP_DIR/$archive"
    mkdir -p "$TMP_DIR/toolchain" "$(dirname "$destination")"
    tar -xzf "$TMP_DIR/$archive" -C "$TMP_DIR/toolchain" --no-same-owner
    [ -x "$TMP_DIR/toolchain/go/bin/go" ] || die "Go download did not contain a working toolchain"
    [ ! -e "$destination" ] || die "Incomplete Go cache already exists: $destination"
    mv "$TMP_DIR/toolchain" "$destination"
    "$GO_BIN" version >&2
}

build_source() {
    resolve_source
    toolchain
    info "Building a static Khaos binary"
    (
        cd "$SOURCE_DIR"
        unset GOROOT
        CGO_ENABLED=0 GOTOOLCHAIN=auto "$GO_BIN" build -trimpath \
            -ldflags='-s -w' -o "$TMP_DIR/$BINARY" ./cmd/khaos
    )
    if have strip; then strip "$TMP_DIR/$BINARY"; fi
    "$TMP_DIR/$BINARY" version >&2
}

install_compose() {
    if docker compose version >/dev/null 2>&1; then return; fi
    local machine base name expected directory
    info "Installing Docker Compose"
    machine=x86_64
    if [ "$ARCH" = arm64 ]; then machine=aarch64; fi
    name="docker-compose-linux-$machine"
    base=https://github.com/docker/compose/releases/download/v2.40.0
    download "$base/$name" "$TMP_DIR/docker-compose"
    download "$base/$name.sha256" "$TMP_DIR/compose.sha256"
    expected="$(awk 'NR == 1 {print $1}' "$TMP_DIR/compose.sha256")"
    verify_checksum "$expected" "$TMP_DIR/docker-compose"
    directory="${DOCKER_CONFIG:-$HOME/.docker}/cli-plugins"
    mkdir -p "$directory"
    install -m 0755 "$TMP_DIR/docker-compose" "$directory/docker-compose"
    docker compose version >/dev/null 2>&1 || die "Docker Compose installation failed"
}

install_docker() {
    if have docker; then return; fi
    info "Installing Docker Engine"
    if have apt-get || have dnf; then
        download https://get.docker.com "$TMP_DIR/docker-install.sh"
        root_access
        "${ROOT[@]}" sh "$TMP_DIR/docker-install.sh" >&2
    elif have pacman; then
        pkg_install docker docker-compose
    elif have zypper; then
        pkg_install docker docker-compose
    elif have apk; then
        pkg_install docker docker-cli-compose
    else
        die "Docker Engine needs apt, dnf, pacman, zypper, or apk on this Linux host"
    fi
    have docker || die "Docker installation did not provide the docker command"
}

start_docker() {
    if "${ROOT[@]}" docker info >/dev/null 2>&1; then return; fi
    info "Starting the local Docker daemon"
    if have systemctl; then
        "${ROOT[@]}" systemctl enable --now docker
    elif have rc-service; then
        "${ROOT[@]}" rc-update add docker default
        "${ROOT[@]}" rc-service docker start
    else
        die "No supported service manager found for Docker; use a running Linux Docker Engine"
    fi
    local attempt
    for attempt in {1..30}; do
        if "${ROOT[@]}" docker info >/dev/null 2>&1; then return; fi
        if [ "$attempt" -eq 30 ]; then break; fi
        sleep 1
    done
    die "Docker did not become ready within 30 seconds"
}

docker_access() {
    local endpoint user
    if docker info >/dev/null 2>&1; then return; fi
    endpoint="$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null || true)"
    if [ -n "${DOCKER_HOST:-}${DOCKER_CONTEXT:-}" ] ||
        { [ -n "$endpoint" ] && [ "$endpoint" != unix:///var/run/docker.sock ]; }; then
        die "The selected Docker endpoint is unavailable. Its configuration was preserved: ${DOCKER_HOST:-$endpoint}"
    fi
    root_access
    start_docker
    if [ "$(id -u)" -ne 0 ]; then
        user="$(id -un)"
        warn "Granting $user access to the local Docker socket, which permits administrative container operations"
        if ! have setfacl; then pkg_install acl; fi
        "${ROOT[@]}" usermod -aG docker "$user"
        "${ROOT[@]}" setfacl -m "u:$user:rw" /var/run/docker.sock
    fi
    docker info >/dev/null 2>&1 || die "The current user still cannot reach Docker"
}

path_contains() {
    case ":$ORIGINAL_PATH:" in *":$1:"*) return 0 ;; *) return 1 ;; esac
}

choose_link_dir() {
    local directory
    if path_contains "$INSTALL_DIR"; then LINK_DIR="$INSTALL_DIR"; return; fi
    local -a candidates
    IFS=: read -r -a candidates <<< "$ORIGINAL_PATH"
    for directory in "${candidates[@]}"; do
        case "$directory" in
            /*)
                if [ -d "$directory" ] && [ -w "$directory" ]; then
                    LINK_DIR="$directory"
                    return
                fi
                ;;
        esac
    done
    for directory in /usr/local/bin /usr/bin; do
        if path_contains "$directory"; then
            root_access
            LINK_DIR="$directory"
            return
        fi
    done
    die "No usable directory exists on PATH; choose --prefix pointing to a directory already on PATH"
}

write_path_config() {
    if path_contains "$INSTALL_DIR"; then return; fi
    local rc line shell_name quoted
    shell_name="${SHELL:-/bin/sh}"
    shell_name="${shell_name##*/}"
    printf -v quoted '%q' "$INSTALL_DIR"
    case "$shell_name" in
        zsh) rc="${ZDOTDIR:-$HOME}/.zshrc"; line="export PATH=$quoted:\$PATH" ;;
        bash) rc="$HOME/.bashrc"; line="export PATH=$quoted:\$PATH" ;;
        fish)
            rc="${XDG_CONFIG_HOME:-$HOME/.config}/fish/conf.d/khaos-path.fish"
            line="fish_add_path -- $quoted"
            ;;
        *) rc="$HOME/.profile"; line="export PATH=$quoted:\$PATH" ;;
    esac
    mkdir -p "$(dirname "$rc")"
    if ! grep -Fqx -- "$line" "$rc" 2>/dev/null; then
        printf '\n%s\n' "$line" >> "$rc"
    fi
}

install_binary() {
    local staging
    choose_link_dir
    if [ ! -d "$INSTALL_DIR" ]; then
        if ! mkdir -p "$INSTALL_DIR" 2>/dev/null; then
            root_access
            "${ROOT[@]}" mkdir -p "$INSTALL_DIR"
        fi
    fi
    if [ -w "$INSTALL_DIR" ]; then
        staging="$(mktemp "$INSTALL_DIR/.khaos-install.XXXXXX")"
        install -m 0755 "$TMP_DIR/$BINARY" "$staging"
        mv -f "$staging" "$INSTALL_DIR/$BINARY"
    else
        root_access
        staging="$("${ROOT[@]}" mktemp "$INSTALL_DIR/.khaos-install.XXXXXX")"
        "${ROOT[@]}" install -m 0755 "$TMP_DIR/$BINARY" "$staging"
        "${ROOT[@]}" mv -f "$staging" "$INSTALL_DIR/$BINARY"
    fi
    if [ "$LINK_DIR" != "$INSTALL_DIR" ]; then
        if [ -e "$LINK_DIR/$BINARY" ] && [ ! -L "$LINK_DIR/$BINARY" ]; then
            die "A different executable already occupies $LINK_DIR/$BINARY; choose that directory with --prefix to update it"
        fi
        if [ -w "$LINK_DIR" ]; then
            ln -sfn "$INSTALL_DIR/$BINARY" "$LINK_DIR/$BINARY"
        else
            root_access
            "${ROOT[@]}" ln -sfn "$INSTALL_DIR/$BINARY" "$LINK_DIR/$BINARY"
        fi
        write_path_config
    fi
    hash -r
    have "$BINARY" || die "The installed command is not discoverable on the original PATH"
    [ "$(readlink -f "$(command -v "$BINARY")")" = "$(readlink -f "$INSTALL_DIR/$BINARY")" ] ||
        die "Another khaos executable shadows the installation on PATH"
    "$BINARY" version >&2
    ok "Installed $BINARY in $INSTALL_DIR"
}

footer() {
    printf '\n%s\n' '  Ready:' '    khaos range up' '    khaos catalog' '    khaos' >&2
    printf '\n%s\n' '  Docs: https://github.com/CarterPerez-dev/khaos#readme' >&2
    if have just && [ -n "$SOURCE_DIR" ]; then
        printf '%s\n' "  Checkout: $SOURCE_DIR" '  Recipes: just build, just check, just gate' >&2
    fi
    if [ "$SETUP_DOCKER" -eq 0 ]; then
        warn "Docker setup was skipped by request; experiments need a reachable Linux Docker Engine"
    fi
}

main() {
    parse_args "$@"
    platform
    banner
    TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/khaos-install.XXXXXX")"
    have tar || pkg_install tar
    if ! have sha256sum && ! have shasum; then pkg_install coreutils; fi
    if [ "$BUILD_SOURCE" -eq 1 ] || ! prebuilt; then build_source; fi
    if [ "$SETUP_DOCKER" -eq 1 ]; then
        install_docker
        install_compose
        docker_access
        ok "Docker Engine and Compose are ready"
    fi
    install_binary
    footer
}

main "$@" </dev/null
