#!/usr/bin/env bash
# ©AngelaMos | 2026
# utils.sh

info()    { [[ "$QUIET" == "true" ]] || echo -e "${CYAN}[*]${RESET} $1" >&2; }
success() { [[ "$QUIET" == "true" ]] || echo -e "${GREEN}[✔]${RESET} $1" >&2; }
warn()    { [[ "$QUIET" == "true" ]] || echo -e "${YELLOW}[!]${RESET} $1" >&2; }
fail()    { echo -e "${RED}[✖]${RESET} $1" >&2; exit "$EXIT_FAIL"; }

progress() {
    [[ "$QUIET" == "true" ]] && return
    printf "\r${DIM}[%s] Checking: %s${RESET}%s" "$1" "$2" "$(printf '%40s')" >&2
}

clear_progress() {
    [[ "$QUIET" == "true" ]] && return
    printf "\r%80s\r" "" >&2
}

check_bash_version() {
    if (( BASH_VERSINFO[0] < MIN_BASH_VERSION )); then
        fail "Bash ${MIN_BASH_VERSION}+ required (found ${BASH_VERSION})"
    fi
}

check_root() {
    if [[ $EUID -ne 0 && "$SYSROOT" == "/" ]]; then
        warn "Running without root privileges — some checks will be skipped"
        return 1
    fi
    return 0
}

detect_os() {
    local os_release="${SYSROOT}/etc/os-release"
    if [[ -f "$os_release" ]]; then
        DETECTED_ID=$(grep -oP '^ID=\K.*' "$os_release" | tr -d '"')
        DETECTED_VERSION=$(grep -oP '^VERSION_ID=\K.*' "$os_release" | tr -d '"')
    else
        DETECTED_ID="unknown"
        DETECTED_VERSION="unknown"
    fi
}

run_cmd() {
    if [[ "$SYSROOT" != "/" ]]; then
        return 1
    fi
    "$@" 2>/dev/null
}

file_exists() {
    [[ -f "${SYSROOT}${1}" ]]
}

read_file() {
    local path="${SYSROOT}${1}"
    if [[ -f "$path" ]]; then
        cat "$path"
    else
        return 1
    fi
}

get_sysctl() {
    local param="$1"
    local proc_path="${SYSROOT}/proc/sys/${param//\.//}"
    if [[ -f "$proc_path" ]]; then
        cat "$proc_path"
        return 0
    fi

    if run_cmd sysctl -n "$param"; then
        return 0
    fi

    return 1
}

get_config_value() {
    local file="$1"
    local key="$2"
    local path="${SYSROOT}${file}"

    if [[ ! -f "$path" ]]; then
        return 1
    fi

    grep -Ei "^\s*${key}\s" "$path" | tail -1 | awk '{print $2}'
}

service_is_enabled() {
    if run_cmd systemctl is-enabled "$1"; then
        return 0
    fi
    return 1
}

service_is_active() {
    if run_cmd systemctl is-active "$1"; then
        return 0
    fi
    return 1
}

package_is_installed() {
    if run_cmd dpkg-query -W -f='${Status}' "$1" | grep -q "install ok installed"; then
        return 0
    fi
    return 1
}
