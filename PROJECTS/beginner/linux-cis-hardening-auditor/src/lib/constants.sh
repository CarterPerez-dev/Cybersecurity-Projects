#!/usr/bin/env bash
# ©AngelaMos | 2026
# constants.sh

declare -gr VERSION="1.0.0"
declare -gr CIS_BENCHMARK="CIS Debian Linux 12 Benchmark v1.1.0"
declare -gr MIN_BASH_VERSION=4

declare -gr EXIT_OK=0
declare -gr EXIT_FAIL=1
declare -gr EXIT_USAGE=2

declare -gr RED='\033[0;31m'
declare -gr GREEN='\033[0;32m'
declare -gr YELLOW='\033[1;33m'
declare -gr CYAN='\033[0;36m'
declare -gr BLUE='\033[0;34m'
declare -gr MAGENTA='\033[0;35m'
declare -gr BOLD='\033[1m'
declare -gr DIM='\033[2m'
declare -gr RESET='\033[0m'

declare -gr STATUS_PASS="PASS"
declare -gr STATUS_FAIL="FAIL"
declare -gr STATUS_WARN="WARN"
declare -gr STATUS_SKIP="SKIP"

declare -g SYSROOT="/"

declare -gr SECTION_INITIAL_SETUP="Initial Setup"
declare -gr SECTION_SERVICES="Services"
declare -gr SECTION_NETWORK="Network Configuration"
declare -gr SECTION_LOGGING="Logging and Auditing"
declare -gr SECTION_ACCESS="Access, Authentication and Authorization"
declare -gr SECTION_MAINTENANCE="System Maintenance"

declare -ga SECTION_ORDER=(
    "$SECTION_INITIAL_SETUP"
    "$SECTION_SERVICES"
    "$SECTION_NETWORK"
    "$SECTION_LOGGING"
    "$SECTION_ACCESS"
    "$SECTION_MAINTENANCE"
)
