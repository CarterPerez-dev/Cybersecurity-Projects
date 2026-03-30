#!/usr/bin/env bash
# ©AngelaMos | 2026
# test_runner.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

source "${PROJECT_DIR}/src/lib/constants.sh"
source "${PROJECT_DIR}/src/lib/utils.sh"
source "${PROJECT_DIR}/src/lib/registry.sh"
source "${PROJECT_DIR}/src/lib/engine.sh"
source "${PROJECT_DIR}/src/lib/report_json.sh"
source "${PROJECT_DIR}/src/lib/baseline.sh"
source "${PROJECT_DIR}/src/controls/registry_data.sh"
for f in "${PROJECT_DIR}/src/checks/"*.sh; do source "$f"; done

source "${SCRIPT_DIR}/test_helpers.sh"

QUIET="true"

run_test_file() {
    local test_file="$1"
    local file_name
    file_name=$(basename "$test_file")

    source "$test_file"

    local test_fns
    test_fns=$(declare -F | awk '{print $3}' | grep '^test_')

    local fn
    for fn in $test_fns; do
        echo "  Running: ${fn}"
        "$fn"
    done

    for fn in $test_fns; do
        unset -f "$fn"
    done
}

main() {
    local test_files=()

    if [[ $# -gt 0 ]]; then
        test_files=("$@")
    else
        for f in "${SCRIPT_DIR}"/test_*.sh; do
            [[ "$(basename "$f")" == "test_helpers.sh" ]] && continue
            [[ "$(basename "$f")" == "test_runner.sh" ]] && continue
            test_files+=("$f")
        done
    fi

    if [[ ${#test_files[@]} -eq 0 ]]; then
        echo "No test files found" >&2
        exit 1
    fi

    echo "Running ${#test_files[@]} test file(s)..."
    echo ""

    local file
    for file in "${test_files[@]}"; do
        echo "[$(basename "$file")]"
        run_test_file "$file"
        echo ""
    done

    print_results
}

main "$@"
