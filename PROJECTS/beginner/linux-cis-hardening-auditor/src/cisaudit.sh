#!/usr/bin/env bash
# ©AngelaMos | 2026
# cisaudit.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

declare -g QUIET="false"
declare -g OPT_LEVEL="all"
declare -g OPT_FORMAT="terminal"
declare -g OPT_OUTPUT=""
declare -g OPT_CATEGORIES="all"
declare -g OPT_BASELINE=""
declare -g OPT_SAVE_BASELINE=""
declare -g OPT_THRESHOLD=0
declare -g OPT_LIST_CONTROLS="false"

source "${SCRIPT_DIR}/lib/constants.sh"
source "${SCRIPT_DIR}/lib/utils.sh"
source "${SCRIPT_DIR}/lib/registry.sh"
source "${SCRIPT_DIR}/lib/engine.sh"

_source_if_exists() {
    local path="$1"
    if [[ -f "$path" ]]; then
        source "$path"
    fi
}

_source_if_exists "${SCRIPT_DIR}/lib/report_terminal.sh"
_source_if_exists "${SCRIPT_DIR}/lib/report_json.sh"
_source_if_exists "${SCRIPT_DIR}/lib/report_html.sh"
_source_if_exists "${SCRIPT_DIR}/lib/baseline.sh"
_source_if_exists "${SCRIPT_DIR}/controls/registry_data.sh"

for check_file in "${SCRIPT_DIR}"/checks/*.sh; do
    [[ -f "$check_file" ]] && source "$check_file"
done

print_version() {
    echo "cisaudit v${VERSION}"
}

print_help() {
    echo -e "${BOLD}cisaudit${RESET} — CIS Benchmark Compliance Auditor for Linux"
    echo ""
    echo -e "${BOLD}USAGE${RESET}"
    echo "    cisaudit [OPTIONS]"
    echo ""
    echo -e "${BOLD}OPTIONS${RESET}"
    echo "    -l, --level LEVEL        Benchmark level: 1, 2, or all (default: all)"
    echo "    -f, --format FORMAT      Output: terminal, json, html (default: terminal)"
    echo "    -o, --output FILE        Write report to file (default: stdout)"
    echo "    -c, --categories LIST    Categories to audit: 1,2,3,4,5,6 (default: all)"
    echo "    -b, --baseline FILE      Compare against a previous baseline JSON"
    echo "    -s, --save-baseline FILE Save results as a baseline JSON file"
    echo "    -t, --test-root DIR      Use DIR as system root (for testing)"
    echo "        --threshold PCT      Minimum pass % to exit 0 (default: 0)"
    echo "        --list-controls      List all registered controls and exit"
    echo "    -q, --quiet              Suppress progress output"
    echo "    -v, --version            Print version and exit"
    echo "    -h, --help               Print this help and exit"
    echo ""
    echo -e "${BOLD}EXAMPLES${RESET}"
    echo "    sudo cisaudit"
    echo "    sudo cisaudit -l 1 -f json -o report.json"
    echo "    sudo cisaudit -c 5 -f terminal"
    echo "    cisaudit -t testdata/fixtures -f json"
    echo "    cisaudit --list-controls"
    echo ""
    echo -e "${BOLD}BENCHMARK${RESET}"
    echo "    ${CIS_BENCHMARK}"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -l|--level)
                OPT_LEVEL="$2"
                shift 2
                ;;
            -f|--format)
                OPT_FORMAT="$2"
                shift 2
                ;;
            -o|--output)
                OPT_OUTPUT="$2"
                shift 2
                ;;
            -c|--categories)
                OPT_CATEGORIES="$2"
                shift 2
                ;;
            -b|--baseline)
                OPT_BASELINE="$2"
                shift 2
                ;;
            -s|--save-baseline)
                OPT_SAVE_BASELINE="$2"
                shift 2
                ;;
            -t|--test-root)
                SYSROOT="${2%/}"
                shift 2
                ;;
            --threshold)
                OPT_THRESHOLD="$2"
                shift 2
                ;;
            --list-controls)
                OPT_LIST_CONTROLS="true"
                shift
                ;;
            -q|--quiet)
                QUIET="true"
                shift
                ;;
            -v|--version)
                print_version
                exit "$EXIT_OK"
                ;;
            -h|--help)
                print_help
                exit "$EXIT_OK"
                ;;
            *)
                fail "Unknown option: $1 (use --help for usage)"
                ;;
        esac
    done
}

list_controls() {
    local id
    printf "${BOLD}%-10s %-8s %-8s %-50s${RESET}\n" "ID" "Level" "Scored" "Title"
    printf "%-10s %-8s %-8s %-50s\n" "----------" "--------" "--------" "--------------------------------------------------"
    for id in "${REGISTERED_IDS[@]}"; do
        printf "%-10s %-8s %-8s %-50s\n" \
            "$id" \
            "${CTRL_LEVEL[$id]}" \
            "${CTRL_SCORED[$id]}" \
            "${CTRL_TITLE[$id]}"
    done
    echo ""
    echo "Total: ${#REGISTERED_IDS[@]} controls"
}

should_run_check() {
    local id="$1"

    if [[ "$OPT_LEVEL" != "all" && "${CTRL_LEVEL[$id]}" != "$OPT_LEVEL" ]]; then
        return 1
    fi

    if [[ "$OPT_CATEGORIES" != "all" ]]; then
        local section_num="${id%%.*}"
        if [[ ! ",$OPT_CATEGORIES," == *",$section_num,"* ]]; then
            return 1
        fi
    fi

    return 0
}

run_checks() {
    local total="${#REGISTERED_IDS[@]}"
    local count=0
    local id fn

    for id in "${REGISTERED_IDS[@]}"; do
        ((count++)) || true
        fn="${CTRL_CHECK_FN[$id]}"

        if ! should_run_check "$id"; then
            continue
        fi

        progress "${count}/${total}" "${CTRL_TITLE[$id]}"

        if declare -f "$fn" &>/dev/null; then
            "$fn" || true
        else
            record_result "$id" "$STATUS_SKIP" "Check function ${fn} not implemented"
        fi
    done

    clear_progress
}

generate_report() {
    local output=""

    case "$OPT_FORMAT" in
        terminal)
            if declare -f emit_terminal_report &>/dev/null; then
                output=$(emit_terminal_report)
            else
                fail "Terminal reporter not loaded"
            fi
            ;;
        json)
            if declare -f emit_json_report &>/dev/null; then
                output=$(emit_json_report)
            else
                fail "JSON reporter not loaded"
            fi
            ;;
        html)
            if declare -f emit_html_report &>/dev/null; then
                output=$(emit_html_report)
            else
                fail "HTML reporter not loaded"
            fi
            ;;
        *)
            fail "Unknown format: ${OPT_FORMAT} (use terminal, json, or html)"
            ;;
    esac

    if [[ -n "$OPT_OUTPUT" ]]; then
        echo "$output" > "$OPT_OUTPUT"
        info "Report written to ${OPT_OUTPUT}"
    else
        echo "$output"
    fi
}

main() {
    check_bash_version
    parse_args "$@"

    if [[ "$OPT_LIST_CONTROLS" == "true" ]]; then
        list_controls
        exit "$EXIT_OK"
    fi

    detect_os
    local is_root=0
    check_root && is_root=1

    info "cisaudit v${VERSION} — ${CIS_BENCHMARK}"
    info "Target: ${SYSROOT} | OS: ${DETECTED_ID} ${DETECTED_VERSION} | Level: ${OPT_LEVEL}"
    info "Controls: $(get_total_controls) registered"
    [[ "$QUIET" == "true" ]] || echo "" >&2

    run_checks
    compute_scores

    generate_report

    if [[ -n "$OPT_SAVE_BASELINE" ]]; then
        if declare -f save_baseline &>/dev/null; then
            save_baseline "$OPT_SAVE_BASELINE"
            info "Baseline saved to ${OPT_SAVE_BASELINE}"
        else
            warn "Baseline module not loaded"
        fi
    fi

    if [[ -n "$OPT_BASELINE" ]]; then
        if declare -f diff_baseline &>/dev/null; then
            diff_baseline "$OPT_BASELINE"
        else
            warn "Baseline module not loaded"
        fi
    fi

    local score_int="${SCORE_OVERALL%.*}"
    if (( score_int < OPT_THRESHOLD )); then
        exit "$EXIT_FAIL"
    fi

    exit "$EXIT_OK"
}

main "$@"
