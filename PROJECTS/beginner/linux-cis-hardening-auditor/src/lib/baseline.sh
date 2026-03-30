#!/usr/bin/env bash
# ©AngelaMos | 2026
# baseline.sh

declare -gA BASELINE_STATUS

save_baseline() {
    local file="$1"
    emit_json_report > "$file"
}

load_baseline() {
    local file="$1"
    BASELINE_STATUS=()

    if [[ ! -f "$file" ]]; then
        warn "Baseline file not found: ${file}"
        return 1
    fi

    local current_id=""
    local id_pattern='"id":[[:space:]]*"([^"]+)"'
    local status_pattern='"status":[[:space:]]*"([^"]+)"'
    while IFS= read -r line; do
        if [[ "$line" =~ $id_pattern ]]; then
            current_id="${BASH_REMATCH[1]}"
        fi
        if [[ -n "$current_id" && "$line" =~ $status_pattern ]]; then
            BASELINE_STATUS["$current_id"]="${BASH_REMATCH[1]}"
            current_id=""
        fi
    done < "$file"
}

diff_baseline() {
    local file="$1"

    if ! load_baseline "$file"; then
        return 1
    fi

    local regressions=0
    local improvements=0
    local new_controls=0
    local unchanged=0

    echo ""
    echo -e "${BOLD}Baseline Comparison${RESET} (vs ${file})"
    echo -e "$(printf '%.0s─' {1..60})"

    local id baseline_stat current_stat
    for id in "${RESULT_ORDER[@]}"; do
        current_stat="${RESULT_STATUS[$id]}"
        baseline_stat="${BASELINE_STATUS[$id]:-}"

        if [[ -z "$baseline_stat" ]]; then
            ((new_controls++)) || true
            printf "  ${CYAN}+${RESET} %-10s %s ${DIM}(new)${RESET}\n" "$id" "${CTRL_TITLE[$id]}"
            continue
        fi

        if [[ "$baseline_stat" == "$current_stat" ]]; then
            ((unchanged++)) || true
            continue
        fi

        if [[ "$baseline_stat" == "$STATUS_PASS" && "$current_stat" == "$STATUS_FAIL" ]]; then
            ((regressions++)) || true
            printf "  ${RED}-${RESET} %-10s %s ${RED}(PASS → FAIL)${RESET}\n" "$id" "${CTRL_TITLE[$id]}"
        elif [[ "$baseline_stat" == "$STATUS_FAIL" && "$current_stat" == "$STATUS_PASS" ]]; then
            ((improvements++)) || true
            printf "  ${GREEN}+${RESET} %-10s %s ${GREEN}(FAIL → PASS)${RESET}\n" "$id" "${CTRL_TITLE[$id]}"
        else
            printf "  ${YELLOW}~${RESET} %-10s %s ${YELLOW}(${baseline_stat} → ${current_stat})${RESET}\n" "$id" "${CTRL_TITLE[$id]}"
        fi
    done

    local removed=0
    for id in "${!BASELINE_STATUS[@]}"; do
        if [[ -z "${RESULT_STATUS[$id]:-}" ]]; then
            ((removed++)) || true
            printf "  ${DIM}x${RESET} %-10s ${DIM}(removed)${RESET}\n" "$id"
        fi
    done

    echo ""
    echo -e "${BOLD}Summary:${RESET} ${GREEN}${improvements} improved${RESET}, ${RED}${regressions} regressed${RESET}, ${unchanged} unchanged, ${new_controls} new, ${removed} removed"

    if (( regressions > 0 )); then
        warn "${regressions} regression(s) detected"
    fi
}
