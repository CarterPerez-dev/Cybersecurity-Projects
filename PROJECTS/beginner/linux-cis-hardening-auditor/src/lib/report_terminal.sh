#!/usr/bin/env bash
# ©AngelaMos | 2026
# report_terminal.sh

_status_color() {
    local status="$1"
    case "$status" in
        "$STATUS_PASS") printf '%b' "$GREEN" ;;
        "$STATUS_FAIL") printf '%b' "$RED" ;;
        "$STATUS_WARN") printf '%b' "$YELLOW" ;;
        "$STATUS_SKIP") printf '%b' "$DIM" ;;
    esac
}

_status_symbol() {
    local status="$1"
    case "$status" in
        "$STATUS_PASS") printf '%s' "✔" ;;
        "$STATUS_FAIL") printf '%s' "✖" ;;
        "$STATUS_WARN") printf '%s' "⚠" ;;
        "$STATUS_SKIP") printf '%s' "─" ;;
    esac
}

_progress_bar() {
    local percentage="$1"
    local width=20
    local filled
    local empty

    if [[ "$percentage" == "N/A" ]]; then
        printf '%s' "░░░░░░░░░░░░░░░░░░░░"
        return
    fi

    filled=$(awk "BEGIN { printf \"%d\", ($percentage / 100) * $width + 0.5 }")
    empty=$((width - filled))

    local bar=""
    local i
    for (( i = 0; i < filled; i++ )); do
        bar+="█"
    done
    for (( i = 0; i < empty; i++ )); do
        bar+="░"
    done
    printf '%s' "$bar"
}

_score_color() {
    local score="$1"

    if [[ "$score" == "N/A" ]]; then
        printf '%b' "$DIM"
        return
    fi

    local int_score="${score%.*}"
    if (( int_score >= 80 )); then
        printf '%b' "$GREEN"
    elif (( int_score >= 60 )); then
        printf '%b' "$YELLOW"
    else
        printf '%b' "$RED"
    fi
}

_repeat_char() {
    local char="$1"
    local count="$2"
    local i
    for (( i = 0; i < count; i++ )); do
        printf '%s' "$char"
    done
}

_print_banner() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S %Z')
    local hostname
    hostname=$(hostname 2>/dev/null || echo "unknown")

    printf '\n'
    printf '%b' "$CYAN"
    printf '    _____ ___ ____    _             _ _ _\n'
    printf '   / ____|_ _/ ___|  / \\  _   _  __| (_) |_\n'
    printf '  | |     | |\\___ \\ / _ \\| | | |/ _` | | __|\n'
    printf '  | |___  | | ___) / ___ \\ |_| | (_| | | |_\n'
    printf '   \\____|___|____/_/   \\_\\__,_|\\__,_|_|\\__|\n'
    printf '%b' "$RESET"
    printf '\n'
    printf '  %b%s%b\n' "$BOLD" "$CIS_BENCHMARK" "$RESET"
    printf '  %bcisaudit v%s%b  |  %s  |  %s\n' "$DIM" "$VERSION" "$RESET" "$hostname" "$timestamp"
    printf '\n'
}

_print_summary_cards() {
    local total=$((TOTAL_PASS + TOTAL_FAIL + TOTAL_WARN + TOTAL_SKIP))
    local score_clr
    score_clr=$(_score_color "$SCORE_OVERALL")

    printf '  %b┌─────────────────────────────────────────────────────────────────────┐%b\n' "$DIM" "$RESET"
    printf '  %b│%b  %bOVERALL SCORE%b                                                     %b│%b\n' "$DIM" "$RESET" "$BOLD" "$RESET" "$DIM" "$RESET"
    printf '  %b│%b                                                                     %b│%b\n' "$DIM" "$RESET" "$DIM" "$RESET"
    printf '  %b│%b       %b%s%%%b                                                      %b│%b\n' "$DIM" "$RESET" "${score_clr}${BOLD}" "$SCORE_OVERALL" "$RESET" "$DIM" "$RESET"
    printf '  %b│%b                                                                     %b│%b\n' "$DIM" "$RESET" "$DIM" "$RESET"
    printf '  %b│%b  %bTotal:%b %-6d %b%bPass:%b %-6d %b%bFail:%b %-6d %b%bWarn:%b %-6d %b%bSkip:%b %-4d %b│%b\n' \
        "$DIM" "$RESET" \
        "$BOLD" "$RESET" "$total" \
        "$GREEN" "$BOLD" "$RESET" "$TOTAL_PASS" \
        "$RED" "$BOLD" "$RESET" "$TOTAL_FAIL" \
        "$YELLOW" "$BOLD" "$RESET" "$TOTAL_WARN" \
        "$DIM" "$BOLD" "$RESET" "$TOTAL_SKIP" \
        "$DIM" "$RESET"
    printf '  %b└─────────────────────────────────────────────────────────────────────┘%b\n' "$DIM" "$RESET"
    printf '\n'
}

_print_section_table() {
    printf '  %b%-44s  %4s  %4s  %4s  %4s  %6s%b\n' \
        "$BOLD" "Section" "Pass" "Fail" "Warn" "Skip" "Score" "$RESET"
    printf '  '
    _repeat_char "─" 75
    printf '\n'

    local section
    for section in "${SECTION_ORDER[@]}"; do
        local p="${SECTION_PASS[$section]:-0}"
        local f="${SECTION_FAIL[$section]:-0}"
        local w="${SECTION_WARN[$section]:-0}"
        local s="${SECTION_SKIP[$section]:-0}"
        local score="${SCORE_BY_SECTION[$section]:-N/A}"
        local bar
        bar=$(_progress_bar "$score")
        local sclr
        sclr=$(_score_color "$score")

        local score_display
        if [[ "$score" == "N/A" ]]; then
            score_display="  N/A"
        else
            score_display=$(printf '%5s%%' "$score")
        fi

        printf '  %-44s  %b%4d%b  %b%4d%b  %b%4d%b  %b%4d%b  %b%s%b  %b%s%b\n' \
            "$section" \
            "$GREEN" "$p" "$RESET" \
            "$RED" "$f" "$RESET" \
            "$YELLOW" "$w" "$RESET" \
            "$DIM" "$s" "$RESET" \
            "${sclr}${BOLD}" "$score_display" "$RESET" \
            "$sclr" "$bar" "$RESET"
    done
    printf '\n'
}

_print_detail_results() {
    local section
    for section in "${SECTION_ORDER[@]}"; do
        local has_results=0
        local id
        for id in "${RESULT_ORDER[@]}"; do
            if [[ "${CTRL_SECTION[$id]}" == "$section" ]]; then
                has_results=1
                break
            fi
        done

        if (( has_results == 0 )); then
            continue
        fi

        printf '  %b━━━ %s ━━━%b\n' "$BOLD" "$section" "$RESET"
        printf '\n'

        for id in "${RESULT_ORDER[@]}"; do
            if [[ "${CTRL_SECTION[$id]}" != "$section" ]]; then
                continue
            fi

            local status="${RESULT_STATUS[$id]}"
            local title="${CTRL_TITLE[$id]}"
            local symbol
            symbol=$(_status_symbol "$status")
            local clr
            clr=$(_status_color "$status")

            local suffix=""
            if [[ "$status" == "$STATUS_SKIP" ]]; then
                suffix=" [SKIPPED]"
            fi

            printf "  ${clr} %s ${BOLD}%-9s ${RESET}${clr}%s%s${RESET}\n" \
                "$symbol" "$id" "$title" "$suffix"

            if [[ "$status" == "$STATUS_FAIL" ]]; then
                local evidence="${RESULT_EVIDENCE[$id]:-}"
                local remediation="${CTRL_REMEDIATION[$id]:-}"

                if [[ -n "$evidence" ]]; then
                    printf '  %b             Evidence: %s%b\n' "$DIM" "$evidence" "$RESET"
                fi
                if [[ -n "$remediation" ]]; then
                    printf '  %b             Fix: %s%b\n' "$YELLOW" "$remediation" "$RESET"
                fi
            fi

            if [[ "$status" == "$STATUS_WARN" ]]; then
                local evidence="${RESULT_EVIDENCE[$id]:-}"
                if [[ -n "$evidence" ]]; then
                    printf '  %b             Evidence: %s%b\n' "$DIM" "$evidence" "$RESET"
                fi
            fi
        done
        printf '\n'
    done
}

_print_footer() {
    local l1_clr
    l1_clr=$(_score_color "$SCORE_LEVEL1")
    local l2_clr
    l2_clr=$(_score_color "$SCORE_LEVEL2")
    local ov_clr
    ov_clr=$(_score_color "$SCORE_OVERALL")

    printf '  '
    _repeat_char "═" 75
    printf '\n'

    local l1_display
    if [[ "$SCORE_LEVEL1" == "N/A" ]]; then
        l1_display="N/A"
    else
        l1_display="${SCORE_LEVEL1}%"
    fi

    local l2_display
    if [[ "$SCORE_LEVEL2" == "N/A" ]]; then
        l2_display="N/A"
    else
        l2_display="${SCORE_LEVEL2}%"
    fi

    printf '  %bLevel 1 Score:%b  %b%s%b' "$BOLD" "$RESET" "${l1_clr}${BOLD}" "$l1_display" "$RESET"
    printf '     %bLevel 2 Score:%b  %b%s%b' "$BOLD" "$RESET" "${l2_clr}${BOLD}" "$l2_display" "$RESET"
    printf '     %bOverall Score:%b  %b%s%%%b\n' "$BOLD" "$RESET" "${ov_clr}${BOLD}" "$SCORE_OVERALL" "$RESET"

    printf '  '
    _repeat_char "═" 75
    printf '\n'
    printf '\n'
}

emit_terminal_report() {
    _print_banner
    _print_summary_cards
    _print_section_table
    _print_detail_results
    _print_footer
}
