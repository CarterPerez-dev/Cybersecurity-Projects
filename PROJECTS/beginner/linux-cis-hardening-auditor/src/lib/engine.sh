#!/usr/bin/env bash
# ©AngelaMos | 2026
# engine.sh

declare -gA SCORE_BY_SECTION
declare -gA SECTION_PASS
declare -gA SECTION_FAIL
declare -gA SECTION_WARN
declare -gA SECTION_SKIP
declare -g SCORE_OVERALL=0
declare -g SCORE_LEVEL1=0
declare -g SCORE_LEVEL2=0

compute_scores() {
    local section
    for section in "${SECTION_ORDER[@]}"; do
        SECTION_PASS["$section"]=0
        SECTION_FAIL["$section"]=0
        SECTION_WARN["$section"]=0
        SECTION_SKIP["$section"]=0
    done

    local id
    for id in "${RESULT_ORDER[@]}"; do
        section="${CTRL_SECTION[$id]}"
        case "${RESULT_STATUS[$id]}" in
            "$STATUS_PASS") ((SECTION_PASS["$section"]++)) || true ;;
            "$STATUS_FAIL") ((SECTION_FAIL["$section"]++)) || true ;;
            "$STATUS_WARN") ((SECTION_WARN["$section"]++)) || true ;;
            "$STATUS_SKIP") ((SECTION_SKIP["$section"]++)) || true ;;
        esac
    done

    for section in "${SECTION_ORDER[@]}"; do
        local p="${SECTION_PASS[$section]}"
        local f="${SECTION_FAIL[$section]}"
        local total=$((p + f))
        if (( total > 0 )); then
            SCORE_BY_SECTION["$section"]=$(awk "BEGIN { printf \"%.1f\", ($p / $total) * 100 }")
        else
            SCORE_BY_SECTION["$section"]="N/A"
        fi
    done

    local scored_total=$((TOTAL_PASS + TOTAL_FAIL))
    if (( scored_total > 0 )); then
        SCORE_OVERALL=$(awk "BEGIN { printf \"%.1f\", ($TOTAL_PASS / $scored_total) * 100 }")
    else
        SCORE_OVERALL="0.0"
    fi

    _compute_level_score 1
    SCORE_LEVEL1="$_LEVEL_SCORE"

    _compute_level_score 2
    SCORE_LEVEL2="$_LEVEL_SCORE"
}

_compute_level_score() {
    local level="$1"
    local pass=0
    local fail=0

    local id
    for id in "${RESULT_ORDER[@]}"; do
        if [[ "${CTRL_LEVEL[$id]}" == "$level" ]]; then
            case "${RESULT_STATUS[$id]}" in
                "$STATUS_PASS") ((pass++)) || true ;;
                "$STATUS_FAIL") ((fail++)) || true ;;
            esac
        fi
    done

    local total=$((pass + fail))
    if (( total > 0 )); then
        _LEVEL_SCORE=$(awk "BEGIN { printf \"%.1f\", ($pass / $total) * 100 }")
    else
        _LEVEL_SCORE="N/A"
    fi
}

get_section_total() {
    local section="$1"
    local p="${SECTION_PASS[$section]:-0}"
    local f="${SECTION_FAIL[$section]:-0}"
    local w="${SECTION_WARN[$section]:-0}"
    local s="${SECTION_SKIP[$section]:-0}"
    echo $((p + f + w + s))
}
