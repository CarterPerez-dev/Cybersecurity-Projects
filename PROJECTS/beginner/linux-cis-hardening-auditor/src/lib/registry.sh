#!/usr/bin/env bash
# ©AngelaMos | 2026
# registry.sh

declare -gA CTRL_TITLE
declare -gA CTRL_SECTION
declare -gA CTRL_LEVEL
declare -gA CTRL_SCORED
declare -gA CTRL_DESCRIPTION
declare -gA CTRL_REMEDIATION
declare -gA CTRL_CHECK_FN

declare -gA RESULT_STATUS
declare -gA RESULT_EVIDENCE
declare -ga RESULT_ORDER=()

declare -g TOTAL_PASS=0
declare -g TOTAL_FAIL=0
declare -g TOTAL_WARN=0
declare -g TOTAL_SKIP=0
declare -ga REGISTERED_IDS=()

register_control() {
    local id="$1"
    local section="$2"
    local title="$3"
    local level="$4"
    local scored="$5"
    local description="$6"
    local remediation="$7"

    CTRL_TITLE["$id"]="$title"
    CTRL_SECTION["$id"]="$section"
    CTRL_LEVEL["$id"]="$level"
    CTRL_SCORED["$id"]="$scored"
    CTRL_DESCRIPTION["$id"]="$description"
    CTRL_REMEDIATION["$id"]="$remediation"

    local fn_name="check_${id//\./_}"
    CTRL_CHECK_FN["$id"]="$fn_name"
    REGISTERED_IDS+=("$id")
}

record_result() {
    local id="$1"
    local status="$2"
    local evidence="$3"

    RESULT_STATUS["$id"]="$status"
    RESULT_EVIDENCE["$id"]="$evidence"
    RESULT_ORDER+=("$id")

    case "$status" in
        "$STATUS_PASS") ((TOTAL_PASS++)) || true ;;
        "$STATUS_FAIL") ((TOTAL_FAIL++)) || true ;;
        "$STATUS_WARN") ((TOTAL_WARN++)) || true ;;
        "$STATUS_SKIP") ((TOTAL_SKIP++)) || true ;;
    esac
}

reset_results() {
    RESULT_STATUS=()
    RESULT_EVIDENCE=()
    RESULT_ORDER=()
    TOTAL_PASS=0
    TOTAL_FAIL=0
    TOTAL_WARN=0
    TOTAL_SKIP=0
}

get_controls_for_section() {
    local section="$1"
    local id
    for id in "${REGISTERED_IDS[@]}"; do
        if [[ "${CTRL_SECTION[$id]}" == "$section" ]]; then
            echo "$id"
        fi
    done
}

get_controls_for_level() {
    local level="$1"
    local id
    for id in "${REGISTERED_IDS[@]}"; do
        if [[ "${CTRL_LEVEL[$id]}" == "$level" ]]; then
            echo "$id"
        fi
    done
}

get_total_controls() {
    echo "${#REGISTERED_IDS[@]}"
}
