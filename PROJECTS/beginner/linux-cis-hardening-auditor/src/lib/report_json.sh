#!/usr/bin/env bash
# ©AngelaMos | 2026
# report_json.sh

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\r'/\\r}"
    printf '%s' "$s"
}

_json_score() {
    local val="$1"
    if [[ "$val" == "N/A" ]]; then
        printf 'null'
    else
        printf '%s' "$val"
    fi
}

_json_bool() {
    local val="$1"
    if [[ "$val" == "yes" ]]; then
        printf 'true'
    else
        printf 'false'
    fi
}

emit_json_report() {
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local hn
    hn=$(hostname 2>/dev/null || echo "unknown")
    local total=$((TOTAL_PASS + TOTAL_FAIL + TOTAL_WARN + TOTAL_SKIP))

    printf '{\n'
    printf '  "version": "%s",\n' "$(json_escape "$VERSION")"
    printf '  "cis_benchmark": "%s",\n' "$(json_escape "$CIS_BENCHMARK")"
    printf '  "timestamp": "%s",\n' "$timestamp"
    printf '  "hostname": "%s",\n' "$(json_escape "$hn")"
    printf '  "os_id": "%s",\n' "$(json_escape "$DETECTED_ID")"
    printf '  "os_version": "%s",\n' "$(json_escape "$DETECTED_VERSION")"

    printf '  "summary": {\n'
    printf '    "total": %d,\n' "$total"
    printf '    "pass": %d,\n' "$TOTAL_PASS"
    printf '    "fail": %d,\n' "$TOTAL_FAIL"
    printf '    "warn": %d,\n' "$TOTAL_WARN"
    printf '    "skip": %d,\n' "$TOTAL_SKIP"
    printf '    "score_percent": %s,\n' "$(_json_score "$SCORE_OVERALL")"
    printf '    "level1_score": %s,\n' "$(_json_score "$SCORE_LEVEL1")"
    printf '    "level2_score": %s\n' "$(_json_score "$SCORE_LEVEL2")"
    printf '  },\n'

    printf '  "sections": [\n'
    local sec_count=0
    local sec_total="${#SECTION_ORDER[@]}"
    for section in "${SECTION_ORDER[@]}"; do
        ((sec_count++)) || true
        local p="${SECTION_PASS[$section]:-0}"
        local f="${SECTION_FAIL[$section]:-0}"
        local w="${SECTION_WARN[$section]:-0}"
        local s="${SECTION_SKIP[$section]:-0}"
        local score="${SCORE_BY_SECTION[$section]:-N/A}"

        printf '    {\n'
        printf '      "name": "%s",\n' "$(json_escape "$section")"
        printf '      "pass": %d,\n' "$p"
        printf '      "fail": %d,\n' "$f"
        printf '      "warn": %d,\n' "$w"
        printf '      "skip": %d,\n' "$s"
        printf '      "score_percent": %s\n' "$(_json_score "$score")"
        printf '    }'

        if (( sec_count < sec_total )); then
            printf ','
        fi
        printf '\n'
    done
    printf '  ],\n'

    printf '  "controls": [\n'
    local ctrl_count=0
    local ctrl_total="${#RESULT_ORDER[@]}"
    for id in "${RESULT_ORDER[@]}"; do
        ((ctrl_count++)) || true
        local status="${RESULT_STATUS[$id]}"
        local evidence="${RESULT_EVIDENCE[$id]:-}"
        local title="${CTRL_TITLE[$id]}"
        local ctrl_section="${CTRL_SECTION[$id]}"
        local level="${CTRL_LEVEL[$id]}"
        local scored="${CTRL_SCORED[$id]}"
        local remediation="${CTRL_REMEDIATION[$id]:-}"

        printf '    {\n'
        printf '      "id": "%s",\n' "$(json_escape "$id")"
        printf '      "section": "%s",\n' "$(json_escape "$ctrl_section")"
        printf '      "title": "%s",\n' "$(json_escape "$title")"
        printf '      "level": %d,\n' "$level"
        printf '      "scored": %s,\n' "$(_json_bool "$scored")"
        printf '      "status": "%s",\n' "$(json_escape "$status")"
        printf '      "evidence": "%s",\n' "$(json_escape "$evidence")"
        printf '      "remediation": "%s"\n' "$(json_escape "$remediation")"
        printf '    }'

        if (( ctrl_count < ctrl_total )); then
            printf ','
        fi
        printf '\n'
    done
    printf '  ]\n'

    printf '}\n'
}
