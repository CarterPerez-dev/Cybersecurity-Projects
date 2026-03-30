#!/usr/bin/env bash
# ©AngelaMos | 2026
# test_report_json.sh

test_json_valid_output() {
    CURRENT_TEST="test_json_valid_output"
    setup_test "${PROJECT_DIR}/testdata/fixtures"

    check_1_1_1
    check_3_1_1
    check_6_2_1

    compute_scores

    local json_output
    json_output=$(emit_json_report)

    assert_json_valid "$json_output"
}

test_json_has_version() {
    CURRENT_TEST="test_json_has_version"
    setup_test "${PROJECT_DIR}/testdata/fixtures"

    check_1_1_1

    compute_scores

    local json_output
    json_output=$(emit_json_report)

    ((TEST_TOTAL++)) || true
    if echo "$json_output" | grep -q '"version"'; then
        ((TEST_PASS++)) || true
    else
        ((TEST_FAIL++)) || true
        echo "  FAIL: ${CURRENT_TEST} — JSON missing 'version' field" >&2
    fi
}

test_json_has_controls_array() {
    CURRENT_TEST="test_json_has_controls_array"
    setup_test "${PROJECT_DIR}/testdata/fixtures"

    check_1_1_1
    check_1_2_1
    check_3_1_1

    compute_scores

    local json_output
    json_output=$(emit_json_report)

    ((TEST_TOTAL++)) || true
    if echo "$json_output" | grep -q '"controls"'; then
        ((TEST_PASS++)) || true
    else
        ((TEST_FAIL++)) || true
        echo "  FAIL: ${CURRENT_TEST} — JSON missing 'controls' array" >&2
    fi

    local ctrl_count
    ctrl_count=$(echo "$json_output" | python3 -c "import sys, json; d=json.load(sys.stdin); print(len(d['controls']))" 2>/dev/null) || true

    ((TEST_TOTAL++)) || true
    if [[ "$ctrl_count" == "3" ]]; then
        ((TEST_PASS++)) || true
    else
        ((TEST_FAIL++)) || true
        echo "  FAIL: ${CURRENT_TEST} — Expected 3 controls in JSON, got ${ctrl_count:-error}" >&2
    fi
}

test_json_has_summary() {
    CURRENT_TEST="test_json_has_summary"
    setup_test "${PROJECT_DIR}/testdata/fixtures"

    check_1_1_1

    compute_scores

    local json_output
    json_output=$(emit_json_report)

    ((TEST_TOTAL++)) || true
    if echo "$json_output" | grep -q '"summary"'; then
        ((TEST_PASS++)) || true
    else
        ((TEST_FAIL++)) || true
        echo "  FAIL: ${CURRENT_TEST} — JSON missing 'summary' field" >&2
    fi

    ((TEST_TOTAL++)) || true
    if echo "$json_output" | grep -q '"score_percent"'; then
        ((TEST_PASS++)) || true
    else
        ((TEST_FAIL++)) || true
        echo "  FAIL: ${CURRENT_TEST} — JSON missing 'score_percent' field" >&2
    fi
}

test_json_has_sections_array() {
    CURRENT_TEST="test_json_has_sections_array"
    setup_test "${PROJECT_DIR}/testdata/fixtures"

    check_1_1_1

    compute_scores

    local json_output
    json_output=$(emit_json_report)

    local section_count
    section_count=$(echo "$json_output" | python3 -c "import sys, json; d=json.load(sys.stdin); print(len(d['sections']))" 2>/dev/null) || true

    ((TEST_TOTAL++)) || true
    if [[ "$section_count" == "6" ]]; then
        ((TEST_PASS++)) || true
    else
        ((TEST_FAIL++)) || true
        echo "  FAIL: ${CURRENT_TEST} — Expected 6 sections, got ${section_count:-error}" >&2
    fi
}

test_json_file_output() {
    CURRENT_TEST="test_json_file_output"
    setup_test "${PROJECT_DIR}/testdata/fixtures"

    check_1_1_1
    check_3_1_1

    compute_scores

    local tmpfile
    tmpfile=$(mktemp /tmp/cisaudit_test_XXXXXX.json)
    emit_json_report > "$tmpfile"

    assert_json_valid "$tmpfile"

    rm -f "$tmpfile"
}

test_json_cis_benchmark_field() {
    CURRENT_TEST="test_json_cis_benchmark_field"
    setup_test "${PROJECT_DIR}/testdata/fixtures"

    check_1_1_1

    compute_scores

    local json_output
    json_output=$(emit_json_report)

    ((TEST_TOTAL++)) || true
    if echo "$json_output" | grep -q '"cis_benchmark"'; then
        ((TEST_PASS++)) || true
    else
        ((TEST_FAIL++)) || true
        echo "  FAIL: ${CURRENT_TEST} — JSON missing 'cis_benchmark' field" >&2
    fi
}
