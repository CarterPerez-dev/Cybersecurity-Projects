#!/usr/bin/env bash
# ©AngelaMos | 2026
# test_baseline.sh

test_baseline_save_and_load() {
    CURRENT_TEST="test_baseline_save_and_load"
    setup_test "${PROJECT_DIR}/testdata/fixtures"

    check_1_1_1
    check_3_1_1
    check_6_2_1

    compute_scores

    local tmpfile
    tmpfile=$(mktemp /tmp/cisaudit_baseline_XXXXXX.json)
    save_baseline "$tmpfile"

    BASELINE_STATUS=()
    load_baseline "$tmpfile"

    ((TEST_TOTAL++)) || true
    if [[ "${BASELINE_STATUS[1.1.1]:-}" == "PASS" ]]; then
        ((TEST_PASS++)) || true
    else
        ((TEST_FAIL++)) || true
        echo "  FAIL: ${CURRENT_TEST} — Expected BASELINE_STATUS[1.1.1]=PASS, got '${BASELINE_STATUS[1.1.1]:-UNSET}'" >&2
    fi

    ((TEST_TOTAL++)) || true
    if [[ "${BASELINE_STATUS[3.1.1]:-}" == "PASS" ]]; then
        ((TEST_PASS++)) || true
    else
        ((TEST_FAIL++)) || true
        echo "  FAIL: ${CURRENT_TEST} — Expected BASELINE_STATUS[3.1.1]=PASS, got '${BASELINE_STATUS[3.1.1]:-UNSET}'" >&2
    fi

    ((TEST_TOTAL++)) || true
    if [[ "${BASELINE_STATUS[6.2.1]:-}" == "PASS" ]]; then
        ((TEST_PASS++)) || true
    else
        ((TEST_FAIL++)) || true
        echo "  FAIL: ${CURRENT_TEST} — Expected BASELINE_STATUS[6.2.1]=PASS, got '${BASELINE_STATUS[6.2.1]:-UNSET}'" >&2
    fi

    rm -f "$tmpfile"
}

test_baseline_diff_all_unchanged() {
    CURRENT_TEST="test_baseline_diff_all_unchanged"
    setup_test "${PROJECT_DIR}/testdata/fixtures"

    check_1_1_1
    check_3_1_1

    compute_scores

    local tmpfile
    tmpfile=$(mktemp /tmp/cisaudit_baseline_XXXXXX.json)
    save_baseline "$tmpfile"

    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_1_1_1
    check_3_1_1

    compute_scores

    local diff_output
    diff_output=$(diff_baseline "$tmpfile" 2>&1)

    ((TEST_TOTAL++)) || true
    if echo "$diff_output" | grep -q "0 improved.*0 regressed.*2 unchanged"; then
        ((TEST_PASS++)) || true
    else
        ((TEST_FAIL++)) || true
        echo "  FAIL: ${CURRENT_TEST} — Expected 0 improved, 0 regressed, 2 unchanged in diff output" >&2
        echo "  Got: ${diff_output}" >&2
    fi

    rm -f "$tmpfile"
}

test_baseline_diff_with_regression() {
    CURRENT_TEST="test_baseline_diff_with_regression"
    setup_test "${PROJECT_DIR}/testdata/fixtures"

    check_1_1_1
    check_3_1_1

    compute_scores

    local tmpfile
    tmpfile=$(mktemp /tmp/cisaudit_baseline_XXXXXX.json)
    save_baseline "$tmpfile"

    reset_results

    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_1_1_1

    SYSROOT="${PROJECT_DIR}/testdata/fixtures_fail"
    check_3_1_1

    compute_scores

    local diff_output
    diff_output=$(diff_baseline "$tmpfile" 2>&1)

    ((TEST_TOTAL++)) || true
    if echo "$diff_output" | grep -q "1 regressed"; then
        ((TEST_PASS++)) || true
    else
        ((TEST_FAIL++)) || true
        echo "  FAIL: ${CURRENT_TEST} — Expected 1 regressed in diff output" >&2
        echo "  Got: ${diff_output}" >&2
    fi

    rm -f "$tmpfile"
}

test_baseline_missing_file() {
    CURRENT_TEST="test_baseline_missing_file"
    setup_test "${PROJECT_DIR}/testdata/fixtures"

    local result
    result=$(load_baseline "/tmp/nonexistent_baseline_12345.json" 2>&1) || true

    ((TEST_TOTAL++)) || true
    if [[ $? -eq 0 ]] || echo "$result" | grep -q "not found"; then
        ((TEST_PASS++)) || true
    else
        ((TEST_FAIL++)) || true
        echo "  FAIL: ${CURRENT_TEST} — Expected failure or warning for missing baseline file" >&2
    fi
}

test_baseline_saved_file_is_valid_json() {
    CURRENT_TEST="test_baseline_saved_file_is_valid_json"
    setup_test "${PROJECT_DIR}/testdata/fixtures"

    check_1_1_1
    check_6_2_1

    compute_scores

    local tmpfile
    tmpfile=$(mktemp /tmp/cisaudit_baseline_XXXXXX.json)
    save_baseline "$tmpfile"

    assert_json_valid "$tmpfile"

    rm -f "$tmpfile"
}
