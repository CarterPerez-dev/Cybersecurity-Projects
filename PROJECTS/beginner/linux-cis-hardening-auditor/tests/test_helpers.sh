#!/usr/bin/env bash
# ©AngelaMos | 2026
# test_helpers.sh
#
# Test assertion framework for the bash test harness
#
# Provides the core testing primitives: setup_test resets registry state
# and sets SYSROOT to a fixture directory for isolated filesystem
# checks. assert_status compares a control's recorded status against an
# expected value. assert_evidence_contains checks for a substring in the
# evidence string. assert_json_valid validates JSON via python3's
# json.tool (accepts both file paths and inline strings). print_results
# outputs the total/pass/fail summary and returns non-zero on failures.
# Tracks counts in TEST_PASS, TEST_FAIL, TEST_TOTAL globals.
#
# Connects to:
#   lib/registry.sh    - reset_results, RESULT_STATUS, RESULT_EVIDENCE
#   tests/test_runner.sh - sources this file before running tests
#   testdata/fixtures/     - pass-scenario fixture directory
#   testdata/fixtures_fail/ - fail-scenario fixture directory

declare -g TEST_PASS=0
declare -g TEST_FAIL=0
declare -g TEST_TOTAL=0
declare -g CURRENT_TEST=""

setup_test() {
    local fixtures_dir="$1"
    reset_results
    SYSROOT="$fixtures_dir"
    DETECTED_ID="debian"
    DETECTED_VERSION="12"
}

assert_status() {
    local id="$1" expected="$2"
    local actual="${RESULT_STATUS[$id]:-UNSET}"
    ((TEST_TOTAL++)) || true
    if [[ "$actual" == "$expected" ]]; then
        ((TEST_PASS++)) || true
    else
        ((TEST_FAIL++)) || true
        echo "  FAIL: ${CURRENT_TEST} — ${id}: expected ${expected}, got ${actual}" >&2
    fi
}

assert_evidence_contains() {
    local id="$1" expected="$2"
    local actual="${RESULT_EVIDENCE[$id]:-}"
    ((TEST_TOTAL++)) || true
    if [[ "$actual" == *"$expected"* ]]; then
        ((TEST_PASS++)) || true
    else
        ((TEST_FAIL++)) || true
        echo "  FAIL: ${CURRENT_TEST} — ${id} evidence missing '${expected}': got '${actual}'" >&2
    fi
}

assert_json_valid() {
    local input="$1"
    ((TEST_TOTAL++)) || true
    if [[ -f "$input" ]]; then
        if python3 -m json.tool "$input" > /dev/null 2>&1; then
            ((TEST_PASS++)) || true
        else
            ((TEST_FAIL++)) || true
            echo "  FAIL: ${CURRENT_TEST} — JSON file '${input}' is not valid" >&2
        fi
    else
        if echo "$input" | python3 -m json.tool > /dev/null 2>&1; then
            ((TEST_PASS++)) || true
        else
            ((TEST_FAIL++)) || true
            echo "  FAIL: ${CURRENT_TEST} — JSON string is not valid" >&2
        fi
    fi
}

print_results() {
    echo ""
    echo "Tests: ${TEST_TOTAL} | Pass: ${TEST_PASS} | Fail: ${TEST_FAIL}"
    if (( TEST_FAIL > 0 )); then
        return 1
    fi
    return 0
}
