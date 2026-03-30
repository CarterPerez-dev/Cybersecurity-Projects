#!/usr/bin/env bash
# ©AngelaMos | 2026
# test_engine.sh

test_engine_compute_scores_pass_fixtures() {
    CURRENT_TEST="test_engine_compute_scores_pass_fixtures"
    setup_test "${PROJECT_DIR}/testdata/fixtures"

    check_1_1_1
    check_1_2_1
    check_1_5_1
    check_3_1_1
    check_3_2_5
    check_6_2_1
    check_6_2_4

    compute_scores

    ((TEST_TOTAL++)) || true
    if [[ "$SCORE_OVERALL" != "0.0" && "$SCORE_OVERALL" != "N/A" ]]; then
        ((TEST_PASS++)) || true
    else
        ((TEST_FAIL++)) || true
        echo "  FAIL: ${CURRENT_TEST} — SCORE_OVERALL should be > 0, got ${SCORE_OVERALL}" >&2
    fi
}

test_engine_section_scores_populated() {
    CURRENT_TEST="test_engine_section_scores_populated"
    setup_test "${PROJECT_DIR}/testdata/fixtures"

    check_1_1_1
    check_1_2_1
    check_3_1_1
    check_6_2_1

    compute_scores

    local initial_score="${SCORE_BY_SECTION[$SECTION_INITIAL_SETUP]:-}"
    ((TEST_TOTAL++)) || true
    if [[ -n "$initial_score" && "$initial_score" != "N/A" ]]; then
        ((TEST_PASS++)) || true
    else
        ((TEST_FAIL++)) || true
        echo "  FAIL: ${CURRENT_TEST} — Initial Setup section score empty or N/A: '${initial_score}'" >&2
    fi

    local network_score="${SCORE_BY_SECTION[$SECTION_NETWORK]:-}"
    ((TEST_TOTAL++)) || true
    if [[ -n "$network_score" && "$network_score" != "N/A" ]]; then
        ((TEST_PASS++)) || true
    else
        ((TEST_FAIL++)) || true
        echo "  FAIL: ${CURRENT_TEST} — Network section score empty or N/A: '${network_score}'" >&2
    fi
}

test_engine_all_pass_is_100() {
    CURRENT_TEST="test_engine_all_pass_is_100"
    setup_test "${PROJECT_DIR}/testdata/fixtures"

    check_1_1_1
    check_1_2_1
    check_3_1_1

    compute_scores

    ((TEST_TOTAL++)) || true
    if [[ "$SCORE_OVERALL" == "100.0" ]]; then
        ((TEST_PASS++)) || true
    else
        ((TEST_FAIL++)) || true
        echo "  FAIL: ${CURRENT_TEST} — Expected 100.0 overall, got ${SCORE_OVERALL}" >&2
    fi
}

test_engine_mixed_results() {
    CURRENT_TEST="test_engine_mixed_results"
    setup_test "${PROJECT_DIR}/testdata/fixtures"

    check_1_1_1

    SYSROOT="${PROJECT_DIR}/testdata/fixtures_fail"
    check_3_1_1

    compute_scores

    ((TEST_TOTAL++)) || true
    if [[ "$SCORE_OVERALL" == "50.0" ]]; then
        ((TEST_PASS++)) || true
    else
        ((TEST_FAIL++)) || true
        echo "  FAIL: ${CURRENT_TEST} — Expected 50.0 for 1 pass + 1 fail, got ${SCORE_OVERALL}" >&2
    fi
}

test_engine_reset_clears_state() {
    CURRENT_TEST="test_engine_reset_clears_state"
    setup_test "${PROJECT_DIR}/testdata/fixtures"

    check_1_1_1
    check_3_1_1

    reset_results

    ((TEST_TOTAL++)) || true
    if [[ "$TOTAL_PASS" -eq 0 && "$TOTAL_FAIL" -eq 0 && "${#RESULT_ORDER[@]}" -eq 0 ]]; then
        ((TEST_PASS++)) || true
    else
        ((TEST_FAIL++)) || true
        echo "  FAIL: ${CURRENT_TEST} — reset_results did not clear state" >&2
    fi
}
