#!/usr/bin/env bash
# ©AngelaMos | 2026
# test_06_maintenance.sh

test_6_2_1_pass() {
    CURRENT_TEST="test_6_2_1_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_6_2_1
    assert_status "6.2.1" "PASS"
    assert_evidence_contains "6.2.1" "No duplicate UIDs"
}

test_6_2_1_fail() {
    CURRENT_TEST="test_6_2_1_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_6_2_1
    assert_status "6.2.1" "FAIL"
    assert_evidence_contains "6.2.1" "Duplicate UIDs"
}

test_6_2_4_pass() {
    CURRENT_TEST="test_6_2_4_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_6_2_4
    assert_status "6.2.4" "PASS"
    assert_evidence_contains "6.2.4" "Only root has UID 0"
}

test_6_2_4_fail() {
    CURRENT_TEST="test_6_2_4_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_6_2_4
    assert_status "6.2.4" "FAIL"
    assert_evidence_contains "6.2.4" "Non-root accounts with UID 0"
}

test_6_2_5_pass() {
    CURRENT_TEST="test_6_2_5_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_6_2_5
    assert_status "6.2.5" "PASS"
    assert_evidence_contains "6.2.5" "No legacy + entries"
}

test_6_2_5_fail() {
    CURRENT_TEST="test_6_2_5_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_6_2_5
    assert_status "6.2.5" "FAIL"
    assert_evidence_contains "6.2.5" "Legacy + entries"
}

test_6_2_2_pass() {
    CURRENT_TEST="test_6_2_2_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_6_2_2
    assert_status "6.2.2" "PASS"
    assert_evidence_contains "6.2.2" "No duplicate GIDs"
}

test_6_2_3_pass() {
    CURRENT_TEST="test_6_2_3_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_6_2_3
    assert_status "6.2.3" "PASS"
    assert_evidence_contains "6.2.3" "No duplicate user names"
}
