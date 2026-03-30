#!/usr/bin/env bash
# ©AngelaMos | 2026
# test_05_access_password.sh

test_5_3_1_pass() {
    CURRENT_TEST="test_5_3_1_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_5_3_1
    assert_status "5.3.1" "PASS"
    assert_evidence_contains "5.3.1" "pam_pwquality"
}

test_5_3_1_fail() {
    CURRENT_TEST="test_5_3_1_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_5_3_1
    assert_status "5.3.1" "FAIL"
    assert_evidence_contains "5.3.1" "No password quality module"
}

test_5_4_1_pass() {
    CURRENT_TEST="test_5_4_1_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_5_4_1
    assert_status "5.4.1" "PASS"
    assert_evidence_contains "5.4.1" "PASS_MAX_DAYS = 365"
}

test_5_4_1_fail() {
    CURRENT_TEST="test_5_4_1_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_5_4_1
    assert_status "5.4.1" "FAIL"
    assert_evidence_contains "5.4.1" "expected 365 or less"
}

test_5_4_2_pass() {
    CURRENT_TEST="test_5_4_2_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_5_4_2
    assert_status "5.4.2" "PASS"
    assert_evidence_contains "5.4.2" "PASS_MIN_DAYS = 1"
}

test_5_4_2_fail() {
    CURRENT_TEST="test_5_4_2_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_5_4_2
    assert_status "5.4.2" "FAIL"
    assert_evidence_contains "5.4.2" "expected 1 or more"
}

test_5_4_3_pass() {
    CURRENT_TEST="test_5_4_3_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_5_4_3
    assert_status "5.4.3" "PASS"
    assert_evidence_contains "5.4.3" "PASS_WARN_AGE = 7"
}

test_5_4_3_fail() {
    CURRENT_TEST="test_5_4_3_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_5_4_3
    assert_status "5.4.3" "FAIL"
    assert_evidence_contains "5.4.3" "expected 7 or more"
}

test_5_5_1_pass() {
    CURRENT_TEST="test_5_5_1_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_5_5_1
    assert_status "5.5.1" "PASS"
    assert_evidence_contains "5.5.1" "pam_faillock"
}

test_5_5_1_fail() {
    CURRENT_TEST="test_5_5_1_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_5_5_1
    assert_status "5.5.1" "FAIL"
    assert_evidence_contains "5.5.1" "No account lockout module"
}
