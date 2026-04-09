#!/usr/bin/env bash
# ©AngelaMos | 2026
# test_05_access_password.sh
#
# Tests for CIS Section 5.3-5.5 password policy and account lockout checks
#
# Uses pass and fail fixture directories to verify PAM password quality
# module presence (5.3.1 pam_pwquality), login.defs PASS_MAX_DAYS
# (5.4.1 <=365), PASS_MIN_DAYS (5.4.2 >=1), PASS_WARN_AGE (5.4.3
# >=7), and account lockout via pam_faillock (5.5.1). Each test
# asserts the expected status and evidence substrings against fixture
# /etc/pam.d/common-password, /etc/login.defs, and /etc/pam.d/
# common-auth contents.
#
# Connects to:
#   checks/05_access_password.sh - check functions under test
#   tests/test_helpers.sh        - setup_test, assert_status,
#                                   assert_evidence_contains

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
