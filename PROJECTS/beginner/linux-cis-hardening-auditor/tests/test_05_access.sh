#!/usr/bin/env bash
# ©AngelaMos | 2026
# test_05_access.sh

test_5_2_4_pass() {
    CURRENT_TEST="test_5_2_4_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_5_2_4
    assert_status "5.2.4" "PASS"
    assert_evidence_contains "5.2.4" "LogLevel"
}

test_5_2_4_fail() {
    CURRENT_TEST="test_5_2_4_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_5_2_4
    assert_status "5.2.4" "FAIL"
    assert_evidence_contains "5.2.4" "QUIET"
}

test_5_2_6_pass() {
    CURRENT_TEST="test_5_2_6_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_5_2_6
    assert_status "5.2.6" "PASS"
    assert_evidence_contains "5.2.6" "MaxAuthTries = 4"
}

test_5_2_6_fail() {
    CURRENT_TEST="test_5_2_6_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_5_2_6
    assert_status "5.2.6" "FAIL"
    assert_evidence_contains "5.2.6" "expected 4 or less"
}

test_5_2_8_pass() {
    CURRENT_TEST="test_5_2_8_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_5_2_8
    assert_status "5.2.8" "PASS"
    assert_evidence_contains "5.2.8" "root login is disabled"
}

test_5_2_8_fail() {
    CURRENT_TEST="test_5_2_8_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_5_2_8
    assert_status "5.2.8" "FAIL"
    assert_evidence_contains "5.2.8" "expected no"
}

test_5_2_9_pass() {
    CURRENT_TEST="test_5_2_9_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_5_2_9
    assert_status "5.2.9" "PASS"
    assert_evidence_contains "5.2.9" "empty passwords are disabled"
}

test_5_2_9_fail() {
    CURRENT_TEST="test_5_2_9_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_5_2_9
    assert_status "5.2.9" "FAIL"
    assert_evidence_contains "5.2.9" "expected no"
}

test_5_2_11_pass() {
    CURRENT_TEST="test_5_2_11_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_5_2_11
    assert_status "5.2.11" "PASS"
    assert_evidence_contains "5.2.11" "strong SSH ciphers"
}

test_5_2_11_fail() {
    CURRENT_TEST="test_5_2_11_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_5_2_11
    assert_status "5.2.11" "FAIL"
    assert_evidence_contains "5.2.11" "Weak SSH ciphers"
}

test_5_2_5_pass() {
    CURRENT_TEST="test_5_2_5_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_5_2_5
    assert_status "5.2.5" "PASS"
    assert_evidence_contains "5.2.5" "X11Forwarding is disabled"
}

test_5_2_5_fail() {
    CURRENT_TEST="test_5_2_5_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_5_2_5
    assert_status "5.2.5" "FAIL"
    assert_evidence_contains "5.2.5" "expected no"
}

test_5_2_7_pass() {
    CURRENT_TEST="test_5_2_7_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_5_2_7
    assert_status "5.2.7" "PASS"
    assert_evidence_contains "5.2.7" "IgnoreRhosts = yes"
}

test_5_2_7_fail() {
    CURRENT_TEST="test_5_2_7_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_5_2_7
    assert_status "5.2.7" "FAIL"
    assert_evidence_contains "5.2.7" "expected yes"
}
