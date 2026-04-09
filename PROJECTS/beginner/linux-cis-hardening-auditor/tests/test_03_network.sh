#!/usr/bin/env bash
# ©AngelaMos | 2026
# test_03_network.sh
#
# Tests for CIS Section 3 (Network Configuration) checks
#
# Uses pass and fail fixture directories to verify IP forwarding
# disabled (3.1.1), send_redirects disabled (3.1.2), martian packet
# logging enabled (3.2.1), TCP SYN cookies enabled (3.2.5), IPv6
# router advertisement rejection (3.2.6), and DCCP protocol module
# disabling (3.4.2). Each test asserts the expected status and key
# evidence substrings from sysctl proc tree values and modprobe.d
# configs in the fixture filesystems.
#
# Connects to:
#   checks/03_network.sh - check functions under test
#   tests/test_helpers.sh - setup_test, assert_status,
#                            assert_evidence_contains

test_3_1_1_pass() {
    CURRENT_TEST="test_3_1_1_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_3_1_1
    assert_status "3.1.1" "PASS"
    assert_evidence_contains "3.1.1" "IP forwarding is disabled"
}

test_3_1_1_fail() {
    CURRENT_TEST="test_3_1_1_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_3_1_1
    assert_status "3.1.1" "FAIL"
    assert_evidence_contains "3.1.1" "expected 0"
}

test_3_2_1_pass() {
    CURRENT_TEST="test_3_2_1_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_3_2_1
    assert_status "3.2.1" "PASS"
    assert_evidence_contains "3.2.1" "Suspicious packets are logged"
}

test_3_2_1_fail() {
    CURRENT_TEST="test_3_2_1_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_3_2_1
    assert_status "3.2.1" "FAIL"
    assert_evidence_contains "3.2.1" "expected 1"
}

test_3_2_5_pass() {
    CURRENT_TEST="test_3_2_5_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_3_2_5
    assert_status "3.2.5" "PASS"
    assert_evidence_contains "3.2.5" "TCP SYN Cookies enabled"
}

test_3_2_5_fail() {
    CURRENT_TEST="test_3_2_5_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_3_2_5
    assert_status "3.2.5" "FAIL"
    assert_evidence_contains "3.2.5" "expected 1"
}

test_3_4_2_pass() {
    CURRENT_TEST="test_3_4_2_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_3_4_2
    assert_status "3.4.2" "PASS"
    assert_evidence_contains "3.4.2" "dccp"
}

test_3_4_2_fail() {
    CURRENT_TEST="test_3_4_2_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_3_4_2
    assert_status "3.4.2" "FAIL"
    assert_evidence_contains "3.4.2" "dccp"
}

test_3_1_2_pass() {
    CURRENT_TEST="test_3_1_2_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_3_1_2
    assert_status "3.1.2" "PASS"
    assert_evidence_contains "3.1.2" "redirect sending disabled"
}

test_3_1_2_fail() {
    CURRENT_TEST="test_3_1_2_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_3_1_2
    assert_status "3.1.2" "FAIL"
}

test_3_2_6_pass() {
    CURRENT_TEST="test_3_2_6_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_3_2_6
    assert_status "3.2.6" "PASS"
    assert_evidence_contains "3.2.6" "router advertisements not accepted"
}

test_3_2_6_fail() {
    CURRENT_TEST="test_3_2_6_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_3_2_6
    assert_status "3.2.6" "FAIL"
    assert_evidence_contains "3.2.6" "expected 0"
}
