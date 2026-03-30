#!/usr/bin/env bash
# ©AngelaMos | 2026
# test_02_services.sh

test_2_1_1_pass() {
    CURRENT_TEST="test_2_1_1_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_2_1_1
    assert_status "2.1.1" "PASS"
    assert_evidence_contains "2.1.1" "not installed"
}

test_2_1_1_fail() {
    CURRENT_TEST="test_2_1_1_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_2_1_1
    assert_status "2.1.1" "FAIL"
    assert_evidence_contains "2.1.1" "xinetd"
}

test_2_2_1_pass() {
    CURRENT_TEST="test_2_2_1_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_2_2_1
    assert_status "2.2.1" "PASS"
    assert_evidence_contains "2.2.1" "not installed"
}

test_2_2_1_fail() {
    CURRENT_TEST="test_2_2_1_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_2_2_1
    assert_status "2.2.1" "FAIL"
    assert_evidence_contains "2.2.1" "X Window System"
}

test_2_2_9_pass() {
    CURRENT_TEST="test_2_2_9_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_2_2_9
    assert_status "2.2.9" "PASS"
    assert_evidence_contains "2.2.9" "No HTTP server"
}

test_2_2_9_fail() {
    CURRENT_TEST="test_2_2_9_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_2_2_9
    assert_status "2.2.9" "FAIL"
    assert_evidence_contains "2.2.9" "apache2"
}

test_2_2_15_pass() {
    CURRENT_TEST="test_2_2_15_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_2_2_15
    assert_status "2.2.15" "PASS"
    assert_evidence_contains "2.2.15" "loopback-only"
}

test_2_2_15_fail() {
    CURRENT_TEST="test_2_2_15_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_2_2_15
    assert_status "2.2.15" "FAIL"
    assert_evidence_contains "2.2.15" "inet_interfaces"
}
