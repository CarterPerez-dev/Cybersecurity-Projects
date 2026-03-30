#!/usr/bin/env bash
# ©AngelaMos | 2026
# test_04_logging.sh

test_4_1_1_pass() {
    CURRENT_TEST="test_4_1_1_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_4_1_1
    assert_status "4.1.1" "PASS"
    assert_evidence_contains "4.1.1" "auditd"
}

test_4_1_1_fail() {
    CURRENT_TEST="test_4_1_1_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_4_1_1
    assert_status "4.1.1" "FAIL"
    assert_evidence_contains "4.1.1" "not installed"
}

test_4_1_3_pass() {
    CURRENT_TEST="test_4_1_3_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_4_1_3
    assert_status "4.1.3" "PASS"
    assert_evidence_contains "4.1.3" "audit=1"
}

test_4_1_3_fail() {
    CURRENT_TEST="test_4_1_3_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_4_1_3
    assert_status "4.1.3" "FAIL"
    assert_evidence_contains "4.1.3" "audit=1"
}

test_4_1_4_pass() {
    CURRENT_TEST="test_4_1_4_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_4_1_4
    assert_status "4.1.4" "PASS"
    assert_evidence_contains "4.1.4" "backlog"
}

test_4_1_4_fail() {
    CURRENT_TEST="test_4_1_4_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_4_1_4
    assert_status "4.1.4" "FAIL"
    assert_evidence_contains "4.1.4" "backlog"
}

test_4_1_5_pass() {
    CURRENT_TEST="test_4_1_5_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_4_1_5
    assert_status "4.1.5" "PASS"
    assert_evidence_contains "4.1.5" "Time change"
}

test_4_1_5_fail() {
    CURRENT_TEST="test_4_1_5_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_4_1_5
    assert_status "4.1.5" "FAIL"
    assert_evidence_contains "4.1.5" "Missing audit rules"
}

test_4_2_1_pass() {
    CURRENT_TEST="test_4_2_1_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_4_2_1
    assert_status "4.2.1" "PASS"
    assert_evidence_contains "4.2.1" "rsyslog"
}

test_4_2_1_fail() {
    CURRENT_TEST="test_4_2_1_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_4_2_1
    assert_status "4.2.1" "FAIL"
    assert_evidence_contains "4.2.1" "not installed"
}

test_4_2_3_pass() {
    CURRENT_TEST="test_4_2_3_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_4_2_3
    assert_status "4.2.3" "PASS"
    assert_evidence_contains "4.2.3" "0640"
}

test_4_2_3_fail() {
    CURRENT_TEST="test_4_2_3_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_4_2_3
    assert_status "4.2.3" "FAIL"
    assert_evidence_contains "4.2.3" "0777"
}

test_4_2_4_pass() {
    CURRENT_TEST="test_4_2_4_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_4_2_4
    assert_status "4.2.4" "PASS"
    assert_evidence_contains "4.2.4" "logging rule"
}

test_4_2_4_fail() {
    CURRENT_TEST="test_4_2_4_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_4_2_4
    assert_status "4.2.4" "FAIL"
    assert_evidence_contains "4.2.4" "No logging rules"
}
