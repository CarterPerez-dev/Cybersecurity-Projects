#!/usr/bin/env bash
# ©AngelaMos | 2026
# test_01_initial_setup.sh

test_1_1_1_pass() {
    CURRENT_TEST="test_1_1_1_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_1_1_1
    assert_status "1.1.1" "PASS"
    assert_evidence_contains "1.1.1" "cramfs"
}

test_1_1_1_fail() {
    CURRENT_TEST="test_1_1_1_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_1_1_1
    assert_status "1.1.1" "FAIL"
    assert_evidence_contains "1.1.1" "cramfs"
}

test_1_2_1_pass() {
    CURRENT_TEST="test_1_2_1_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_1_2_1
    assert_status "1.2.1" "PASS"
    assert_evidence_contains "1.2.1" "/tmp"
}

test_1_2_1_fail() {
    CURRENT_TEST="test_1_2_1_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_1_2_1
    assert_status "1.2.1" "FAIL"
    assert_evidence_contains "1.2.1" "/tmp"
}

test_1_2_2_pass() {
    CURRENT_TEST="test_1_2_2_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_1_2_2
    assert_status "1.2.2" "PASS"
    assert_evidence_contains "1.2.2" "noexec"
}

test_1_2_2_fail() {
    CURRENT_TEST="test_1_2_2_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_1_2_2
    assert_status "1.2.2" "SKIP"
    assert_evidence_contains "1.2.2" "/tmp"
}

test_1_2_3_pass() {
    CURRENT_TEST="test_1_2_3_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_1_2_3
    assert_status "1.2.3" "PASS"
    assert_evidence_contains "1.2.3" "nosuid"
}

test_1_2_4_pass() {
    CURRENT_TEST="test_1_2_4_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_1_2_4
    assert_status "1.2.4" "PASS"
    assert_evidence_contains "1.2.4" "nodev"
}

test_1_5_1_pass() {
    CURRENT_TEST="test_1_5_1_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_1_5_1
    assert_status "1.5.1" "PASS"
    assert_evidence_contains "1.5.1" "ASLR is fully enabled"
}

test_1_5_1_fail() {
    CURRENT_TEST="test_1_5_1_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_1_5_1
    assert_status "1.5.1" "FAIL"
    assert_evidence_contains "1.5.1" "ASLR is disabled"
}

test_1_5_2_pass() {
    CURRENT_TEST="test_1_5_2_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_1_5_2
    assert_status "1.5.2" "PASS"
    assert_evidence_contains "1.5.2" "Core dumps restricted"
}

test_1_5_2_fail() {
    CURRENT_TEST="test_1_5_2_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_1_5_2
    assert_status "1.5.2" "FAIL"
}
