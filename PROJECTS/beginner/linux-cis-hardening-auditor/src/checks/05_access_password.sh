#!/usr/bin/env bash
# ©AngelaMos | 2026
# 05_access_password.sh

check_5_3_1() {
    local id="5.3.1"
    local status="$STATUS_PASS"
    local evidence=""
    local common_password="${SYSROOT}/etc/pam.d/common-password"

    if [[ ! -f "$common_password" ]]; then
        status="$STATUS_SKIP"
        evidence="/etc/pam.d/common-password not found"
        record_result "$id" "$status" "$evidence"
        return
    fi

    if grep -qE '^\s*password\s+.*pam_pwquality\.so' "$common_password"; then
        evidence="pam_pwquality is configured in common-password"
    elif grep -qE '^\s*password\s+.*pam_cracklib\.so' "$common_password"; then
        evidence="pam_cracklib is configured in common-password"
    else
        status="$STATUS_FAIL"
        evidence="No password quality module (pam_pwquality or pam_cracklib) in common-password"
    fi

    record_result "$id" "$status" "$evidence"
}

_check_login_defs_value() {
    local id="$1"
    local param="$2"
    local comparison="$3"
    local threshold="$4"
    local pass_desc="$5"
    local fail_desc="$6"

    local status="$STATUS_PASS"
    local evidence=""
    local login_defs="${SYSROOT}/etc/login.defs"

    if [[ ! -f "$login_defs" ]]; then
        status="$STATUS_SKIP"
        evidence="/etc/login.defs not found"
        record_result "$id" "$status" "$evidence"
        return
    fi

    local value
    value=$(grep -E "^\s*${param}\s" "$login_defs" | tail -1 | awk '{print $2}') || true

    if [[ -z "$value" ]]; then
        status="$STATUS_FAIL"
        evidence="${param} not set in /etc/login.defs"
    elif [[ "$comparison" == "le" ]] && (( value <= threshold )); then
        evidence="${pass_desc} (${param} = ${value})"
    elif [[ "$comparison" == "ge" ]] && (( value >= threshold )); then
        evidence="${pass_desc} (${param} = ${value})"
    else
        status="$STATUS_FAIL"
        evidence="${param} = ${value} (${fail_desc})"
    fi

    record_result "$id" "$status" "$evidence"
}

check_5_4_1() {
    _check_login_defs_value "5.4.1" "PASS_MAX_DAYS" "le" 365 \
        "Password expiration is configured" \
        "expected 365 or less"
}

check_5_4_2() {
    _check_login_defs_value "5.4.2" "PASS_MIN_DAYS" "ge" 1 \
        "Minimum days between password changes is configured" \
        "expected 1 or more"
}

check_5_4_3() {
    _check_login_defs_value "5.4.3" "PASS_WARN_AGE" "ge" 7 \
        "Password expiration warning is configured" \
        "expected 7 or more"
}

check_5_5_1() {
    local id="5.5.1"
    local status="$STATUS_PASS"
    local evidence=""
    local common_auth="${SYSROOT}/etc/pam.d/common-auth"

    if [[ ! -f "$common_auth" ]]; then
        status="$STATUS_SKIP"
        evidence="/etc/pam.d/common-auth not found"
        record_result "$id" "$status" "$evidence"
        return
    fi

    if grep -qE '^\s*auth\s+.*pam_faillock\.so' "$common_auth"; then
        evidence="Account lockout configured via pam_faillock in common-auth"
    elif grep -qE '^\s*auth\s+.*pam_tally2\.so' "$common_auth"; then
        evidence="Account lockout configured via pam_tally2 in common-auth"
    else
        status="$STATUS_FAIL"
        evidence="No account lockout module (pam_faillock or pam_tally2) in common-auth"
    fi

    record_result "$id" "$status" "$evidence"
}
