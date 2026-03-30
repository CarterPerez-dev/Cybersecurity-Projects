#!/usr/bin/env bash
# ©AngelaMos | 2026
# 06_maintenance.sh

_check_file_permissions() {
    local id="$1"
    local filepath="$2"
    local expected_perms="$3"
    local expected_owner="$4"
    local expected_group="$5"

    local status="$STATUS_PASS"
    local evidence=""
    local full_path="${SYSROOT}${filepath}"

    if [[ ! -f "$full_path" ]]; then
        status="$STATUS_SKIP"
        evidence="${filepath} not found"
        record_result "$id" "$status" "$evidence"
        return
    fi

    local file_stat
    if file_stat=$(run_cmd stat -c '%a %U %G' "$full_path"); then
        local perms owner group
        perms=$(echo "$file_stat" | awk '{print $1}')
        owner=$(echo "$file_stat" | awk '{print $2}')
        group=$(echo "$file_stat" | awk '{print $3}')

        local issues=""

        if [[ "$owner" != "$expected_owner" ]]; then
            issues="${issues:+${issues}; }owner is ${owner} (expected ${expected_owner})"
        fi
        if [[ "$group" != "$expected_group" ]]; then
            issues="${issues:+${issues}; }group is ${group} (expected ${expected_group})"
        fi
        if (( 8#$perms > 8#$expected_perms )); then
            issues="${issues:+${issues}; }permissions ${perms} (expected ${expected_perms} or stricter)"
        fi

        if [[ -n "$issues" ]]; then
            status="$STATUS_FAIL"
            evidence="${filepath}: ${issues}"
        else
            evidence="${filepath} permissions ${perms}, owned by ${owner}:${group}"
        fi
    else
        evidence="${filepath} exists (permissions not verifiable in test mode)"
    fi

    record_result "$id" "$status" "$evidence"
}

check_6_1_1() {
    _check_file_permissions "6.1.1" "/etc/passwd" "644" "root" "root"
}

check_6_1_2() {
    _check_file_permissions "6.1.2" "/etc/shadow" "640" "root" "shadow"
}

check_6_1_3() {
    _check_file_permissions "6.1.3" "/etc/group" "644" "root" "root"
}

check_6_1_4() {
    _check_file_permissions "6.1.4" "/etc/gshadow" "640" "root" "shadow"
}

check_6_1_5() {
    _check_file_permissions "6.1.5" "/etc/passwd-" "600" "root" "root"
}

check_6_2_1() {
    local id="6.2.1"
    local status="$STATUS_PASS"
    local evidence=""

    local passwd_file="${SYSROOT}/etc/passwd"

    if [[ ! -f "$passwd_file" ]]; then
        status="$STATUS_SKIP"
        evidence="/etc/passwd not found"
        record_result "$id" "$status" "$evidence"
        return
    fi

    local duplicates
    duplicates=$(awk -F: '{print $3}' "$passwd_file" | sort | uniq -d)

    if [[ -n "$duplicates" ]]; then
        status="$STATUS_FAIL"
        evidence="Duplicate UIDs found: ${duplicates}"
    else
        evidence="No duplicate UIDs found"
    fi

    record_result "$id" "$status" "$evidence"
}

check_6_2_2() {
    local id="6.2.2"
    local status="$STATUS_PASS"
    local evidence=""

    local group_file="${SYSROOT}/etc/group"

    if [[ ! -f "$group_file" ]]; then
        status="$STATUS_SKIP"
        evidence="/etc/group not found"
        record_result "$id" "$status" "$evidence"
        return
    fi

    local duplicates
    duplicates=$(awk -F: '{print $3}' "$group_file" | sort | uniq -d)

    if [[ -n "$duplicates" ]]; then
        status="$STATUS_FAIL"
        evidence="Duplicate GIDs found: ${duplicates}"
    else
        evidence="No duplicate GIDs found"
    fi

    record_result "$id" "$status" "$evidence"
}

check_6_2_3() {
    local id="6.2.3"
    local status="$STATUS_PASS"
    local evidence=""

    local passwd_file="${SYSROOT}/etc/passwd"

    if [[ ! -f "$passwd_file" ]]; then
        status="$STATUS_SKIP"
        evidence="/etc/passwd not found"
        record_result "$id" "$status" "$evidence"
        return
    fi

    local duplicates
    duplicates=$(awk -F: '{print $1}' "$passwd_file" | sort | uniq -d)

    if [[ -n "$duplicates" ]]; then
        status="$STATUS_FAIL"
        evidence="Duplicate user names found: ${duplicates}"
    else
        evidence="No duplicate user names found"
    fi

    record_result "$id" "$status" "$evidence"
}

check_6_2_4() {
    local id="6.2.4"
    local status="$STATUS_PASS"
    local evidence=""

    local passwd_file="${SYSROOT}/etc/passwd"

    if [[ ! -f "$passwd_file" ]]; then
        status="$STATUS_SKIP"
        evidence="/etc/passwd not found"
        record_result "$id" "$status" "$evidence"
        return
    fi

    local uid0_accounts
    uid0_accounts=$(awk -F: '$3 == 0 {print $1}' "$passwd_file")

    local uid0_count
    uid0_count=$(echo "$uid0_accounts" | wc -l)

    if [[ "$uid0_count" -eq 1 && "$uid0_accounts" == "root" ]]; then
        evidence="Only root has UID 0"
    elif [[ "$uid0_count" -eq 0 ]]; then
        status="$STATUS_WARN"
        evidence="No accounts with UID 0 found"
    else
        local non_root
        non_root=$(echo "$uid0_accounts" | grep -v '^root$') || true
        status="$STATUS_FAIL"
        evidence="Non-root accounts with UID 0: ${non_root}"
    fi

    record_result "$id" "$status" "$evidence"
}

check_6_2_5() {
    local id="6.2.5"
    local status="$STATUS_PASS"
    local evidence=""

    local files_to_check=("/etc/passwd" "/etc/shadow" "/etc/group")
    local legacy_found=""

    for filepath in "${files_to_check[@]}"; do
        local full_path="${SYSROOT}${filepath}"
        [[ -f "$full_path" ]] || continue
        if grep -q '^+:' "$full_path"; then
            legacy_found="${legacy_found:+${legacy_found}, }${filepath}"
        fi
    done

    if [[ -n "$legacy_found" ]]; then
        status="$STATUS_FAIL"
        evidence="Legacy + entries found in: ${legacy_found}"
    else
        evidence="No legacy + entries found in passwd/shadow/group"
    fi

    record_result "$id" "$status" "$evidence"
}
