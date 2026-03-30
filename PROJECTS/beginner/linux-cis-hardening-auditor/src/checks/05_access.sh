#!/usr/bin/env bash
# ©AngelaMos | 2026
# 05_access.sh

check_5_1_1() {
    local id="5.1.1"
    local status="$STATUS_PASS"
    local evidence=""

    if service_is_enabled "cron"; then
        evidence="cron daemon is enabled"
    elif file_exists "/etc/crontab"; then
        evidence="cron configuration exists (/etc/crontab found)"
    else
        status="$STATUS_FAIL"
        evidence="cron daemon is not enabled"
    fi

    record_result "$id" "$status" "$evidence"
}

check_5_1_2() {
    local id="5.1.2"
    local status="$STATUS_PASS"
    local evidence=""

    local crontab="${SYSROOT}/etc/crontab"

    if [[ ! -f "$crontab" ]]; then
        status="$STATUS_SKIP"
        evidence="/etc/crontab not found"
        record_result "$id" "$status" "$evidence"
        return
    fi

    local file_stat
    if file_stat=$(run_cmd stat -c '%a %U %G' "$crontab"); then
        local perms owner group
        perms=$(echo "$file_stat" | awk '{print $1}')
        owner=$(echo "$file_stat" | awk '{print $2}')
        group=$(echo "$file_stat" | awk '{print $3}')

        if [[ "$owner" != "root" || "$group" != "root" ]]; then
            status="$STATUS_FAIL"
            evidence="/etc/crontab owned by ${owner}:${group} (expected root:root)"
        elif (( 8#$perms > 8#0600 )); then
            status="$STATUS_FAIL"
            evidence="/etc/crontab permissions ${perms} (expected 600 or stricter)"
        else
            evidence="/etc/crontab permissions ${perms}, owned by ${owner}:${group}"
        fi
    else
        evidence="/etc/crontab exists (permissions not verifiable in test mode)"
    fi

    record_result "$id" "$status" "$evidence"
}

check_5_1_3() {
    local id="5.1.3"
    local status="$STATUS_PASS"
    local evidence=""

    local cron_hourly="${SYSROOT}/etc/cron.hourly"

    if [[ ! -d "$cron_hourly" ]]; then
        status="$STATUS_SKIP"
        evidence="/etc/cron.hourly not found"
        record_result "$id" "$status" "$evidence"
        return
    fi

    local dir_stat
    if dir_stat=$(run_cmd stat -c '%a %U %G' "$cron_hourly"); then
        local perms owner group
        perms=$(echo "$dir_stat" | awk '{print $1}')
        owner=$(echo "$dir_stat" | awk '{print $2}')
        group=$(echo "$dir_stat" | awk '{print $3}')

        if [[ "$owner" != "root" || "$group" != "root" ]]; then
            status="$STATUS_FAIL"
            evidence="/etc/cron.hourly owned by ${owner}:${group} (expected root:root)"
        elif (( 8#$perms > 8#0700 )); then
            status="$STATUS_FAIL"
            evidence="/etc/cron.hourly permissions ${perms} (expected 700 or stricter)"
        else
            evidence="/etc/cron.hourly permissions ${perms}, owned by ${owner}:${group}"
        fi
    else
        evidence="/etc/cron.hourly exists (permissions not verifiable in test mode)"
    fi

    record_result "$id" "$status" "$evidence"
}

check_5_1_4() {
    local id="5.1.4"
    local status="$STATUS_PASS"
    local evidence=""

    local cron_daily="${SYSROOT}/etc/cron.daily"

    if [[ ! -d "$cron_daily" ]]; then
        status="$STATUS_SKIP"
        evidence="/etc/cron.daily not found"
        record_result "$id" "$status" "$evidence"
        return
    fi

    local dir_stat
    if dir_stat=$(run_cmd stat -c '%a %U %G' "$cron_daily"); then
        local perms owner group
        perms=$(echo "$dir_stat" | awk '{print $1}')
        owner=$(echo "$dir_stat" | awk '{print $2}')
        group=$(echo "$dir_stat" | awk '{print $3}')

        if [[ "$owner" != "root" || "$group" != "root" ]]; then
            status="$STATUS_FAIL"
            evidence="/etc/cron.daily owned by ${owner}:${group} (expected root:root)"
        elif (( 8#$perms > 8#0700 )); then
            status="$STATUS_FAIL"
            evidence="/etc/cron.daily permissions ${perms} (expected 700 or stricter)"
        else
            evidence="/etc/cron.daily permissions ${perms}, owned by ${owner}:${group}"
        fi
    else
        evidence="/etc/cron.daily exists (permissions not verifiable in test mode)"
    fi

    record_result "$id" "$status" "$evidence"
}

check_5_2_1() {
    local id="5.2.1"
    local status="$STATUS_PASS"
    local evidence=""

    local sshd_config="${SYSROOT}/etc/ssh/sshd_config"

    if [[ ! -f "$sshd_config" ]]; then
        status="$STATUS_SKIP"
        evidence="sshd_config not found"
        record_result "$id" "$status" "$evidence"
        return
    fi

    local file_stat
    if file_stat=$(run_cmd stat -c '%a %U %G' "$sshd_config"); then
        local perms owner group
        perms=$(echo "$file_stat" | awk '{print $1}')
        owner=$(echo "$file_stat" | awk '{print $2}')
        group=$(echo "$file_stat" | awk '{print $3}')

        if [[ "$owner" != "root" ]]; then
            status="$STATUS_FAIL"
            evidence="sshd_config owned by ${owner} (expected root)"
        elif (( 8#$perms > 8#0600 )); then
            status="$STATUS_FAIL"
            evidence="sshd_config permissions ${perms} (expected 600 or stricter)"
        else
            evidence="sshd_config permissions ${perms}, owned by ${owner}:${group}"
        fi
    else
        evidence="sshd_config exists (permissions not verifiable in test mode)"
    fi

    record_result "$id" "$status" "$evidence"
}

check_5_2_2() {
    local id="5.2.2"
    local status="$STATUS_PASS"
    local evidence=""

    if ! file_exists "/etc/ssh/sshd_config"; then
        status="$STATUS_SKIP"
        evidence="sshd_config not found"
        record_result "$id" "$status" "$evidence"
        return
    fi

    local sshd_config="${SYSROOT}/etc/ssh/sshd_config"
    local found_directive="false"
    local directives=("AllowUsers" "AllowGroups" "DenyUsers" "DenyGroups")
    local found_list=""

    for directive in "${directives[@]}"; do
        if grep -Eiq "^\s*${directive}\s" "$sshd_config"; then
            found_directive="true"
            found_list="${found_list:+${found_list}, }${directive}"
        fi
    done

    if [[ "$found_directive" == "true" ]]; then
        evidence="SSH access limited via: ${found_list}"
    else
        status="$STATUS_FAIL"
        evidence="No SSH access restrictions configured (no AllowUsers/AllowGroups/DenyUsers/DenyGroups)"
    fi

    record_result "$id" "$status" "$evidence"
}

check_5_2_3() {
    local id="5.2.3"
    local status="$STATUS_PASS"
    local evidence=""

    local ssh_dir="${SYSROOT}/etc/ssh"
    local bad_keys=""
    local key_count=0

    if [[ ! -d "$ssh_dir" ]]; then
        status="$STATUS_SKIP"
        evidence="/etc/ssh directory not found"
        record_result "$id" "$status" "$evidence"
        return
    fi

    for key_file in "${ssh_dir}"/ssh_host_*_key; do
        [[ -f "$key_file" ]] || continue
        ((key_count++)) || true

        local file_stat
        if file_stat=$(run_cmd stat -c '%a %U' "$key_file"); then
            local perms owner
            perms=$(echo "$file_stat" | awk '{print $1}')
            owner=$(echo "$file_stat" | awk '{print $2}')

            if [[ "$owner" != "root" ]] || (( 8#$perms > 8#0600 )); then
                bad_keys="${bad_keys:+${bad_keys}, }${key_file##*/}(${perms}/${owner})"
            fi
        fi
    done

    if [[ "$key_count" -eq 0 ]]; then
        if [[ "$SYSROOT" != "/" ]]; then
            evidence="No SSH host private keys found (test mode)"
        else
            status="$STATUS_WARN"
            evidence="No SSH host private keys found"
        fi
    elif [[ -n "$bad_keys" ]]; then
        status="$STATUS_FAIL"
        evidence="Insecure SSH private key files: ${bad_keys}"
    else
        evidence="All ${key_count} SSH private key file(s) have correct permissions"
    fi

    record_result "$id" "$status" "$evidence"
}

check_5_2_4() {
    local id="5.2.4"
    local status="$STATUS_PASS"
    local evidence=""

    local value
    value=$(get_config_value "/etc/ssh/sshd_config" "LogLevel") || true

    if [[ -z "$value" ]]; then
        if ! file_exists "/etc/ssh/sshd_config"; then
            status="$STATUS_SKIP"
            evidence="sshd_config not found"
        else
            evidence="LogLevel not set (default is INFO)"
        fi
    elif [[ "${value^^}" == "INFO" || "${value^^}" == "VERBOSE" ]]; then
        evidence="SSH LogLevel = ${value}"
    else
        status="$STATUS_FAIL"
        evidence="SSH LogLevel = ${value} (expected INFO or VERBOSE)"
    fi

    record_result "$id" "$status" "$evidence"
}

_check_ssh_value() {
    local id="$1"
    local directive="$2"
    local expected="$3"
    local default_status="$4"
    local default_msg="$5"
    local pass_msg="$6"

    local status="$STATUS_PASS"
    local evidence=""

    local value
    value=$(get_config_value "/etc/ssh/sshd_config" "$directive") || true

    if [[ -z "$value" ]]; then
        if ! file_exists "/etc/ssh/sshd_config"; then
            status="$STATUS_SKIP"
            evidence="sshd_config not found"
        else
            status="$default_status"
            evidence="${directive} not set (${default_msg})"
        fi
    elif [[ "${value,,}" == "${expected,,}" ]]; then
        evidence="$pass_msg"
    else
        status="$STATUS_FAIL"
        evidence="${directive} = ${value} (expected ${expected})"
    fi

    record_result "$id" "$status" "$evidence"
}

check_5_2_5() {
    _check_ssh_value "5.2.5" "X11Forwarding" "no" "$STATUS_FAIL" \
        "default may allow forwarding" "SSH X11Forwarding is disabled"
}

_check_ssh_max_int() {
    local id="$1"
    local directive="$2"
    local threshold="$3"
    local default_msg="$4"

    local status="$STATUS_PASS"
    local evidence=""

    local value
    value=$(get_config_value "/etc/ssh/sshd_config" "$directive") || true

    if [[ -z "$value" ]]; then
        if ! file_exists "/etc/ssh/sshd_config"; then
            status="$STATUS_SKIP"
            evidence="sshd_config not found"
        else
            status="$STATUS_FAIL"
            evidence="${directive} not set (${default_msg})"
        fi
    elif (( value <= threshold )); then
        evidence="SSH ${directive} = ${value}"
    else
        status="$STATUS_FAIL"
        evidence="${directive} = ${value} (expected ${threshold} or less)"
    fi

    record_result "$id" "$status" "$evidence"
}

check_5_2_6() { _check_ssh_max_int "5.2.6" "MaxAuthTries" 4 "default is 6"; }

check_5_2_7() {
    _check_ssh_value "5.2.7" "IgnoreRhosts" "yes" "$STATUS_PASS" \
        "default is yes" "SSH IgnoreRhosts = yes"
}

check_5_2_8() {
    _check_ssh_value "5.2.8" "PermitRootLogin" "no" "$STATUS_FAIL" \
        "default allows root login" "SSH root login is disabled (PermitRootLogin = no)"
}

check_5_2_9() {
    _check_ssh_value "5.2.9" "PermitEmptyPasswords" "no" "$STATUS_PASS" \
        "default is no" "SSH empty passwords are disabled"
}

check_5_2_10() {
    _check_ssh_value "5.2.10" "PermitUserEnvironment" "no" "$STATUS_PASS" \
        "default is no" "SSH user environment processing is disabled"
}

_check_ssh_no_weak() {
    local id="$1"
    local directive="$2"
    local label="$3"
    shift 3
    local weak_items=("$@")

    local status="$STATUS_PASS"
    local evidence=""

    local value
    value=$(get_config_value "/etc/ssh/sshd_config" "$directive") || true

    if [[ -z "$value" ]]; then
        if ! file_exists "/etc/ssh/sshd_config"; then
            status="$STATUS_SKIP"
            evidence="sshd_config not found"
        else
            status="$STATUS_WARN"
            evidence="${directive} not explicitly configured (using defaults)"
        fi
        record_result "$id" "$status" "$evidence"
        return
    fi

    local found_weak=""
    for weak in "${weak_items[@]}"; do
        if echo ",$value," | grep -qi ",${weak},"; then
            found_weak="${found_weak:+${found_weak}, }${weak}"
        fi
    done

    if [[ -n "$found_weak" ]]; then
        status="$STATUS_FAIL"
        evidence="Weak SSH ${label} found: ${found_weak}"
    else
        evidence="Only strong SSH ${label} configured"
    fi

    record_result "$id" "$status" "$evidence"
}

check_5_2_11() {
    _check_ssh_no_weak "5.2.11" "Ciphers" "ciphers" \
        "3des-cbc" "aes128-cbc" "aes192-cbc" "aes256-cbc" \
        "blowfish-cbc" "cast128-cbc" "arcfour" "arcfour128" "arcfour256"
}

check_5_2_12() {
    _check_ssh_no_weak "5.2.12" "MACs" "MACs" \
        "hmac-md5" "hmac-md5-96" "hmac-md5-etm@openssh.com" \
        "hmac-md5-96-etm@openssh.com" "hmac-sha1-96" \
        "hmac-sha1-96-etm@openssh.com" "umac-64@openssh.com" \
        "umac-64-etm@openssh.com"
}

check_5_2_13() {
    _check_ssh_no_weak "5.2.13" "KexAlgorithms" "key exchange algorithms" \
        "diffie-hellman-group1-sha1" "diffie-hellman-group14-sha1" \
        "diffie-hellman-group-exchange-sha1"
}

check_5_2_14() { _check_ssh_max_int "5.2.14" "LoginGraceTime" 60 "default is 120"; }
