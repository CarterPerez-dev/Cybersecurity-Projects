#!/usr/bin/env bash
# ©AngelaMos | 2026
# 04_logging.sh

check_4_1_1() {
    local id="4.1.1"
    local status="$STATUS_PASS"
    local evidence=""

    if package_is_installed "auditd"; then
        evidence="auditd package is installed"
    elif file_exists "/usr/sbin/auditd"; then
        evidence="auditd binary found at /usr/sbin/auditd"
    else
        status="$STATUS_FAIL"
        evidence="auditd is not installed"
    fi

    record_result "$id" "$status" "$evidence"
}

check_4_1_2() {
    local id="4.1.2"
    local status="$STATUS_PASS"
    local evidence=""

    if service_is_enabled "auditd"; then
        evidence="auditd service is enabled"
    else
        local symlink="${SYSROOT}/etc/systemd/system/multi-user.target.wants/auditd.service"
        if [[ -L "$symlink" || -f "$symlink" ]]; then
            evidence="auditd enabled via systemd symlink"
        else
            status="$STATUS_FAIL"
            evidence="auditd service is not enabled"
        fi
    fi

    record_result "$id" "$status" "$evidence"
}

check_4_1_3() {
    local id="4.1.3"
    local status="$STATUS_PASS"
    local evidence=""

    local grub_default="${SYSROOT}/etc/default/grub"

    if [[ ! -f "$grub_default" ]]; then
        status="$STATUS_SKIP"
        evidence="/etc/default/grub not found"
        record_result "$id" "$status" "$evidence"
        return
    fi

    local cmdline
    cmdline=$(grep -E '^\s*GRUB_CMDLINE_LINUX=' "$grub_default" | tail -1) || true

    if [[ -z "$cmdline" ]]; then
        status="$STATUS_FAIL"
        evidence="GRUB_CMDLINE_LINUX not configured"
    elif echo "$cmdline" | grep -q 'audit=1'; then
        evidence="Pre-auditd auditing enabled (audit=1 in GRUB_CMDLINE_LINUX)"
    else
        status="$STATUS_FAIL"
        evidence="audit=1 not found in GRUB_CMDLINE_LINUX"
    fi

    record_result "$id" "$status" "$evidence"
}

check_4_1_4() {
    local id="4.1.4"
    local status="$STATUS_PASS"
    local evidence=""

    local grub_default="${SYSROOT}/etc/default/grub"

    if [[ ! -f "$grub_default" ]]; then
        status="$STATUS_SKIP"
        evidence="/etc/default/grub not found"
        record_result "$id" "$status" "$evidence"
        return
    fi

    local cmdline
    cmdline=$(grep -E '^\s*GRUB_CMDLINE_LINUX=' "$grub_default" | tail -1) || true

    if [[ -z "$cmdline" ]]; then
        status="$STATUS_FAIL"
        evidence="GRUB_CMDLINE_LINUX not configured"
    elif echo "$cmdline" | grep -qE 'audit_backlog_limit=[0-9]+'; then
        local limit
        limit=$(echo "$cmdline" | grep -oE 'audit_backlog_limit=[0-9]+' | cut -d= -f2)
        if (( limit >= 8192 )); then
            evidence="Audit backlog limit is sufficient (${limit})"
        else
            status="$STATUS_FAIL"
            evidence="Audit backlog limit is ${limit} (expected >= 8192)"
        fi
    else
        status="$STATUS_FAIL"
        evidence="audit_backlog_limit not found in GRUB_CMDLINE_LINUX"
    fi

    record_result "$id" "$status" "$evidence"
}

_check_audit_rules() {
    local id="$1"
    shift
    local description="$1"
    shift
    local search_patterns=("$@")

    local status="$STATUS_PASS"
    local evidence=""
    local rules_dir="${SYSROOT}/etc/audit/rules.d"
    local audit_rules="${SYSROOT}/etc/audit/audit.rules"
    local missing=()

    for pattern in "${search_patterns[@]}"; do
        local found="false"
        if [[ -d "$rules_dir" ]]; then
            for rule_file in "$rules_dir"/*.rules; do
                [[ -f "$rule_file" ]] || continue
                if grep -q "$pattern" "$rule_file"; then
                    found="true"
                    break
                fi
            done
        fi
        if [[ "$found" == "false" && -f "$audit_rules" ]]; then
            if grep -q "$pattern" "$audit_rules"; then
                found="true"
            fi
        fi
        if [[ "$found" == "false" ]]; then
            missing+=("$pattern")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        status="$STATUS_FAIL"
        evidence="Missing audit rules for: ${missing[*]}"
    else
        evidence="${description} audit rules are configured"
    fi

    record_result "$id" "$status" "$evidence"
}

check_4_1_5() {
    _check_audit_rules "4.1.5" "Time change" \
        "adjtimex" "settimeofday" "clock_settime" "/etc/localtime"
}

check_4_1_6() {
    _check_audit_rules "4.1.6" "User/group change" \
        "/etc/group" "/etc/passwd" "/etc/gshadow" "/etc/shadow" "/etc/security/opasswd"
}

check_4_1_7() {
    _check_audit_rules "4.1.7" "Network environment" \
        "sethostname" "setdomainname" "/etc/issue" "/etc/hosts" "/etc/networks"
}

check_4_1_8() {
    local id="4.1.8"
    local status="$STATUS_PASS"
    local evidence=""
    local rules_dir="${SYSROOT}/etc/audit/rules.d"
    local audit_rules="${SYSROOT}/etc/audit/audit.rules"
    local found="false"

    local mac_patterns=("/etc/selinux/" "/etc/apparmor/")

    for pattern in "${mac_patterns[@]}"; do
        if [[ -d "$rules_dir" ]]; then
            for rule_file in "$rules_dir"/*.rules; do
                [[ -f "$rule_file" ]] || continue
                if grep -q "$pattern" "$rule_file"; then
                    found="true"
                    break 2
                fi
            done
        fi
        if [[ "$found" == "false" && -f "$audit_rules" ]]; then
            if grep -q "$pattern" "$audit_rules"; then
                found="true"
                break
            fi
        fi
    done

    if [[ "$found" == "false" ]]; then
        status="$STATUS_FAIL"
        evidence="Missing audit rules for MAC policy changes"
    else
        evidence="MAC policy change audit rules are configured"
    fi

    record_result "$id" "$status" "$evidence"
}

check_4_1_9() {
    _check_audit_rules "4.1.9" "Login/logout event" \
        "/var/log/lastlog" "/var/run/faillock/"
}

check_4_1_10() {
    _check_audit_rules "4.1.10" "Session initiation" \
        "/var/run/utmp" "/var/log/wtmp" "/var/log/btmp"
}

check_4_1_11() {
    _check_audit_rules "4.1.11" "DAC permission change" \
        "chmod" "chown" "fchmod" "fchown" "lchown" "setxattr"
}

check_4_1_12() {
    local id="4.1.12"
    local status="$STATUS_PASS"
    local evidence=""
    local rules_dir="${SYSROOT}/etc/audit/rules.d"
    local audit_rules="${SYSROOT}/etc/audit/audit.rules"
    local found_eacces="false"
    local found_eperm="false"

    if [[ -d "$rules_dir" ]]; then
        for rule_file in "$rules_dir"/*.rules; do
            [[ -f "$rule_file" ]] || continue
            grep -q "EACCES" "$rule_file" && found_eacces="true"
            grep -q "EPERM" "$rule_file" && found_eperm="true"
        done
    fi
    if [[ -f "$audit_rules" ]]; then
        grep -q "EACCES" "$audit_rules" && found_eacces="true"
        grep -q "EPERM" "$audit_rules" && found_eperm="true"
    fi

    if [[ "$found_eacces" == "false" || "$found_eperm" == "false" ]]; then
        local missing_items=""
        [[ "$found_eacces" == "false" ]] && missing_items="EACCES"
        [[ "$found_eperm" == "false" ]] && missing_items="${missing_items:+${missing_items} }EPERM"
        status="$STATUS_FAIL"
        evidence="Missing audit rules for unauthorized access: ${missing_items}"
    else
        evidence="Unauthorized file access audit rules are configured"
    fi

    record_result "$id" "$status" "$evidence"
}

check_4_1_13() {
    _check_audit_rules "4.1.13" "File system mount" \
        "mount"
}

check_4_1_14() {
    _check_audit_rules "4.1.14" "File deletion" \
        "unlink" "rename"
}

check_4_2_1() {
    local id="4.2.1"
    local status="$STATUS_PASS"
    local evidence=""

    if package_is_installed "rsyslog"; then
        evidence="rsyslog package is installed"
    elif file_exists "/usr/sbin/rsyslogd"; then
        evidence="rsyslogd binary found at /usr/sbin/rsyslogd"
    else
        status="$STATUS_FAIL"
        evidence="rsyslog is not installed"
    fi

    record_result "$id" "$status" "$evidence"
}

check_4_2_2() {
    local id="4.2.2"
    local status="$STATUS_PASS"
    local evidence=""

    if service_is_enabled "rsyslog"; then
        evidence="rsyslog service is enabled"
    else
        local symlink="${SYSROOT}/etc/systemd/system/multi-user.target.wants/rsyslog.service"
        if [[ -L "$symlink" || -f "$symlink" ]]; then
            evidence="rsyslog enabled via systemd symlink"
        else
            status="$STATUS_FAIL"
            evidence="rsyslog service is not enabled"
        fi
    fi

    record_result "$id" "$status" "$evidence"
}

check_4_2_3() {
    local id="4.2.3"
    local status="$STATUS_PASS"
    local evidence=""

    local rsyslog_conf="${SYSROOT}/etc/rsyslog.conf"

    if [[ ! -f "$rsyslog_conf" ]]; then
        status="$STATUS_SKIP"
        evidence="/etc/rsyslog.conf not found"
        record_result "$id" "$status" "$evidence"
        return
    fi

    local file_mode
    file_mode=$(grep -E '^\s*\$FileCreateMode' "$rsyslog_conf" | tail -1 | awk '{print $2}') || true

    if [[ -z "$file_mode" ]]; then
        status="$STATUS_FAIL"
        evidence="\$FileCreateMode not set in rsyslog.conf"
    elif (( 8#$file_mode <= 8#0640 )); then
        evidence="rsyslog FileCreateMode is ${file_mode}"
    else
        status="$STATUS_FAIL"
        evidence="rsyslog FileCreateMode is ${file_mode} (expected 0640 or stricter)"
    fi

    record_result "$id" "$status" "$evidence"
}

check_4_2_4() {
    local id="4.2.4"
    local status="$STATUS_PASS"
    local evidence=""

    local rsyslog_conf="${SYSROOT}/etc/rsyslog.conf"

    if [[ ! -f "$rsyslog_conf" ]]; then
        status="$STATUS_SKIP"
        evidence="/etc/rsyslog.conf not found"
        record_result "$id" "$status" "$evidence"
        return
    fi

    local rule_count
    rule_count=$(grep -cE '^\s*[a-z]+\.\*\s+/|^\s*\*\.\*\s+/' "$rsyslog_conf") || true

    if [[ "$rule_count" -gt 0 ]]; then
        evidence="Found ${rule_count} logging rule(s) in rsyslog.conf"
    else
        local include_count
        include_count=$(grep -cE '^\s*\$IncludeConfig|^\s*include\(' "$rsyslog_conf") || true

        if [[ "$include_count" -gt 0 ]]; then
            evidence="Logging configured via included config files (${include_count} include directive(s))"
        else
            status="$STATUS_FAIL"
            evidence="No logging rules found in rsyslog.conf"
        fi
    fi

    record_result "$id" "$status" "$evidence"
}
