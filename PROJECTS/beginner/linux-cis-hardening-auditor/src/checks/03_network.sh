#!/usr/bin/env bash
# ©AngelaMos | 2026
# 03_network.sh

check_3_1_1() {
    local id="3.1.1"
    local status="$STATUS_PASS"
    local evidence=""

    local value
    value=$(get_sysctl "net.ipv4.ip_forward") || true

    if [[ -z "$value" ]]; then
        status="$STATUS_SKIP"
        evidence="Unable to read net.ipv4.ip_forward"
    elif [[ "$value" != "0" ]]; then
        status="$STATUS_FAIL"
        evidence="net.ipv4.ip_forward = ${value} (expected 0)"
    else
        evidence="IP forwarding is disabled (net.ipv4.ip_forward = 0)"
    fi

    record_result "$id" "$status" "$evidence"
}

check_3_1_2() {
    local id="3.1.2"
    local status="$STATUS_PASS"
    local evidence=""

    local val_all val_default
    val_all=$(get_sysctl "net.ipv4.conf.all.send_redirects") || true
    val_default=$(get_sysctl "net.ipv4.conf.default.send_redirects") || true

    if [[ -z "$val_all" && -z "$val_default" ]]; then
        status="$STATUS_SKIP"
        evidence="Unable to read send_redirects sysctl values"
    elif [[ "$val_all" != "0" || "$val_default" != "0" ]]; then
        status="$STATUS_FAIL"
        evidence="send_redirects: all=${val_all:-unset} default=${val_default:-unset} (expected 0)"
    else
        evidence="Packet redirect sending disabled (all=0, default=0)"
    fi

    record_result "$id" "$status" "$evidence"
}

check_3_1_3() {
    local id="3.1.3"
    local status="$STATUS_PASS"
    local evidence=""

    local val_all val_default
    val_all=$(get_sysctl "net.ipv4.conf.all.accept_source_route") || true
    val_default=$(get_sysctl "net.ipv4.conf.default.accept_source_route") || true

    if [[ -z "$val_all" && -z "$val_default" ]]; then
        status="$STATUS_SKIP"
        evidence="Unable to read accept_source_route sysctl values"
    elif [[ "$val_all" != "0" || "$val_default" != "0" ]]; then
        status="$STATUS_FAIL"
        evidence="accept_source_route: all=${val_all:-unset} default=${val_default:-unset} (expected 0)"
    else
        evidence="Source routed packets not accepted (all=0, default=0)"
    fi

    record_result "$id" "$status" "$evidence"
}

check_3_1_4() {
    local id="3.1.4"
    local status="$STATUS_PASS"
    local evidence=""

    local val_all val_default
    val_all=$(get_sysctl "net.ipv4.conf.all.accept_redirects") || true
    val_default=$(get_sysctl "net.ipv4.conf.default.accept_redirects") || true

    if [[ -z "$val_all" && -z "$val_default" ]]; then
        status="$STATUS_SKIP"
        evidence="Unable to read accept_redirects sysctl values"
    elif [[ "$val_all" != "0" || "$val_default" != "0" ]]; then
        status="$STATUS_FAIL"
        evidence="accept_redirects: all=${val_all:-unset} default=${val_default:-unset} (expected 0)"
    else
        evidence="ICMP redirects not accepted (all=0, default=0)"
    fi

    record_result "$id" "$status" "$evidence"
}

check_3_2_1() {
    local id="3.2.1"
    local status="$STATUS_PASS"
    local evidence=""

    local value
    value=$(get_sysctl "net.ipv4.conf.all.log_martians") || true

    if [[ -z "$value" ]]; then
        status="$STATUS_SKIP"
        evidence="Unable to read net.ipv4.conf.all.log_martians"
    elif [[ "$value" != "1" ]]; then
        status="$STATUS_FAIL"
        evidence="net.ipv4.conf.all.log_martians = ${value} (expected 1)"
    else
        evidence="Suspicious packets are logged (net.ipv4.conf.all.log_martians = 1)"
    fi

    record_result "$id" "$status" "$evidence"
}

check_3_2_2() {
    local id="3.2.2"
    local status="$STATUS_PASS"
    local evidence=""

    local value
    value=$(get_sysctl "net.ipv4.icmp_echo_ignore_broadcasts") || true

    if [[ -z "$value" ]]; then
        status="$STATUS_SKIP"
        evidence="Unable to read net.ipv4.icmp_echo_ignore_broadcasts"
    elif [[ "$value" != "1" ]]; then
        status="$STATUS_FAIL"
        evidence="net.ipv4.icmp_echo_ignore_broadcasts = ${value} (expected 1)"
    else
        evidence="Broadcast ICMP requests ignored (net.ipv4.icmp_echo_ignore_broadcasts = 1)"
    fi

    record_result "$id" "$status" "$evidence"
}

check_3_2_3() {
    local id="3.2.3"
    local status="$STATUS_PASS"
    local evidence=""

    local value
    value=$(get_sysctl "net.ipv4.icmp_ignore_bogus_error_responses") || true

    if [[ -z "$value" ]]; then
        status="$STATUS_SKIP"
        evidence="Unable to read net.ipv4.icmp_ignore_bogus_error_responses"
    elif [[ "$value" != "1" ]]; then
        status="$STATUS_FAIL"
        evidence="net.ipv4.icmp_ignore_bogus_error_responses = ${value} (expected 1)"
    else
        evidence="Bogus ICMP responses ignored (net.ipv4.icmp_ignore_bogus_error_responses = 1)"
    fi

    record_result "$id" "$status" "$evidence"
}

check_3_2_4() {
    local id="3.2.4"
    local status="$STATUS_PASS"
    local evidence=""

    local value
    value=$(get_sysctl "net.ipv4.conf.all.rp_filter") || true

    if [[ -z "$value" ]]; then
        status="$STATUS_SKIP"
        evidence="Unable to read net.ipv4.conf.all.rp_filter"
    elif [[ "$value" != "1" ]]; then
        status="$STATUS_FAIL"
        evidence="net.ipv4.conf.all.rp_filter = ${value} (expected 1)"
    else
        evidence="Reverse Path Filtering enabled (net.ipv4.conf.all.rp_filter = 1)"
    fi

    record_result "$id" "$status" "$evidence"
}

check_3_2_5() {
    local id="3.2.5"
    local status="$STATUS_PASS"
    local evidence=""

    local value
    value=$(get_sysctl "net.ipv4.tcp_syncookies") || true

    if [[ -z "$value" ]]; then
        status="$STATUS_SKIP"
        evidence="Unable to read net.ipv4.tcp_syncookies"
    elif [[ "$value" != "1" ]]; then
        status="$STATUS_FAIL"
        evidence="net.ipv4.tcp_syncookies = ${value} (expected 1)"
    else
        evidence="TCP SYN Cookies enabled (net.ipv4.tcp_syncookies = 1)"
    fi

    record_result "$id" "$status" "$evidence"
}

check_3_2_6() {
    local id="3.2.6"
    local status="$STATUS_PASS"
    local evidence=""

    local value
    value=$(get_sysctl "net.ipv6.conf.all.accept_ra") || true

    if [[ -z "$value" ]]; then
        status="$STATUS_SKIP"
        evidence="Unable to read net.ipv6.conf.all.accept_ra"
    elif [[ "$value" != "0" ]]; then
        status="$STATUS_FAIL"
        evidence="net.ipv6.conf.all.accept_ra = ${value} (expected 0)"
    else
        evidence="IPv6 router advertisements not accepted (net.ipv6.conf.all.accept_ra = 0)"
    fi

    record_result "$id" "$status" "$evidence"
}

check_3_3_1() {
    local id="3.3.1"
    local status="$STATUS_PASS"
    local evidence=""

    if package_is_installed "iptables"; then
        evidence="iptables package is installed"
    elif file_exists "/usr/sbin/iptables"; then
        evidence="iptables binary found at /usr/sbin/iptables"
    else
        status="$STATUS_FAIL"
        evidence="iptables is not installed"
    fi

    record_result "$id" "$status" "$evidence"
}

check_3_3_2() {
    local id="3.3.2"
    local status="$STATUS_PASS"
    local evidence=""

    local policy=""
    local iptables_output
    if iptables_output=$(run_cmd iptables -L INPUT -n 2>/dev/null); then
        policy=$(echo "$iptables_output" | head -1 | grep -oP 'policy \K\w+') || true
    fi

    if [[ -z "$policy" ]]; then
        local rules_file="${SYSROOT}/etc/iptables/rules.v4"
        if [[ -f "$rules_file" ]]; then
            policy=$(grep -E '^\s*:INPUT\s' "$rules_file" | awk '{print $2}') || true
        fi
    fi

    if [[ -z "$policy" ]]; then
        status="$STATUS_SKIP"
        evidence="Unable to determine INPUT chain policy"
    elif [[ "$policy" == "DROP" || "$policy" == "REJECT" ]]; then
        evidence="INPUT chain default policy is ${policy}"
    else
        status="$STATUS_FAIL"
        evidence="INPUT chain default policy is ${policy} (expected DROP or REJECT)"
    fi

    record_result "$id" "$status" "$evidence"
}

check_3_3_3() {
    local id="3.3.3"
    local status="$STATUS_PASS"
    local evidence=""

    local policy=""
    local iptables_output
    if iptables_output=$(run_cmd iptables -L FORWARD -n 2>/dev/null); then
        policy=$(echo "$iptables_output" | head -1 | grep -oP 'policy \K\w+') || true
    fi

    if [[ -z "$policy" ]]; then
        local rules_file="${SYSROOT}/etc/iptables/rules.v4"
        if [[ -f "$rules_file" ]]; then
            policy=$(grep -E '^\s*:FORWARD\s' "$rules_file" | awk '{print $2}') || true
        fi
    fi

    if [[ -z "$policy" ]]; then
        status="$STATUS_SKIP"
        evidence="Unable to determine FORWARD chain policy"
    elif [[ "$policy" == "DROP" || "$policy" == "REJECT" ]]; then
        evidence="FORWARD chain default policy is ${policy}"
    else
        status="$STATUS_FAIL"
        evidence="FORWARD chain default policy is ${policy} (expected DROP or REJECT)"
    fi

    record_result "$id" "$status" "$evidence"
}

check_3_3_4() {
    local id="3.3.4"
    local status="$STATUS_PASS"
    local evidence=""

    local policy=""
    local iptables_output
    if iptables_output=$(run_cmd iptables -L OUTPUT -n 2>/dev/null); then
        policy=$(echo "$iptables_output" | head -1 | grep -oP 'policy \K\w+') || true
    fi

    if [[ -z "$policy" ]]; then
        local rules_file="${SYSROOT}/etc/iptables/rules.v4"
        if [[ -f "$rules_file" ]]; then
            policy=$(grep -E '^\s*:OUTPUT\s' "$rules_file" | awk '{print $2}') || true
        fi
    fi

    if [[ -z "$policy" ]]; then
        status="$STATUS_SKIP"
        evidence="Unable to determine OUTPUT chain policy"
    elif [[ "$policy" == "DROP" || "$policy" == "REJECT" ]]; then
        evidence="OUTPUT chain default policy is ${policy}"
    else
        status="$STATUS_FAIL"
        evidence="OUTPUT chain default policy is ${policy} (expected DROP or REJECT)"
    fi

    record_result "$id" "$status" "$evidence"
}

check_3_3_5() {
    local id="3.3.5"
    local status="$STATUS_PASS"
    local evidence=""

    if [[ "$SYSROOT" != "/" ]]; then
        status="$STATUS_SKIP"
        evidence="Firewall rule coverage requires live system (test mode)"
        record_result "$id" "$status" "$evidence"
        return
    fi

    local open_ports
    open_ports=$(run_cmd ss -tlnp 2>/dev/null | awk 'NR>1 {print $4}' | grep -oP '\d+$' | sort -un) || true

    if [[ -z "$open_ports" ]]; then
        evidence="No open TCP ports detected"
        record_result "$id" "$status" "$evidence"
        return
    fi

    local iptables_rules
    iptables_rules=$(run_cmd iptables -L INPUT -n 2>/dev/null) || true

    if [[ -z "$iptables_rules" ]]; then
        status="$STATUS_SKIP"
        evidence="Unable to read iptables INPUT rules"
        record_result "$id" "$status" "$evidence"
        return
    fi

    local uncovered=""
    local port
    for port in $open_ports; do
        if ! echo "$iptables_rules" | grep -q "dpt:${port}\b"; then
            if [[ -n "$uncovered" ]]; then
                uncovered="${uncovered}, ${port}"
            else
                uncovered="${port}"
            fi
        fi
    done

    if [[ -n "$uncovered" ]]; then
        status="$STATUS_FAIL"
        evidence="Open ports without firewall rules: ${uncovered}"
    else
        evidence="All open ports have matching firewall rules"
    fi

    record_result "$id" "$status" "$evidence"
}

check_3_4_1() {
    local id="3.4.1"
    local status="$STATUS_PASS"
    local evidence=""

    if [[ "$SYSROOT" != "/" ]]; then
        status="$STATUS_SKIP"
        evidence="Wireless interface check requires live system (test mode)"
        record_result "$id" "$status" "$evidence"
        return
    fi

    local wireless_ifaces
    wireless_ifaces=$(run_cmd ip link show 2>/dev/null | grep -oP '^\d+:\s+\Kwlan\S+') || true

    if [[ -n "$wireless_ifaces" ]]; then
        local all_blocked="true"
        if run_cmd rfkill list wifi 2>/dev/null | grep -q "Soft blocked: yes"; then
            evidence="Wireless interfaces found but blocked via rfkill"
        else
            all_blocked="false"
        fi

        if [[ "$all_blocked" == "false" ]]; then
            status="$STATUS_FAIL"
            evidence="Active wireless interfaces found: ${wireless_ifaces}"
        fi
    else
        evidence="No wireless interfaces detected"
    fi

    record_result "$id" "$status" "$evidence"
}

_check_protocol_module_disabled() {
    local id="$1"
    local module="$2"

    local status="$STATUS_PASS"
    local evidence=""
    local found_disabled="false"

    for conf in "${SYSROOT}"/etc/modprobe.d/*.conf; do
        [[ -f "$conf" ]] || continue
        if grep -q "install ${module} /bin/true\|install ${module} /bin/false\|blacklist ${module}" "$conf"; then
            found_disabled="true"
            evidence="${module} disabled via ${conf}"
            break
        fi
    done

    if [[ "$found_disabled" == "false" ]]; then
        if run_cmd lsmod | grep -q "^${module} "; then
            status="$STATUS_FAIL"
            evidence="${module} module is loaded"
        else
            status="$STATUS_FAIL"
            evidence="No modprobe config found disabling ${module}"
        fi
    fi

    record_result "$id" "$status" "$evidence"
}

check_3_4_2() { _check_protocol_module_disabled "3.4.2" "dccp"; }
check_3_4_3() { _check_protocol_module_disabled "3.4.3" "sctp"; }
check_3_4_4() { _check_protocol_module_disabled "3.4.4" "rds"; }
check_3_4_5() { _check_protocol_module_disabled "3.4.5" "tipc"; }
