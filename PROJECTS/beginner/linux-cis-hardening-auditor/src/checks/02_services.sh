#!/usr/bin/env bash
# ©AngelaMos | 2026
# 02_services.sh

check_2_1_1() {
    local id="2.1.1"
    local status="$STATUS_PASS"
    local evidence=""
    local pkg="xinetd"

    if package_is_installed "$pkg"; then
        status="$STATUS_FAIL"
        evidence="${pkg} is installed"
    elif file_exists "/etc/xinetd.conf" || file_exists "/etc/xinetd.d"; then
        status="$STATUS_FAIL"
        evidence="${pkg} configuration found at /etc/xinetd.conf"
    else
        evidence="${pkg} is not installed"
    fi

    record_result "$id" "$status" "$evidence"
}

check_2_1_2() {
    local id="2.1.2"
    local status="$STATUS_PASS"
    local evidence=""
    local pkg="openbsd-inetd"

    if package_is_installed "$pkg"; then
        status="$STATUS_FAIL"
        evidence="${pkg} is installed"
    elif file_exists "/etc/inetd.conf"; then
        status="$STATUS_FAIL"
        evidence="${pkg} configuration found at /etc/inetd.conf"
    else
        evidence="${pkg} is not installed"
    fi

    record_result "$id" "$status" "$evidence"
}

check_2_2_1() {
    local id="2.2.1"
    local status="$STATUS_PASS"
    local evidence=""
    local pkg="xserver-xorg"

    if package_is_installed "$pkg"; then
        status="$STATUS_FAIL"
        evidence="${pkg} is installed"
    elif file_exists "/usr/bin/X" || file_exists "/usr/bin/Xorg"; then
        status="$STATUS_FAIL"
        evidence="X Window System binary found"
    else
        evidence="${pkg} is not installed"
    fi

    record_result "$id" "$status" "$evidence"
}

check_2_2_2() {
    local id="2.2.2"
    local status="$STATUS_PASS"
    local evidence=""
    local pkg="avahi-daemon"

    if package_is_installed "$pkg"; then
        status="$STATUS_FAIL"
        evidence="${pkg} is installed"
    elif file_exists "/usr/sbin/avahi-daemon" || file_exists "/etc/avahi/avahi-daemon.conf"; then
        status="$STATUS_FAIL"
        evidence="${pkg} binary or configuration found"
    else
        evidence="${pkg} is not installed"
    fi

    record_result "$id" "$status" "$evidence"
}

check_2_2_3() {
    local id="2.2.3"
    local status="$STATUS_PASS"
    local evidence=""
    local pkg="cups"

    if package_is_installed "$pkg"; then
        status="$STATUS_FAIL"
        evidence="${pkg} is installed"
    elif file_exists "/usr/sbin/cupsd" || file_exists "/etc/cups/cupsd.conf"; then
        status="$STATUS_FAIL"
        evidence="${pkg} binary or configuration found"
    else
        evidence="${pkg} is not installed"
    fi

    record_result "$id" "$status" "$evidence"
}

check_2_2_4() {
    local id="2.2.4"
    local status="$STATUS_PASS"
    local evidence=""
    local pkg="isc-dhcp-server"

    if package_is_installed "$pkg"; then
        status="$STATUS_FAIL"
        evidence="${pkg} is installed"
    elif file_exists "/usr/sbin/dhcpd" || file_exists "/etc/dhcp/dhcpd.conf"; then
        status="$STATUS_FAIL"
        evidence="${pkg} binary or configuration found"
    else
        evidence="${pkg} is not installed"
    fi

    record_result "$id" "$status" "$evidence"
}

check_2_2_5() {
    local id="2.2.5"
    local status="$STATUS_PASS"
    local evidence=""
    local pkg="slapd"

    if package_is_installed "$pkg"; then
        status="$STATUS_FAIL"
        evidence="${pkg} is installed"
    elif file_exists "/usr/sbin/slapd" || file_exists "/etc/ldap/slapd.d"; then
        status="$STATUS_FAIL"
        evidence="${pkg} binary or configuration found"
    else
        evidence="${pkg} is not installed"
    fi

    record_result "$id" "$status" "$evidence"
}

check_2_2_6() {
    local id="2.2.6"
    local status="$STATUS_PASS"
    local evidence=""
    local pkg="nfs-kernel-server"

    if package_is_installed "$pkg"; then
        status="$STATUS_FAIL"
        evidence="${pkg} is installed"
    elif file_exists "/usr/sbin/rpc.nfsd" || file_exists "/etc/exports"; then
        status="$STATUS_FAIL"
        evidence="${pkg} binary or configuration found"
    else
        evidence="${pkg} is not installed"
    fi

    record_result "$id" "$status" "$evidence"
}

check_2_2_7() {
    local id="2.2.7"
    local status="$STATUS_PASS"
    local evidence=""
    local pkg="bind9"

    if package_is_installed "$pkg"; then
        status="$STATUS_FAIL"
        evidence="${pkg} is installed"
    elif file_exists "/usr/sbin/named" || file_exists "/etc/bind/named.conf"; then
        status="$STATUS_FAIL"
        evidence="${pkg} binary or configuration found"
    else
        evidence="${pkg} is not installed"
    fi

    record_result "$id" "$status" "$evidence"
}

check_2_2_8() {
    local id="2.2.8"
    local status="$STATUS_PASS"
    local evidence=""
    local pkg="vsftpd"

    if package_is_installed "$pkg"; then
        status="$STATUS_FAIL"
        evidence="${pkg} is installed"
    elif file_exists "/usr/sbin/vsftpd" || file_exists "/etc/vsftpd.conf"; then
        status="$STATUS_FAIL"
        evidence="${pkg} binary or configuration found"
    else
        evidence="${pkg} is not installed"
    fi

    record_result "$id" "$status" "$evidence"
}

check_2_2_9() {
    local id="2.2.9"
    local status="$STATUS_PASS"
    local evidence=""
    local installed=""

    if package_is_installed "apache2"; then
        installed="apache2"
    elif package_is_installed "nginx"; then
        installed="nginx"
    elif file_exists "/usr/sbin/apache2" || file_exists "/etc/apache2/apache2.conf"; then
        installed="apache2"
    elif file_exists "/usr/sbin/nginx" || file_exists "/etc/nginx/nginx.conf"; then
        installed="nginx"
    fi

    if [[ -n "$installed" ]]; then
        status="$STATUS_FAIL"
        evidence="${installed} is installed"
    else
        evidence="No HTTP server is installed"
    fi

    record_result "$id" "$status" "$evidence"
}

check_2_2_10() {
    local id="2.2.10"
    local status="$STATUS_PASS"
    local evidence=""
    local installed=""

    if package_is_installed "dovecot-imapd"; then
        installed="dovecot-imapd"
    fi

    if package_is_installed "dovecot-pop3d"; then
        if [[ -n "$installed" ]]; then
            installed="${installed} and dovecot-pop3d"
        else
            installed="dovecot-pop3d"
        fi
    fi

    if [[ -z "$installed" ]]; then
        if file_exists "/usr/sbin/dovecot" || file_exists "/etc/dovecot/dovecot.conf"; then
            installed="dovecot"
        fi
    fi

    if [[ -n "$installed" ]]; then
        status="$STATUS_FAIL"
        evidence="${installed} is installed"
    else
        evidence="No IMAP or POP3 server is installed"
    fi

    record_result "$id" "$status" "$evidence"
}

check_2_2_11() {
    local id="2.2.11"
    local status="$STATUS_PASS"
    local evidence=""
    local pkg="samba"

    if package_is_installed "$pkg"; then
        status="$STATUS_FAIL"
        evidence="${pkg} is installed"
    elif file_exists "/usr/sbin/smbd" || file_exists "/etc/samba/smb.conf"; then
        status="$STATUS_FAIL"
        evidence="${pkg} binary or configuration found"
    else
        evidence="${pkg} is not installed"
    fi

    record_result "$id" "$status" "$evidence"
}

check_2_2_12() {
    local id="2.2.12"
    local status="$STATUS_PASS"
    local evidence=""
    local pkg="squid"

    if package_is_installed "$pkg"; then
        status="$STATUS_FAIL"
        evidence="${pkg} is installed"
    elif file_exists "/usr/sbin/squid" || file_exists "/etc/squid/squid.conf"; then
        status="$STATUS_FAIL"
        evidence="${pkg} binary or configuration found"
    else
        evidence="${pkg} is not installed"
    fi

    record_result "$id" "$status" "$evidence"
}

check_2_2_13() {
    local id="2.2.13"
    local status="$STATUS_PASS"
    local evidence=""
    local pkg="snmpd"

    if package_is_installed "$pkg"; then
        status="$STATUS_FAIL"
        evidence="${pkg} is installed"
    elif file_exists "/usr/sbin/snmpd" || file_exists "/etc/snmp/snmpd.conf"; then
        status="$STATUS_FAIL"
        evidence="${pkg} binary or configuration found"
    else
        evidence="${pkg} is not installed"
    fi

    record_result "$id" "$status" "$evidence"
}

check_2_2_14() {
    local id="2.2.14"
    local status="$STATUS_PASS"
    local evidence=""
    local pkg="nis"

    if package_is_installed "$pkg"; then
        status="$STATUS_FAIL"
        evidence="${pkg} is installed"
    elif file_exists "/usr/sbin/ypserv" || file_exists "/etc/yp.conf"; then
        status="$STATUS_FAIL"
        evidence="${pkg} binary or configuration found"
    else
        evidence="${pkg} is not installed"
    fi

    record_result "$id" "$status" "$evidence"
}

check_2_2_15() {
    local id="2.2.15"
    local status="$STATUS_PASS"
    local evidence=""

    local listening_external=""

    if run_cmd ss -lntp | grep -qE ':25\s' 2>/dev/null; then
        local listeners
        listeners=$(run_cmd ss -lntp | grep -E ':25\s' 2>/dev/null) || true

        if echo "$listeners" | grep -qvE '127\.0\.0\.1:25|::1:25|\[::1\]:25|\*:25'; then
            local bound_addrs
            bound_addrs=$(echo "$listeners" | awk '{print $4}')
            if echo "$bound_addrs" | grep -qvE '^127\.0\.0\.1:|^\[::1\]:|^::1:'; then
                listening_external="true"
            fi
        fi
    fi

    if [[ "$listening_external" == "true" ]]; then
        status="$STATUS_FAIL"
        evidence="MTA is listening on non-loopback interface on port 25"
        record_result "$id" "$status" "$evidence"
        return
    fi

    local main_cf
    main_cf=$(read_file "/etc/postfix/main.cf" 2>/dev/null) || true

    if [[ -n "$main_cf" ]]; then
        local inet_interfaces
        inet_interfaces=$(echo "$main_cf" | grep -Ei '^\s*inet_interfaces\s*=' | tail -1 | awk -F= '{print $2}' | tr -d ' ') || true

        if [[ -z "$inet_interfaces" ]]; then
            status="$STATUS_FAIL"
            evidence="Postfix inet_interfaces not configured (defaults to all)"
        elif [[ "$inet_interfaces" == "loopback-only" || "$inet_interfaces" == "localhost" || "$inet_interfaces" == "127.0.0.1" ]]; then
            evidence="Postfix configured for local-only (inet_interfaces = ${inet_interfaces})"
        else
            status="$STATUS_FAIL"
            evidence="Postfix inet_interfaces = ${inet_interfaces} (expected loopback-only or localhost)"
        fi

        record_result "$id" "$status" "$evidence"
        return
    fi

    local exim_conf
    exim_conf=$(read_file "/etc/exim4/update-exim4.conf.conf" 2>/dev/null) || true

    if [[ -n "$exim_conf" ]]; then
        local listen_addrs
        listen_addrs=$(echo "$exim_conf" | grep -Ei '^\s*dc_local_interfaces' | tail -1 | awk -F= "'{print \$2}'" | tr -d "' ") || true

        if [[ -z "$listen_addrs" || "$listen_addrs" == "127.0.0.1;::1" || "$listen_addrs" == "127.0.0.1" ]]; then
            evidence="Exim configured for local-only (dc_local_interfaces = ${listen_addrs:-127.0.0.1;::1})"
        else
            status="$STATUS_FAIL"
            evidence="Exim dc_local_interfaces = ${listen_addrs} (expected 127.0.0.1;::1)"
        fi

        record_result "$id" "$status" "$evidence"
        return
    fi

    if file_exists "/usr/sbin/sendmail" || file_exists "/usr/lib/sendmail"; then
        status="$STATUS_WARN"
        evidence="Sendmail detected but configuration not checked in test mode"
        record_result "$id" "$status" "$evidence"
        return
    fi

    evidence="No MTA detected or MTA not listening on port 25"
    record_result "$id" "$status" "$evidence"
}

check_2_2_16() {
    local id="2.2.16"
    local status="$STATUS_PASS"
    local evidence=""
    local pkg="rsync"

    if package_is_installed "$pkg"; then
        status="$STATUS_FAIL"
        evidence="${pkg} is installed"
    elif service_is_enabled "rsync"; then
        status="$STATUS_FAIL"
        evidence="rsync service is enabled"
    elif file_exists "/usr/bin/rsync" && file_exists "/etc/rsyncd.conf"; then
        status="$STATUS_FAIL"
        evidence="${pkg} binary and daemon configuration found"
    else
        evidence="${pkg} is not installed"
    fi

    record_result "$id" "$status" "$evidence"
}
