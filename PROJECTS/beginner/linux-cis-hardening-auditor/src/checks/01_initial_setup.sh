#!/usr/bin/env bash
# ©AngelaMos | 2026
# 01_initial_setup.sh

_check_module_disabled() {
    local id="$1"
    local module="$2"

    local status="$STATUS_PASS"
    local evidence=""
    local modprobe_conf="${SYSROOT}/etc/modprobe.d/${module}.conf"

    if run_cmd lsmod | grep -q "^${module} "; then
        status="$STATUS_FAIL"
        evidence="${module} module is currently loaded"
    elif [[ -f "$modprobe_conf" ]] && grep -q "install ${module} /bin/true\|install ${module} /bin/false" "$modprobe_conf"; then
        evidence="${module} disabled via ${modprobe_conf}"
    elif run_cmd modprobe -n -v "$module" 2>/dev/null | grep -q "install /bin/true\|install /bin/false"; then
        evidence="${module} disabled via modprobe config"
    else
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
            if [[ "$SYSROOT" != "/" ]]; then
                status="$STATUS_FAIL"
                evidence="No modprobe config found disabling ${module}"
            else
                status="$STATUS_FAIL"
                evidence="${module} is not disabled"
            fi
        fi
    fi

    record_result "$id" "$status" "$evidence"
}

check_1_1_1() { _check_module_disabled "1.1.1" "cramfs"; }
check_1_1_2() { _check_module_disabled "1.1.2" "freevxfs"; }
check_1_1_3() { _check_module_disabled "1.1.3" "jffs2"; }
check_1_1_4() { _check_module_disabled "1.1.4" "hfs"; }
check_1_1_5() { _check_module_disabled "1.1.5" "hfsplus"; }
check_1_1_6() { _check_module_disabled "1.1.6" "squashfs"; }
check_1_1_7() { _check_module_disabled "1.1.7" "udf"; }
check_1_1_8() { _check_module_disabled "1.1.8" "vfat"; }

check_1_2_1() {
    local id="1.2.1"
    local status="$STATUS_PASS"
    local evidence=""

    local fstab_content
    fstab_content=$(read_file "/etc/fstab" 2>/dev/null) || true

    if [[ -n "$fstab_content" ]]; then
        local tmp_line
        tmp_line=$(echo "$fstab_content" | grep -E '\s/tmp\s' || true)
        if [[ -n "$tmp_line" ]]; then
            evidence="/tmp is a separate partition in fstab"
        else
            status="$STATUS_FAIL"
            evidence="/tmp is not configured as a separate partition in fstab"
        fi
    elif run_cmd findmnt -n /tmp > /dev/null 2>&1; then
        evidence="/tmp is a separate partition (findmnt)"
    else
        status="$STATUS_FAIL"
        evidence="/tmp is not configured as a separate partition"
    fi

    record_result "$id" "$status" "$evidence"
}

_check_tmp_mount_option() {
    local id="$1"
    local option="$2"

    local status="$STATUS_PASS"
    local evidence=""
    local fstab_content
    fstab_content=$(read_file "/etc/fstab" 2>/dev/null) || true
    local options=""

    if [[ -n "$fstab_content" ]]; then
        local tmp_line
        tmp_line=$(echo "$fstab_content" | grep -E '\s/tmp\s' || true)
        if [[ -n "$tmp_line" ]]; then
            options=$(echo "$tmp_line" | awk '{print $4}')
        fi
    fi

    if [[ -z "$options" ]]; then
        options=$(run_cmd findmnt -n -o OPTIONS /tmp 2>/dev/null) || true
    fi

    if [[ -z "$options" ]]; then
        status="$STATUS_SKIP"
        evidence="/tmp partition not found or not accessible"
    elif echo "$options" | grep -q "$option"; then
        evidence="${option} is set on /tmp (${options})"
    else
        status="$STATUS_FAIL"
        evidence="${option} is not set on /tmp (${options})"
    fi

    record_result "$id" "$status" "$evidence"
}

check_1_2_2() { _check_tmp_mount_option "1.2.2" "noexec"; }
check_1_2_3() { _check_tmp_mount_option "1.2.3" "nosuid"; }
check_1_2_4() { _check_tmp_mount_option "1.2.4" "nodev"; }

check_1_3_1() {
    local id="1.3.1"
    local status="$STATUS_PASS"
    local evidence=""

    local sources_list="${SYSROOT}/etc/apt/sources.list"
    local sources_dir="${SYSROOT}/etc/apt/sources.list.d"
    local found_repos="false"

    if [[ -f "$sources_list" ]]; then
        local active_lines
        active_lines=$(grep -cE '^\s*deb\s' "$sources_list" 2>/dev/null) || true
        if [[ "$active_lines" -gt 0 ]]; then
            found_repos="true"
            evidence="Found ${active_lines} repo(s) in sources.list"
        fi
    fi

    if [[ -d "$sources_dir" ]]; then
        local source_files
        source_files=$(find "$sources_dir" -maxdepth 1 -name "*.list" -o -name "*.sources" 2>/dev/null | head -20) || true
        if [[ -n "$source_files" ]]; then
            local file_count
            file_count=$(echo "$source_files" | wc -l)
            found_repos="true"
            if [[ -n "$evidence" ]]; then
                evidence="${evidence}; ${file_count} source file(s) in sources.list.d"
            else
                evidence="${file_count} source file(s) in sources.list.d"
            fi
        fi
    fi

    if [[ "$found_repos" == "false" ]]; then
        status="$STATUS_FAIL"
        evidence="No package repositories configured"
    fi

    record_result "$id" "$status" "$evidence"
}

check_1_3_2() {
    local id="1.3.2"
    local status="$STATUS_PASS"
    local evidence=""

    local trusted_dir="${SYSROOT}/etc/apt/trusted.gpg.d"
    local keyrings_dir="${SYSROOT}/etc/apt/keyrings"
    local found_keys="false"

    if [[ -d "$trusted_dir" ]]; then
        local key_files
        key_files=$(find "$trusted_dir" -maxdepth 1 -name "*.gpg" -o -name "*.asc" 2>/dev/null | head -20) || true
        if [[ -n "$key_files" ]]; then
            local key_count
            key_count=$(echo "$key_files" | wc -l)
            found_keys="true"
            evidence="${key_count} GPG key(s) in trusted.gpg.d"
        fi
    fi

    if [[ -d "$keyrings_dir" ]]; then
        local keyring_files
        keyring_files=$(find "$keyrings_dir" -maxdepth 1 -name "*.gpg" -o -name "*.asc" 2>/dev/null | head -20) || true
        if [[ -n "$keyring_files" ]]; then
            local ring_count
            ring_count=$(echo "$keyring_files" | wc -l)
            found_keys="true"
            if [[ -n "$evidence" ]]; then
                evidence="${evidence}; ${ring_count} keyring(s) in apt/keyrings"
            else
                evidence="${ring_count} keyring(s) in apt/keyrings"
            fi
        fi
    fi

    if [[ "$found_keys" == "false" ]]; then
        local apt_key_output
        if apt_key_output=$(run_cmd apt-key list 2>/dev/null) && [[ -n "$apt_key_output" ]]; then
            found_keys="true"
            evidence="GPG keys found via apt-key"
        fi
    fi

    if [[ "$found_keys" == "false" ]]; then
        status="$STATUS_FAIL"
        evidence="No GPG keys configured for package verification"
    fi

    record_result "$id" "$status" "$evidence"
}

check_1_4_1() {
    local id="1.4.1"
    local status="$STATUS_PASS"
    local evidence=""

    local grub_dir="${SYSROOT}/etc/grub.d"
    local grub_default="${SYSROOT}/etc/default/grub"
    local found_password="false"

    if [[ -d "$grub_dir" ]]; then
        for grub_file in "${grub_dir}"/*; do
            [[ -f "$grub_file" ]] || continue
            if grep -q "password" "$grub_file" 2>/dev/null; then
                found_password="true"
                evidence="Bootloader password set in ${grub_file}"
                break
            fi
        done
    fi

    if [[ "$found_password" == "false" && -f "$grub_default" ]]; then
        if grep -q "GRUB_PASSWORD\|GRUB_USERS" "$grub_default" 2>/dev/null; then
            found_password="true"
            evidence="Bootloader password configured in /etc/default/grub"
        fi
    fi

    if [[ "$found_password" == "false" ]]; then
        local grub_cfg="${SYSROOT}/boot/grub/grub.cfg"
        if [[ -f "$grub_cfg" ]]; then
            if grep -q "password_pbkdf2\|password " "$grub_cfg" 2>/dev/null; then
                found_password="true"
                evidence="Bootloader password found in grub.cfg"
            fi
        fi
    fi

    if [[ "$found_password" == "false" ]]; then
        status="$STATUS_FAIL"
        evidence="Bootloader password is not set"
    fi

    record_result "$id" "$status" "$evidence"
}

check_1_4_2() {
    local id="1.4.2"
    local status="$STATUS_PASS"
    local evidence=""

    local grub_cfg="${SYSROOT}/boot/grub/grub.cfg"

    if [[ ! -f "$grub_cfg" ]]; then
        status="$STATUS_SKIP"
        evidence="/boot/grub/grub.cfg not found"
        record_result "$id" "$status" "$evidence"
        return
    fi

    local file_stat
    if file_stat=$(run_cmd stat -c '%a %U %G' "$grub_cfg" 2>/dev/null); then
        local perms owner group
        perms=$(echo "$file_stat" | awk '{print $1}')
        owner=$(echo "$file_stat" | awk '{print $2}')
        group=$(echo "$file_stat" | awk '{print $3}')

        if [[ "$owner" != "root" || "$group" != "root" ]]; then
            status="$STATUS_FAIL"
            evidence="grub.cfg owned by ${owner}:${group} (expected root:root)"
        elif (( 8#$perms > 8#0600 )); then
            status="$STATUS_FAIL"
            evidence="grub.cfg permissions ${perms} (expected 600 or more restrictive)"
        else
            evidence="grub.cfg permissions ${perms}, owned by ${owner}:${group}"
        fi
    else
        local ls_output
        ls_output=$(ls -l "$grub_cfg" 2>/dev/null) || true
        if [[ -n "$ls_output" ]]; then
            local perm_str
            perm_str=$(echo "$ls_output" | awk '{print $1}')
            local file_owner
            file_owner=$(echo "$ls_output" | awk '{print $3}')
            local file_group
            file_group=$(echo "$ls_output" | awk '{print $4}')

            if [[ "$file_owner" != "root" || "$file_group" != "root" ]]; then
                status="$STATUS_FAIL"
                evidence="grub.cfg owned by ${file_owner}:${file_group} (expected root:root)"
            elif echo "$perm_str" | grep -q "......r\|.......w\|........x"; then
                status="$STATUS_FAIL"
                evidence="grub.cfg has excessive permissions (${perm_str})"
            else
                evidence="grub.cfg permissions ${perm_str}, owned by ${file_owner}:${file_group}"
            fi
        else
            status="$STATUS_SKIP"
            evidence="Unable to determine grub.cfg permissions"
        fi
    fi

    record_result "$id" "$status" "$evidence"
}

check_1_4_3() {
    local id="1.4.3"
    local status="$STATUS_PASS"
    local evidence=""

    local rescue_service="${SYSROOT}/usr/lib/systemd/system/rescue.service"
    local emergency_service="${SYSROOT}/usr/lib/systemd/system/emergency.service"
    local found_sulogin="false"

    if [[ -f "$rescue_service" ]]; then
        if grep -q "sulogin" "$rescue_service" 2>/dev/null; then
            found_sulogin="true"
            evidence="sulogin required for rescue mode"
        fi
    fi

    if [[ -f "$emergency_service" ]]; then
        if grep -q "sulogin" "$emergency_service" 2>/dev/null; then
            if [[ "$found_sulogin" == "true" ]]; then
                evidence="sulogin required for rescue and emergency modes"
            else
                found_sulogin="true"
                evidence="sulogin required for emergency mode"
            fi
        fi
    fi

    if [[ "$found_sulogin" == "false" ]]; then
        local inittab="${SYSROOT}/etc/inittab"
        if [[ -f "$inittab" ]]; then
            if grep -q "sulogin" "$inittab" 2>/dev/null; then
                found_sulogin="true"
                evidence="sulogin required via /etc/inittab"
            fi
        fi
    fi

    if [[ "$found_sulogin" == "false" ]]; then
        local override_rescue="${SYSROOT}/etc/systemd/system/rescue.service.d"
        local override_emergency="${SYSROOT}/etc/systemd/system/emergency.service.d"

        for override_dir in "$override_rescue" "$override_emergency"; do
            [[ -d "$override_dir" ]] || continue
            for override_file in "${override_dir}"/*.conf; do
                [[ -f "$override_file" ]] || continue
                if grep -q "sulogin" "$override_file" 2>/dev/null; then
                    found_sulogin="true"
                    evidence="sulogin required via systemd override"
                    break 2
                fi
            done
        done
    fi

    if [[ "$found_sulogin" == "false" ]]; then
        status="$STATUS_FAIL"
        evidence="Authentication not required for single-user mode"
    fi

    record_result "$id" "$status" "$evidence"
}

check_1_5_1() {
    local id="1.5.1"
    local status="$STATUS_PASS"
    local evidence=""

    local aslr_value
    aslr_value=$(get_sysctl "kernel.randomize_va_space") || true

    if [[ -z "$aslr_value" ]]; then
        status="$STATUS_SKIP"
        evidence="Unable to determine ASLR status"
    elif [[ "$aslr_value" == "2" ]]; then
        evidence="ASLR is fully enabled (kernel.randomize_va_space = 2)"
    elif [[ "$aslr_value" == "1" ]]; then
        status="$STATUS_WARN"
        evidence="ASLR is partially enabled (kernel.randomize_va_space = 1, expected 2)"
    else
        status="$STATUS_FAIL"
        evidence="ASLR is disabled (kernel.randomize_va_space = ${aslr_value}, expected 2)"
    fi

    record_result "$id" "$status" "$evidence"
}

check_1_5_2() {
    local id="1.5.2"
    local status="$STATUS_PASS"
    local evidence=""

    local limits_ok="false"
    local sysctl_ok="false"
    local limits_file="${SYSROOT}/etc/security/limits.conf"
    local limits_dir="${SYSROOT}/etc/security/limits.d"

    if [[ -f "$limits_file" ]]; then
        if grep -qE '^\s*\*\s+hard\s+core\s+0' "$limits_file" 2>/dev/null; then
            limits_ok="true"
        fi
    fi

    if [[ "$limits_ok" == "false" && -d "$limits_dir" ]]; then
        for lconf in "${limits_dir}"/*.conf; do
            [[ -f "$lconf" ]] || continue
            if grep -qE '^\s*\*\s+hard\s+core\s+0' "$lconf" 2>/dev/null; then
                limits_ok="true"
                break
            fi
        done
    fi

    local dumpable
    dumpable=$(get_sysctl "fs.suid_dumpable") || true

    if [[ "$dumpable" == "0" ]]; then
        sysctl_ok="true"
    fi

    if [[ "$limits_ok" == "true" && "$sysctl_ok" == "true" ]]; then
        evidence="Core dumps restricted (limits.conf + fs.suid_dumpable = 0)"
    elif [[ "$limits_ok" == "true" && "$sysctl_ok" == "false" ]]; then
        status="$STATUS_FAIL"
        evidence="Core limit set but fs.suid_dumpable = ${dumpable:-unknown} (expected 0)"
    elif [[ "$limits_ok" == "false" && "$sysctl_ok" == "true" ]]; then
        status="$STATUS_FAIL"
        evidence="fs.suid_dumpable = 0 but hard core 0 not set in limits.conf"
    else
        status="$STATUS_FAIL"
        evidence="Core dumps not restricted (missing limits.conf and sysctl settings)"
    fi

    record_result "$id" "$status" "$evidence"
}

check_1_5_3() {
    local id="1.5.3"
    local status="$STATUS_PASS"
    local evidence=""

    if run_cmd dpkg-query -W prelink > /dev/null 2>&1; then
        status="$STATUS_FAIL"
        evidence="prelink is installed"
    else
        local prelink_bin="${SYSROOT}/usr/sbin/prelink"
        if [[ -f "$prelink_bin" ]]; then
            status="$STATUS_FAIL"
            evidence="prelink binary found at /usr/sbin/prelink"
        else
            evidence="prelink is not installed"
        fi
    fi

    record_result "$id" "$status" "$evidence"
}
