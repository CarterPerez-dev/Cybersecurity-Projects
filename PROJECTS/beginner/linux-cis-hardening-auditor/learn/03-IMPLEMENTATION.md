<!-- © AngelaMos | 2026 | 03-IMPLEMENTATION.md -->

# Implementation Guide

This document walks through the actual code. We will trace how controls are registered, how check functions inspect the system, how scores are computed, and how reports are generated. Code snippets come directly from the project source files.

---

## File Structure Walkthrough

```
src/
├── cisaudit.sh              # Entry point and CLI orchestration
├── lib/
│   ├── constants.sh         # All constants and color codes
│   ├── utils.sh             # System inspection helpers
│   ├── registry.sh          # Control registration and result storage
│   ├── engine.sh            # Score aggregation
│   ├── report_terminal.sh   # Terminal output with progress bars
│   ├── report_json.sh       # Machine-readable JSON
│   ├── report_html.sh       # Standalone HTML with embedded CSS
│   └── baseline.sh          # Save/load/diff baselines
├── controls/
│   └── registry_data.sh     # 104 control definitions
└── checks/
    ├── 01_initial_setup.sh  # 20 checks for Section 1
    ├── 02_services.sh       # 16 checks for Section 2
    ├── 03_network.sh        # 20 checks for Section 3
    ├── 04_logging.sh        # 18 checks for Section 4
    ├── 05_access.sh         # 14 checks for Section 5 (cron, SSH)
    ├── 05_access_password.sh # 4 checks for Section 5 (passwords, PAM)
    └── 06_maintenance.sh    # 10 checks for Section 6
```

---

## Building the Control Registry

### The register_control Function

Every CIS control starts as a call to `register_control` in `registry_data.sh`. The function in `registry.sh` stores control metadata into associative arrays and derives the check function name from the control ID:

```bash
register_control() {
    local id="$1"
    local section="$2"
    local title="$3"
    local level="$4"
    local scored="$5"
    local description="$6"
    local remediation="$7"

    CTRL_TITLE["$id"]="$title"
    CTRL_SECTION["$id"]="$section"
    CTRL_LEVEL["$id"]="$level"
    CTRL_SCORED["$id"]="$scored"
    CTRL_DESCRIPTION["$id"]="$description"
    CTRL_REMEDIATION["$id"]="$remediation"

    local fn_name="check_${id//\./_}"
    CTRL_CHECK_FN["$id"]="$fn_name"
    REGISTERED_IDS+=("$id")
}
```

The expression `${id//\./_}` replaces every dot with an underscore. Control ID `"1.1.1"` becomes function name `"check_1_1_1"`. Control ID `"5.2.14"` becomes `"check_5_2_14"`. This naming convention is enforced by the registration system, not by documentation. If a check function does not exist, the engine skips it with evidence explaining why.

### A Registration Call

In `registry_data.sh`, each control definition looks like this:

```bash
register_control "1.2.1" \
    "Initial Setup" \
    "Ensure /tmp is a separate partition" \
    "1" \
    "yes" \
    "The /tmp directory is a world-writable location used for temporary file storage..." \
    "echo 'tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0' >> /etc/fstab && mount -o remount /tmp"
```

The seven positional arguments are: ID, section, title, level, scored, description, remediation. The description is stored but not displayed in terminal reports (only in JSON and HTML). The remediation string is shown to the user when a control fails, so they know exactly what command to run.

### The record_result Function

After a check function inspects the system, it records its finding:

```bash
record_result() {
    local id="$1"
    local status="$2"
    local evidence="$3"

    RESULT_STATUS["$id"]="$status"
    RESULT_EVIDENCE["$id"]="$evidence"
    RESULT_ORDER+=("$id")

    case "$status" in
        "$STATUS_PASS") ((TOTAL_PASS++)) || true ;;
        "$STATUS_FAIL") ((TOTAL_FAIL++)) || true ;;
        "$STATUS_WARN") ((TOTAL_WARN++)) || true ;;
        "$STATUS_SKIP") ((TOTAL_SKIP++)) || true ;;
    esac
}
```

The `|| true` after the increment is necessary because `((TOTAL_PASS++))` returns exit code 1 when TOTAL_PASS was 0 (because `0` is falsy in arithmetic context), and `set -e` would terminate the script. This is a common Bash gotcha that silently kills scripts using strict mode.

---

## Writing Check Functions

### Pattern 1: Shared Helper with Per-Control Wrappers

Many controls in the same section follow an identical check pattern with different parameters. Instead of duplicating logic, a private helper function does the work and thin wrappers call it.

The filesystem module disable checks all follow this pattern. The helper `_check_module_disabled` in `01_initial_setup.sh` handles the full logic:

```bash
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
            status="$STATUS_FAIL"
            evidence="${module} is not disabled"
        fi
    fi

    record_result "$id" "$status" "$evidence"
}
```

The function checks three things in order: (1) is the module currently loaded in memory, (2) does a dedicated modprobe config file exist, (3) does any modprobe config file contain a disable or blacklist directive for this module. If none of these succeed, the control fails.

Each control wraps the helper in a one-liner:

```bash
check_1_1_1() { _check_module_disabled "1.1.1" "cramfs"; }
check_1_1_2() { _check_module_disabled "1.1.2" "freevxfs"; }
check_1_1_3() { _check_module_disabled "1.1.3" "jffs2"; }
```

The same pattern appears throughout the codebase. SSH checks use `_check_ssh_value` and `_check_ssh_max_int`. Password policy checks use `_check_login_defs_value`. File permission checks use `_check_file_permissions`.

### Pattern 2: Standalone Complex Check

Some controls have unique logic that does not generalize. The MTA local-only check (`check_2_2_15`) inspects multiple mail transfer agents in priority order:

```bash
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
    # ... continues with Postfix, Exim, Sendmail checks ...
}
```

This function first checks whether anything is listening on port 25 on a non-loopback interface (the definitive test). Then it falls back to reading Postfix's `inet_interfaces` setting, then Exim's `dc_local_interfaces`, then checks for Sendmail. The layered approach handles different MTA configurations without hardcoding assumptions about which MTA is installed.

### Pattern 3: Audit Rule Verification

The `_check_audit_rules` function in `04_logging.sh` takes a list of patterns and verifies that each one appears in at least one audit rules file:

```bash
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
```

Callers pass variable-length pattern lists:

```bash
check_4_1_5() {
    _check_audit_rules "4.1.5" "Time change" \
        "adjtimex" "settimeofday" "clock_settime" "/etc/localtime"
}
```

If any pattern is missing from all rules files, the control fails with evidence listing exactly which patterns were not found. This gives the user actionable information about what audit rules to add.

---

## The SYSROOT Abstraction

### How It Works

The `SYSROOT` variable defaults to `"/"`. When running in test mode (`-t testdata/fixtures`), it is set to the fixture directory path. Every system inspection function prepends `SYSROOT` to file paths:

```bash
file_exists() {
    [[ -f "${SYSROOT}${1}" ]]
}

read_file() {
    local path="${SYSROOT}${1}"
    if [[ -f "$path" ]]; then
        cat "$path"
    else
        return 1
    fi
}
```

The `get_sysctl` function is where this gets interesting. Sysctl values are normally read with `sysctl -n net.ipv4.ip_forward`, but that requires a running kernel. In test mode, the function translates the dotted sysctl parameter name into a `/proc/sys/` path:

```bash
get_sysctl() {
    local param="$1"
    local proc_path="${SYSROOT}/proc/sys/${param//\.//}"
    if [[ -f "$proc_path" ]]; then
        cat "$proc_path"
        return 0
    fi

    if run_cmd sysctl -n "$param"; then
        return 0
    fi

    return 1
}
```

The expression `${param//\.//}` replaces dots with slashes. So `net.ipv4.ip_forward` becomes `net/ipv4/ip_forward`, and the full path becomes `testdata/fixtures/proc/sys/net/ipv4/ip_forward`. That file contains `0` (the expected secure value).

The `run_cmd` function explicitly blocks command execution in test mode:

```bash
run_cmd() {
    if [[ "$SYSROOT" != "/" ]]; then
        return 1
    fi
    "$@" 2>/dev/null
}
```

When `SYSROOT` is not `/`, `run_cmd` always returns failure. This means checks that rely on `systemctl`, `dpkg-query`, `lsmod`, or `iptables` will skip in test mode because those commands cannot run against a fixture directory. Only file-based checks produce results.

---

## Score Computation

The `compute_scores` function in `engine.sh` aggregates results per section and per level:

```bash
compute_scores() {
    local section
    for section in "${SECTION_ORDER[@]}"; do
        SECTION_PASS["$section"]=0
        SECTION_FAIL["$section"]=0
        SECTION_WARN["$section"]=0
        SECTION_SKIP["$section"]=0
    done

    local id
    for id in "${RESULT_ORDER[@]}"; do
        section="${CTRL_SECTION[$id]}"
        case "${RESULT_STATUS[$id]}" in
            "$STATUS_PASS") ((SECTION_PASS["$section"]++)) || true ;;
            "$STATUS_FAIL") ((SECTION_FAIL["$section"]++)) || true ;;
            "$STATUS_WARN") ((SECTION_WARN["$section"]++)) || true ;;
            "$STATUS_SKIP") ((SECTION_SKIP["$section"]++)) || true ;;
        esac
    done
    # ...
}
```

Scores are computed as `(pass / (pass + fail)) * 100`. WARN and SKIP results are excluded from the percentage because CIS scoring guidelines only count definitively passed or failed controls. A control that was skipped (because it requires a live system) should not penalize the score.

The `awk` call for percentage calculation avoids Bash's limitation of integer-only arithmetic:

```bash
SCORE_OVERALL=$(awk "BEGIN { printf \"%.1f\", ($TOTAL_PASS / $scored_total) * 100 }")
```

---

## Report Generation

### Terminal Report

The terminal reporter in `report_terminal.sh` produces a structured ASCII output with colored sections. The main function chains four rendering steps:

```bash
emit_terminal_report() {
    _print_banner
    _print_summary_cards
    _print_section_table
    _print_detail_results
    _print_footer
}
```

The progress bar function `_progress_bar` renders a 20-character wide bar using block characters:

```bash
_progress_bar() {
    local percentage="$1"
    local width=20
    local filled
    local empty

    if [[ "$percentage" == "N/A" ]]; then
        printf '%s' "░░░░░░░░░░░░░░░░░░░░"
        return
    fi

    filled=$(awk "BEGIN { printf \"%d\", ($percentage / 100) * $width + 0.5 }")
    empty=$((width - filled))

    local bar=""
    local i
    for (( i = 0; i < filled; i++ )); do
        bar+="█"
    done
    for (( i = 0; i < empty; i++ )); do
        bar+="░"
    done
    printf '%s' "$bar"
}
```

The detail results section shows per-control status with evidence and remediation for failed controls:

```bash
if [[ "$status" == "$STATUS_FAIL" ]]; then
    local evidence="${RESULT_EVIDENCE[$id]:-}"
    local remediation="${CTRL_REMEDIATION[$id]:-}"

    if [[ -n "$evidence" ]]; then
        printf '  %b             Evidence: %s%b\n' "$DIM" "$evidence" "$RESET"
    fi
    if [[ -n "$remediation" ]]; then
        printf '  %b             Fix: %s%b\n' "$YELLOW" "$remediation" "$RESET"
    fi
fi
```

### JSON Report

The JSON reporter in `report_json.sh` uses `printf` to build valid JSON without `jq`. The `json_escape` function handles the five characters that must be escaped in JSON strings:

```bash
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\r'/\\r}"
    printf '%s' "$s"
}
```

The report includes metadata (version, benchmark, timestamp, hostname, OS), a summary object, an array of section scores, and an array of all control results. Each control result includes the ID, section, title, level, scored status, result status, evidence, and remediation. This makes the JSON output usable for ingestion into SIEMs, dashboards, or compliance platforms.

### HTML Report

The HTML reporter in `report_html.sh` generates a standalone HTML document with embedded CSS. The entire report is a single self-contained file with no external dependencies, which means it can be emailed, archived, or viewed offline.

The CSS uses a dark color scheme with CSS custom properties for theme colors. Failed controls are rendered with `<details open>` so they are expanded by default, while passing controls are collapsed. The report includes responsive breakpoints for mobile viewing and a print stylesheet that switches to a light theme.

---

## Baseline Comparison

The baseline module in `baseline.sh` lets users save a JSON snapshot and compare future runs against it.

Saving is straightforward: it calls `emit_json_report` and writes the output to a file.

Loading and diffing uses pure Bash regex matching to extract control IDs and statuses from the JSON without requiring `jq`:

```bash
load_baseline() {
    local file="$1"
    BASELINE_STATUS=()

    local current_id=""
    local id_pattern='"id":[[:space:]]*"([^"]+)"'
    local status_pattern='"status":[[:space:]]*"([^"]+)"'
    while IFS= read -r line; do
        if [[ "$line" =~ $id_pattern ]]; then
            current_id="${BASH_REMATCH[1]}"
        fi
        if [[ -n "$current_id" && "$line" =~ $status_pattern ]]; then
            BASELINE_STATUS["$current_id"]="${BASH_REMATCH[1]}"
            current_id=""
        fi
    done < "$file"
}
```

The diff output categorizes changes as regressions (PASS to FAIL), improvements (FAIL to PASS), unchanged, new controls, and removed controls. Regressions are highlighted in red and generate a warning.

---

## The Test Framework

### Test Runner

The test runner in `test_runner.sh` sources all project modules, then discovers test files by globbing `test_*.sh` (excluding `test_helpers.sh` and `test_runner.sh`). For each file, it sources it, discovers functions matching `^test_`, calls each one, and then unsets them to prevent collisions with the next file:

```bash
run_test_file() {
    local test_file="$1"
    source "$test_file"

    local test_fns
    test_fns=$(declare -F | awk '{print $3}' | grep '^test_')

    local fn
    for fn in $test_fns; do
        echo "  Running: ${fn}"
        "$fn"
    done

    for fn in $test_fns; do
        unset -f "$fn"
    done
}
```

### Assertion Helpers

The `setup_test` function resets all result state and sets `SYSROOT` to a fixture directory:

```bash
setup_test() {
    local fixtures_dir="$1"
    reset_results
    SYSROOT="$fixtures_dir"
    DETECTED_ID="debian"
    DETECTED_VERSION="12"
}
```

`assert_status` compares the recorded result status for a control ID against the expected value:

```bash
assert_status() {
    local id="$1" expected="$2"
    local actual="${RESULT_STATUS[$id]:-UNSET}"
    ((TEST_TOTAL++)) || true
    if [[ "$actual" == "$expected" ]]; then
        ((TEST_PASS++)) || true
    else
        ((TEST_FAIL++)) || true
        echo "  FAIL: ${CURRENT_TEST} — ${id}: expected ${expected}, got ${actual}" >&2
    fi
}
```

`assert_evidence_contains` verifies that the evidence string contains an expected substring. This is more robust than exact matching because evidence strings often include variable details like file paths or numeric values.

---

## Adding a New Control

To add a new CIS control, you need exactly two changes:

**Step 1: Register the control** in `controls/registry_data.sh`:

```bash
register_control "1.6.1" \
    "Initial Setup" \
    "Ensure SELinux or AppArmor is installed" \
    "1" \
    "yes" \
    "Mandatory access control frameworks restrict process capabilities beyond DAC permissions" \
    "apt-get install apparmor apparmor-utils"
```

**Step 2: Write the check function** in the appropriate `checks/0X_section.sh` file:

```bash
check_1_6_1() {
    local id="1.6.1"
    local status="$STATUS_PASS"
    local evidence=""

    if package_is_installed "apparmor"; then
        evidence="AppArmor is installed"
    elif package_is_installed "selinux-basics"; then
        evidence="SELinux is installed"
    elif file_exists "/usr/sbin/apparmor_parser"; then
        evidence="AppArmor binary found"
    else
        status="$STATUS_FAIL"
        evidence="Neither AppArmor nor SELinux is installed"
    fi

    record_result "$id" "$status" "$evidence"
}
```

**Step 3: Add tests** in the appropriate `tests/test_0X_section.sh` file:

```bash
test_selinux_apparmor_pass() {
    CURRENT_TEST="test_selinux_apparmor_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    # add /usr/sbin/apparmor_parser to fixtures first
    check_1_6_1
    assert_status "1.6.1" "$STATUS_PASS"
}
```

The engine, reporters, baseline module, and scoring engine automatically pick up the new control. No other files need modification.

---

## Common Implementation Pitfalls

### Pitfall 1: Arithmetic Increment Under set -e

**Symptom:** Script exits silently when incrementing a counter that is currently 0.

**Cause:**

```bash
((count++))
```

When `count` is 0, `((count++))` evaluates to 0 (the pre-increment value), which is falsy in Bash arithmetic. Under `set -e`, this non-zero exit code terminates the script.

**Fix:**

```bash
((count++)) || true
```

The `|| true` swallows the false exit code. This pattern appears throughout the codebase wherever a counter is incremented.

### Pitfall 2: Grep Failure Under set -e

**Symptom:** Script exits when grep finds no matches.

**Cause:** `grep` returns exit code 1 when it finds no matches. Under `set -e`, this is treated as a fatal error.

**Fix:**

```bash
local result
result=$(grep "pattern" "$file") || true
```

The `|| true` ensures the script continues when grep finds nothing. The variable `result` will be empty, and the check function should handle that case.

### Pitfall 3: Missing Quote Around Variable in Array Key

**Symptom:** Associative array lookups return empty for keys containing special characters.

**Cause:**

```bash
RESULT_STATUS[$id]="PASS"
```

If `$id` contains characters that Bash might interpret (spaces, special characters), the lookup fails.

**Fix:**

```bash
RESULT_STATUS["$id"]="PASS"
```

Always quote associative array keys. The codebase consistently quotes all array key accesses.

---

## Debugging Tips

### Control Returns Unexpected Status

1. Run the specific control in isolation against a fixture:
   ```bash
   source src/lib/constants.sh src/lib/utils.sh src/lib/registry.sh
   source src/controls/registry_data.sh
   source src/checks/01_initial_setup.sh
   SYSROOT="testdata/fixtures" QUIET="true"
   check_1_1_1
   echo "${RESULT_STATUS[1.1.1]}: ${RESULT_EVIDENCE[1.1.1]}"
   ```
2. Check whether the fixture file exists and contains the expected content
3. Verify that the check function is looking at the right file path under `SYSROOT`

### JSON Report Is Invalid

1. Pipe through `python3 -m json.tool` to see where the parser fails
2. Check whether any evidence string contains unescaped quotes or newlines
3. The `json_escape` function handles `\`, `"`, `\n`, `\t`, and `\r`. If a new character causes issues, add it to the function

### Tests Pass Locally But Fail in CI

1. Check the Bash version: `bash --version`. Some CI environments ship Bash 4.x where a check relies on Bash 5.x features
2. Verify that the working directory is set correctly. `SCRIPT_DIR` and `PROJECT_DIR` in the test runner depend on `${BASH_SOURCE[0]}`
3. Ensure that fixture files have the correct line endings (LF, not CRLF)

---

## Next Steps

You have seen how the code works. Now:

1. **Try the challenges** - [04-CHALLENGES.md](./04-CHALLENGES.md) has extension ideas ranging from new output formats to multi-distro support
2. **Modify a check** - Pick a control, change the expected value in a fixture, and verify the check fails as expected
3. **Add a control** - Follow the three-step process above to add a control from the CIS benchmark that is not yet implemented
