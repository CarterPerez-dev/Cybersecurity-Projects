<!-- © AngelaMos | 2026 | 02-ARCHITECTURE.md -->

# System Architecture

This document breaks down how cisaudit is designed, how data flows through the system, and why the modular architecture makes it straightforward to add new controls, output formats, and benchmark versions.

---

## High Level Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    cisaudit.sh (entry point)              │
│  Parse CLI args  →  Load modules  →  Orchestrate audit   │
└────────────────┬──────────────────────────┬──────────────┘
                 │                          │
    ┌────────────▼────────────┐  ┌──────────▼──────────────┐
    │   controls/             │  │   lib/                   │
    │   registry_data.sh      │  │   constants.sh           │
    │                         │  │   utils.sh               │
    │   104 register_control  │  │   registry.sh            │
    │   calls defining every  │  │   engine.sh              │
    │   control's metadata    │  │   baseline.sh            │
    └────────────┬────────────┘  │   report_terminal.sh     │
                 │               │   report_json.sh         │
                 │               │   report_html.sh         │
    ┌────────────▼────────────┐  └──────────────────────────┘
    │   checks/               │
    │   01_initial_setup.sh   │
    │   02_services.sh        │
    │   03_network.sh         │
    │   04_logging.sh         │
    │   05_access.sh          │
    │   05_access_password.sh │
    │   06_maintenance.sh     │
    │                         │
    │   check_X_Y_Z()         │
    │   functions that        │
    │   inspect the system    │
    │   and call              │
    │   record_result()       │
    └─────────────────────────┘
```

### Component Breakdown

**cisaudit.sh (Entry Point)**
- Parses command-line arguments into global variables
- Sources all library modules, control definitions, and check functions
- Orchestrates the audit: detect OS, run checks, compute scores, emit report
- Handles baseline save/diff and threshold exit codes

**controls/registry_data.sh (Control Registry)**
- Contains 104 `register_control` calls, each defining one CIS benchmark control
- Each call specifies: control ID, section name, title, level, scored status, description, and remediation command
- This is the single source of truth for what the tool audits

**checks/*.sh (Check Functions)**
- One file per CIS benchmark section
- Each file contains `check_X_Y_Z()` functions that inspect the system and call `record_result()`
- Check functions read config files, query sysctl values, verify file permissions, and test for installed packages

**lib/ (Core Libraries)**
- `constants.sh`: Version, benchmark name, ANSI color codes, status codes, section names
- `utils.sh`: Logging, OS detection, file read helpers, sysctl helpers, service/package queries
- `registry.sh`: `register_control()` and `record_result()` functions, result storage
- `engine.sh`: Score computation by section and by level
- `report_*.sh`: Three output formatters (terminal, JSON, HTML)
- `baseline.sh`: Save results as JSON, load and diff against a previous baseline

---

## Data Flow

### Full Audit Flow

Step by step walkthrough of what happens when you run `sudo cisaudit -l 1 -f json -o report.json`:

```
1. cisaudit.sh starts
   └─ source lib/constants.sh, utils.sh, registry.sh, engine.sh
   └─ source lib/report_*.sh, baseline.sh
   └─ source controls/registry_data.sh (populates CTRL_* arrays)
   └─ source checks/*.sh (defines check_X_Y_Z functions)

2. parse_args() processes CLI arguments
   └─ OPT_LEVEL="1", OPT_FORMAT="json", OPT_OUTPUT="report.json"

3. detect_os() reads /etc/os-release
   └─ DETECTED_ID="debian", DETECTED_VERSION="12"

4. run_checks() iterates REGISTERED_IDS[]
   └─ For each control ID:
       ├─ should_run_check() filters by level and category
       ├─ Calls check_X_Y_Z() function via CTRL_CHECK_FN lookup
       └─ check function calls record_result(id, status, evidence)
           └─ Appends to RESULT_STATUS[], RESULT_EVIDENCE[], RESULT_ORDER[]
           └─ Increments TOTAL_PASS/FAIL/WARN/SKIP counters

5. compute_scores() aggregates results
   └─ Counts pass/fail per section → SCORE_BY_SECTION[]
   └─ Computes SCORE_OVERALL, SCORE_LEVEL1, SCORE_LEVEL2

6. generate_report() dispatches to emit_json_report()
   └─ Iterates RESULT_ORDER[] and SECTION_ORDER[]
   └─ Prints JSON with metadata, summary, sections, controls
   └─ Writes to report.json via OPT_OUTPUT

7. Threshold check: if SCORE_OVERALL < OPT_THRESHOLD, exit 1
```

### Control Registration Flow

Every control follows the same path from definition to result:

```
registry_data.sh                    checks/0X_section.sh
       │                                   │
register_control(                    check_1_1_1() {
  "1.1.1",                              status = PASS
  "Initial Setup",                       evidence = ""
  "Ensure cramfs disabled",              # inspect system
  "1", "yes",                            # ...
  "description...",                      record_result(
  "remediation..."                         "1.1.1",
)                                          status,
       │                                   evidence
       ▼                                 )
CTRL_TITLE["1.1.1"]                  }
CTRL_SECTION["1.1.1"]                     │
CTRL_LEVEL["1.1.1"]                       ▼
CTRL_SCORED["1.1.1"]              RESULT_STATUS["1.1.1"]
CTRL_DESCRIPTION["1.1.1"]        RESULT_EVIDENCE["1.1.1"]
CTRL_REMEDIATION["1.1.1"]        RESULT_ORDER += "1.1.1"
CTRL_CHECK_FN["1.1.1"]           TOTAL_PASS++
  = "check_1_1_1"
```

The naming convention is automatic. `register_control "1.1.1"` generates the function name `check_1_1_1` by replacing dots with underscores. The check function must exist with that exact name, or the engine logs a SKIP with "Check function check_1_1_1 not implemented."

---

## Design Patterns

### Registry Pattern

The core architectural pattern is a control registry. All 104 controls are registered through a single function (`register_control`) into associative arrays. The engine does not hardcode any control logic. It iterates `REGISTERED_IDS[]`, looks up the check function name from `CTRL_CHECK_FN[]`, and calls it dynamically.

This pattern means:
- Adding a new control requires exactly two changes: one `register_control` call and one `check_X_Y_Z` function
- The engine, reporters, and baseline modules are completely independent of which controls exist
- Controls can be added or removed without modifying any core code

```bash
register_control "1.1.1" \
    "Initial Setup" \
    "Ensure mounting of cramfs is disabled" \
    "1" \
    "yes" \
    "The cramfs filesystem type is..." \
    "echo 'install cramfs /bin/true' >> /etc/modprobe.d/cramfs.conf"
```

This call populates six associative arrays and one indexed array. The function name is derived from the ID: `check_1_1_1`.

### Strategy Pattern for Reporters

Three reporter modules (`report_terminal.sh`, `report_json.sh`, `report_html.sh`) each expose a single entry function: `emit_terminal_report`, `emit_json_report`, `emit_html_report`. The `generate_report` function in `cisaudit.sh` dispatches to the correct one based on `OPT_FORMAT`.

Each reporter reads the same global state (RESULT_STATUS, RESULT_EVIDENCE, SCORE_BY_SECTION, etc.) and transforms it into a different format. They share no code between them because each output format has fundamentally different structure.

Adding a new format (CSV, SARIF, Markdown) means writing one new file with one `emit_X_report` function and adding one case to `generate_report`. Nothing else changes.

### SYSROOT Abstraction

Every file access goes through helper functions that prepend the `SYSROOT` variable:

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

get_sysctl() {
    local param="$1"
    local proc_path="${SYSROOT}/proc/sys/${param//\.//}"
    if [[ -f "$proc_path" ]]; then
        cat "$proc_path"
        return 0
    fi
    # ...
}
```

When `SYSROOT="/"`, these functions access the real system. When `SYSROOT="testdata/fixtures"`, they access the mock filesystem. This single abstraction enables the entire test suite to run without root and without a live system.

---

## Layer Separation

```
┌──────────────────────────────────────┐
│  Layer 1: CLI / Orchestration        │
│  cisaudit.sh                         │
│  - Parses arguments                  │
│  - Controls execution order          │
│  - Does NOT inspect the system       │
└──────────────────────────────────────┘
           ↓
┌──────────────────────────────────────┐
│  Layer 2: Control Definitions        │
│  controls/registry_data.sh           │
│  - Declares what to check            │
│  - Contains no check logic           │
│  - Pure metadata                     │
└──────────────────────────────────────┘
           ↓
┌──────────────────────────────────────┐
│  Layer 3: Check Functions            │
│  checks/01_initial_setup.sh ...      │
│  - Inspects the system               │
│  - Calls record_result()             │
│  - Does NOT format output            │
└──────────────────────────────────────┘
           ↓
┌──────────────────────────────────────┐
│  Layer 4: Scoring and Reporting      │
│  lib/engine.sh, report_*.sh          │
│  - Computes scores from results      │
│  - Formats output                    │
│  - Does NOT know what was checked    │
└──────────────────────────────────────┘
```

### Why Layers?

- **Testability**: Check functions can be tested against mock filesystems without involving the CLI layer. The scoring engine can be tested with synthetic result data without running any checks.
- **Extensibility**: A new CIS benchmark version means updating Layer 2 (control definitions) and Layer 3 (check functions). Layers 1 and 4 are unchanged.
- **Separation of concerns**: A check function never touches formatting. A reporter never touches the filesystem. Each module has one job.

---

## Data Models

cisaudit uses Bash associative arrays as its data model. There are no external data stores.

### Control Registry (populated by register_control)

```
CTRL_TITLE["1.1.1"]       = "Ensure mounting of cramfs is disabled"
CTRL_SECTION["1.1.1"]     = "Initial Setup"
CTRL_LEVEL["1.1.1"]       = "1"
CTRL_SCORED["1.1.1"]      = "yes"
CTRL_DESCRIPTION["1.1.1"] = "The cramfs filesystem type is..."
CTRL_REMEDIATION["1.1.1"] = "echo 'install cramfs /bin/true' >> ..."
CTRL_CHECK_FN["1.1.1"]    = "check_1_1_1"
REGISTERED_IDS[]           = ("1.1.1" "1.1.2" "1.1.3" ...)
```

### Result Storage (populated by record_result)

```
RESULT_STATUS["1.1.1"]    = "PASS"
RESULT_EVIDENCE["1.1.1"]  = "cramfs disabled via /etc/modprobe.d/cramfs.conf"
RESULT_ORDER[]            = ("1.1.1" "1.1.2" ...)
TOTAL_PASS                = 72
TOTAL_FAIL                = 18
TOTAL_WARN                = 6
TOTAL_SKIP                = 8
```

### Score Aggregation (populated by compute_scores)

```
SECTION_PASS["Initial Setup"]    = 16
SECTION_FAIL["Initial Setup"]    = 2
SCORE_BY_SECTION["Initial Setup"] = "88.9"
SCORE_OVERALL                    = "80.0"
SCORE_LEVEL1                     = "82.5"
SCORE_LEVEL2                     = "75.0"
```

---

## Test Architecture

### Fixture-Based Testing

The test suite runs checks against two mock filesystems:

```
testdata/
├── fixtures/          # Hardened system (most checks PASS)
│   ├── etc/
│   │   ├── modprobe.d/    # cramfs.conf, dccp.conf, etc.
│   │   ├── ssh/sshd_config
│   │   ├── pam.d/
│   │   ├── audit/rules.d/cis.rules
│   │   ├── sysctl.conf
│   │   ├── fstab
│   │   ├── passwd, shadow, group, gshadow
│   │   └── ...
│   └── proc/sys/          # Simulated /proc values
│       ├── kernel/randomize_va_space  (contains "2")
│       ├── net/ipv4/ip_forward        (contains "0")
│       └── ...
│
└── fixtures_fail/     # Unhardened system (most checks FAIL)
    ├── etc/
    │   ├── modprobe.d/    # empty
    │   ├── ssh/sshd_config (PermitRootLogin yes, etc.)
    │   └── ...
    └── proc/sys/          # Insecure values
        ├── net/ipv4/ip_forward  (contains "1")
        └── ...
```

Each `/proc/sys/` parameter is a plain file containing the expected value. The `get_sysctl` function reads the file at `${SYSROOT}/proc/sys/net/ipv4/ip_forward` instead of calling `sysctl -n net.ipv4.ip_forward`. This lets the test fixtures simulate kernel parameters without running on a real kernel.

### Test Framework

The test runner is a custom framework in `test_helpers.sh` with three assertion functions:

```bash
assert_status "1.1.1" "$STATUS_PASS"
assert_evidence_contains "1.1.1" "cramfs disabled"
assert_json_valid "$json_output"
```

Tests follow a consistent pattern:

```bash
test_cramfs_disabled_pass() {
    CURRENT_TEST="test_cramfs_disabled_pass"
    setup_test "${PROJECT_DIR}/testdata/fixtures"
    check_1_1_1
    assert_status "1.1.1" "$STATUS_PASS"
}

test_cramfs_disabled_fail() {
    CURRENT_TEST="test_cramfs_disabled_fail"
    setup_test "${PROJECT_DIR}/testdata/fixtures_fail"
    check_1_1_1
    assert_status "1.1.1" "$STATUS_FAIL"
}
```

Each test resets the result state via `setup_test`, sets `SYSROOT` to the appropriate fixture directory, calls the check function, and asserts the expected status.

---

## Security Architecture

### Threat Model

**What we protect against:**
1. Misconfigured Linux systems going into production without hardening
2. Configuration drift where a system's hardening regresses over time (detected via baseline comparison)
3. Compliance gaps where an organization does not know which CIS controls they pass or fail

**What we do NOT protect against:**
- Runtime exploitation of services (this is an audit tool, not an IDS)
- Active attacks in progress (cisaudit is a point-in-time snapshot, not continuous monitoring)
- Misrepresentation of results (someone could modify fixture files to fake a passing audit)

### Defense in the Tool Itself

- `set -euo pipefail` in every script: fails on undefined variables, pipe errors, and uncaught errors
- `json_escape` and `html_escape` prevent injection in JSON and HTML reports
- `SYSROOT` defaults to `/` so the tool cannot accidentally audit a test fixture when run as root without `-t`
- The tool never modifies the system. It is read-only by design. All check functions use `grep`, `cat`, `stat`, and `sysctl` to inspect without changing state

---

## Design Decisions

### Why Bash?

CIS auditing needs to run on minimal systems where Python, Ruby, or Go might not be installed. Bash 4+ is present on every modern Linux distribution. The tool has zero external dependencies beyond standard GNU utilities (grep, awk, sed, stat, date). This means it can run on a freshly provisioned server before any configuration management or package installation has occurred.

The trade-off is that Bash's associative arrays are slower than hash tables in compiled languages, and string manipulation is verbose. For 104 controls, the performance difference is negligible. The audit completes in under 2 seconds on typical systems.

### Why Not Use Existing Tools?

Tools like OpenSCAP and Lynis provide similar functionality. This project exists as a learning resource that demonstrates how compliance auditing works from first principles. OpenSCAP uses XCCDF/OVAL XML definitions that are difficult to read. Lynis is a monolithic 7000+ line script. cisaudit is intentionally modular and readable so that every design decision is visible.

### Why Associative Arrays Instead of JSON/SQLite?

Bash associative arrays keep the tool dependency-free. Using `jq` for JSON manipulation or `sqlite3` for storage would add external dependencies. The trade-off is that the data model is implicit (arrays must be declared and populated in the right order) rather than schema-enforced. For 104 controls, the simplicity is worth it.

---

## Key Files Reference

Quick map of where to find things:

- `src/cisaudit.sh` - CLI entry point, argument parsing, orchestration
- `src/lib/constants.sh` - All constants (version, colors, status codes, section names)
- `src/lib/registry.sh` - `register_control()` and `record_result()` functions
- `src/lib/engine.sh` - Score computation logic
- `src/lib/utils.sh` - System inspection helpers (`get_sysctl`, `read_file`, `file_exists`)
- `src/controls/registry_data.sh` - All 104 control definitions
- `src/checks/01_initial_setup.sh` - Filesystem and bootloader checks
- `src/checks/03_network.sh` - Network parameter and firewall checks
- `src/lib/report_terminal.sh` - ASCII art terminal report
- `src/lib/report_html.sh` - Standalone HTML report with CSS
- `tests/test_helpers.sh` - Test assertion functions

---

## Next Steps

Now that you understand the architecture:
1. Read [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) for a code walkthrough of each module
2. Try running `cisaudit -t testdata/fixtures -f json | python3 -m json.tool` and trace the output back through the code
