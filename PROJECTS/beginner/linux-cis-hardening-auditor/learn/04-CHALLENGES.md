<!-- © AngelaMos | 2026 | 04-CHALLENGES.md -->

# Extension Challenges

You have built the base project. Now make it yours by extending it with new features.

These challenges are ordered by difficulty. Start with the easier ones to build confidence, then tackle the harder ones when you want to dive deeper.

---

## Easy Challenges

### Challenge 1: CSV Report Output

**What to build:**
Add a `csv` output format that produces a spreadsheet-friendly report.

**Why it's useful:**
Compliance teams live in spreadsheets. A CSV report can be imported into Excel, Google Sheets, or a GRC (Governance, Risk, Compliance) platform for tracking and sign-off workflows. JSON is great for automation, but when an auditor asks for evidence, they want a spreadsheet.

**What you'll learn:**
- How the report strategy pattern works
- CSV escaping (fields containing commas or quotes need to be quoted)
- Adding a new option value to the CLI parser

**Hints:**
- Create `src/lib/report_csv.sh` with an `emit_csv_report` function
- Add `csv` as a case in `generate_report` in `cisaudit.sh`
- Header row: `ID,Section,Title,Level,Scored,Status,Evidence,Remediation`
- Use a `csv_escape` function that wraps fields containing commas or double quotes in double quotes, and doubles any internal double quotes

**Test it works:**
```bash
cisaudit -t testdata/fixtures -f csv -o report.csv
head -5 report.csv
```

### Challenge 2: Control Count Summary

**What to build:**
Add a `--summary` flag that prints a one-line summary instead of the full report.

**Why it's useful:**
CI/CD pipelines need a quick pass/fail answer, not a multi-page report. A summary line like `cisaudit: 82/104 passed (78.8%) Level1=85.2% Level2=68.0%` is easy to parse in shell scripts and log aggregators.

**What you'll learn:**
- Adding a new CLI flag to `parse_args`
- Short-circuiting the report generation

**Hints:**
- Add `OPT_SUMMARY="false"` to the global declarations
- Add a `--summary` case to `parse_args`
- In `main`, after `compute_scores`, check `OPT_SUMMARY` and print the one-liner instead of calling `generate_report`

**Test it works:**
```bash
cisaudit -t testdata/fixtures --summary
```

### Challenge 3: Color Toggle

**What to build:**
Add a `--no-color` flag that disables ANSI color codes in terminal output.

**Why it's useful:**
Piping colored output to a file or another tool produces garbage characters like `[0;32m`. Log aggregation systems, pagers like `less` (without `-R`), and CI logs often render ANSI codes as literal text. A `--no-color` flag makes the output clean for non-terminal use.

**What you'll learn:**
- How ANSI color constants work in `constants.sh`
- Conditional initialization of global variables

**Hints:**
- Add `--no-color` to `parse_args`
- After parsing, if `--no-color` was set, re-declare all color variables as empty strings: `RED=""`, `GREEN=""`, etc.
- Alternatively, detect `[[ ! -t 1 ]]` (stdout is not a terminal) and auto-disable colors

**Test it works:**
```bash
cisaudit -t testdata/fixtures --no-color | cat
cisaudit -t testdata/fixtures -f terminal | less
```

---

## Intermediate Challenges

### Challenge 4: RHEL/CentOS Support

**What to build:**
Extend the check functions to handle Red Hat-based distributions (RHEL, CentOS, Rocky Linux, AlmaLinux) in addition to Debian/Ubuntu.

**Why it's useful:**
CIS publishes separate benchmarks for different distributions, but many controls are identical. Enterprise environments often run both Debian and RHEL systems. A single audit tool that handles both reduces tooling overhead.

**What you'll learn:**
- How package management differs between distributions (dpkg vs rpm)
- Distribution detection from `/etc/os-release`
- Conditional logic based on OS family

**Implementation approach:**

1. **Modify `utils.sh`** to add RHEL-aware functions:
   ```bash
   package_is_installed() {
       case "$DETECTED_ID" in
           debian|ubuntu)
               run_cmd dpkg-query -W -f='${Status}' "$1" | grep -q "install ok installed"
               ;;
           rhel|centos|rocky|almalinux)
               run_cmd rpm -q "$1" &>/dev/null
               ;;
       esac
   }
   ```

2. **Update check functions** where Debian and RHEL differ:
   - PAM configuration paths differ (`/etc/pam.d/common-password` vs `/etc/pam.d/system-auth`)
   - Service names may differ (`rsyslog` is the same, but package names vary)
   - Firewall tools may differ (`iptables` vs `firewalld`)

3. **Add RHEL test fixtures** in `testdata/fixtures_rhel/` with RHEL-style config files

**Hints:**
- Start by making `detect_os` set a `DETECTED_FAMILY` variable (`debian` or `rhel`)
- Modify the package and service helpers first since many checks depend on them
- Add RHEL fixture files and tests incrementally, one section at a time

### Challenge 5: Markdown Report

**What to build:**
Add a `markdown` output format that produces a clean Markdown document suitable for pasting into GitHub issues, Confluence pages, or pull request comments.

**Why it's useful:**
Security review findings are often documented in Markdown. A compliance report in Markdown format can be committed to a repository, attached to a pull request, or pasted into a wiki page for review.

**What you'll learn:**
- Markdown table generation
- How to structure a report format for readability in both raw and rendered form

**Hints:**
- Create `src/lib/report_markdown.sh` with an `emit_markdown_report` function
- Use Markdown tables for the section breakdown
- Use collapsible details blocks (`<details><summary>`) for individual control results
- Failed controls should be expanded by default, passing controls collapsed

**Test it works:**
```bash
cisaudit -t testdata/fixtures -f markdown -o report.md
```

### Challenge 6: Parallel Check Execution

**What to build:**
Run independent check functions in parallel using background jobs to reduce audit time on systems with many controls.

**Why it's useful:**
Some checks involve network operations or file scans that take time. Running independent checks in parallel can cut audit time on large systems from minutes to seconds.

**What you'll learn:**
- Bash background jobs (`&`)
- `wait` for job completion
- Handling shared state (result arrays) with parallel writers
- Temporary file-based result collection to avoid race conditions

**Hints:**
- Checks within different sections are independent and can run in parallel
- Checks within the same section may share state and should run sequentially
- Write results to temporary files (one per check) and merge them after all jobs complete
- Use `mktemp -d` for the temporary result directory and clean it up in a trap

**Gotchas:**
- Bash associative arrays cannot be safely written from multiple background jobs
- You will need to serialize results to temporary files and load them in the parent process

---

## Advanced Challenges

### Challenge 7: Auto-Remediation Mode

**What to build:**
Add a `--fix` flag that applies remediation commands for failed controls after confirmation.

**Why it's useful:**
Going from audit report to hardened system currently requires manually running each remediation command. An auto-remediation mode with confirmation prompts turns a 2-hour manual hardening process into a 10-minute guided session.

**What you'll learn:**
- Dangerous operations and confirmation UX
- Idempotent remediation (applying the same fix twice should not break anything)
- Dry-run mode for previewing changes

**Implementation steps:**

1. **Add `--fix` and `--fix-dry-run` flags** to the CLI parser
2. **After running checks**, iterate failed controls and display the remediation command
3. **Prompt the user** for each control: "Apply fix for 1.1.1 (cramfs)? [y/N/a(ll)]"
4. **Execute remediation** with error handling (some commands require root, some may fail)
5. **Re-run the specific check** after applying the fix to verify it passes
6. **Print a summary** of what was fixed and what still needs manual attention

**Gotchas:**
- Some remediation commands are destructive (modifying GRUB config, changing fstab). Always require confirmation.
- Some remediations require a reboot to take effect (kernel parameters set via sysctl.conf)
- Never auto-fix in non-interactive mode (piped input). Check `[[ -t 0 ]]` before prompting.

### Challenge 8: Ansible Playbook Generation

**What to build:**
Add a `--emit-playbook` flag that generates an Ansible playbook to remediate all failed controls.

**Why it's useful:**
In infrastructure-as-code environments, manual remediation does not persist. The next time the server is provisioned from a base image, all hardening is lost. An Ansible playbook captures the remediation as code that can be applied to every server, reviewed in pull requests, and versioned in Git.

**What you'll learn:**
- YAML generation from structured data
- Ansible module selection (sysctl, lineinfile, service, mount, modprobe)
- Idempotent configuration management concepts

**Architecture changes needed:**

```
┌──────────────────────────┐
│  New: playbook_emitter   │
│  Reads RESULT_STATUS[]   │
│  Maps remediation to     │
│  Ansible modules         │
│  Outputs YAML playbook   │
└──────────────────────────┘
```

**Implementation steps:**

1. **Create a mapping** from CIS control categories to Ansible modules:
   - Kernel modules (1.1.x) → `community.general.modprobe`
   - Mount options (1.2.x) → `ansible.posix.mount`
   - Sysctl parameters (3.x.x) → `ansible.posix.sysctl`
   - SSH config (5.2.x) → `ansible.builtin.lineinfile`
   - Package removal (2.x.x) → `ansible.builtin.apt` with `state: absent`
   - File permissions (6.x.x) → `ansible.builtin.file`

2. **Generate the playbook** with tasks only for failed controls
3. **Include tags** per CIS section so operators can run `ansible-playbook --tags section3` to apply only network hardening

**Hints:**
- Use a heredoc for the playbook header (hosts, become, vars)
- Generate one task per failed control
- Include the CIS control ID in the task name for traceability

### Challenge 9: Configuration Profiles

**What to build:**
Support custom benchmark profiles that override which controls are enabled, their expected values, and their levels.

**Why it's useful:**
Organizations rarely apply the CIS benchmark as-is. A database server might need different SSH settings than a web server. A Docker host cannot disable squashfs. Profiles let teams define "our CIS baseline for web servers" and "our CIS baseline for database servers" as separate configurations.

**What you'll learn:**
- Configuration file parsing in Bash
- Override/inheritance patterns
- Profile composition (base profile + role-specific overrides)

**Implementation approach:**

1. **Define a profile format** (YAML or INI-style config):
   ```ini
   [profile]
   name = web-server
   base = cis-debian-12-l1

   [overrides]
   1.1.6 = skip   # squashfs needed for snap
   1.1.8 = skip   # vfat needed for UEFI
   5.2.5 = skip   # X11 forwarding needed for remote IDE

   [thresholds]
   overall = 80
   section.3 = 90
   ```

2. **Load the profile** before running checks
3. **Apply overrides** in `should_run_check` to skip or modify controls
4. **Support per-section thresholds** in the exit code logic

---

## Expert Challenges

### Challenge 10: Multi-Host Scanning with SSH

**What to build:**
Add the ability to scan remote hosts over SSH, collecting results from multiple servers and generating a consolidated report.

**Why it's useful:**
A security team managing 200 servers cannot log into each one individually. A multi-host scanner runs the audit remotely, collects JSON results, and produces a fleet-wide compliance dashboard showing which servers are out of compliance and on which specific controls.

**Prerequisites:**
Complete Challenge 4 (RHEL support) first since remote hosts may run different distributions.

**What you'll learn:**
- SSH-based remote command execution
- Parallel remote job management
- Result aggregation from multiple sources
- Fleet-level compliance scoring

**Implementation phases:**

**Phase 1: Remote execution**
- Accept a host list file (`--hosts hosts.txt`)
- SSH to each host, copy cisaudit, run it with `-f json`, and collect the output
- Handle SSH authentication (key-based only, never passwords)

**Phase 2: Result aggregation**
- Parse JSON results from each host
- Compute per-host scores and a fleet-wide average
- Identify controls that fail across multiple hosts (systemic issues)

**Phase 3: Consolidated reporting**
- Generate a fleet report showing per-host scores in a table
- Highlight controls with the highest failure rate across the fleet
- Export as HTML with a host-level drill-down

**Gotchas:**
- SSH connections can fail. Handle timeouts and unreachable hosts gracefully
- Different hosts may have different Bash versions. Ship cisaudit as a self-contained script
- Rate-limit parallel SSH connections to avoid overloading the network or triggering IDS alerts

### Challenge 11: Continuous Compliance Monitoring

**What to build:**
A systemd service and timer that runs cisaudit on a schedule, stores results, and sends alerts when compliance regresses.

**Why it's useful:**
Point-in-time audits catch problems but do not prevent drift. A server that passes CIS today can be misconfigured tomorrow by a package update, a manual change, or a configuration management failure. Continuous monitoring catches drift within hours instead of waiting for the next quarterly audit.

**What you'll learn:**
- systemd service and timer unit files
- Result storage and trend analysis
- Alert integration (email, Slack webhook, syslog)
- Time-series compliance data

**Implementation steps:**

1. **Create a systemd timer** that runs cisaudit daily:
   ```ini
   [Timer]
   OnCalendar=daily
   Persistent=true
   ```

2. **Store results** in a directory like `/var/lib/cisaudit/` with timestamped JSON files

3. **Compare against the previous run** using the baseline module

4. **Send alerts** when:
   - Overall score drops below a threshold
   - A previously passing control starts failing (regression)
   - A new control appears with FAIL status

5. **Generate a weekly summary** showing the compliance trend

**Success criteria:**
- [ ] systemd timer runs cisaudit daily
- [ ] Results are stored with timestamps
- [ ] Regressions trigger alerts
- [ ] A CLI command shows the compliance trend over the last 30 days

---

## Security Challenges

### Challenge: Pass CIS Level 2

**The goal:**
Take a fresh Debian 12 installation and use cisaudit to achieve 100% compliance on Level 2.

**Current gaps on a fresh install:**
- Filesystem modules are not disabled
- /tmp is not a separate partition
- Bootloader has no password
- Most services are in default configuration
- Audit rules are not configured
- SSH allows root login
- Password policies use defaults

**Approach:**
1. Run `sudo cisaudit -l 2 -f json -o baseline-fresh.json`
2. Work through each failed control using the remediation commands
3. Re-run after each section to track progress
4. Document which Level 2 controls you had to skip and why

**Watch out for:**
- Disabling vfat breaks UEFI boot on some systems
- Disabling squashfs breaks snap packages
- Setting aggressive password policies can lock you out if you are not careful
- Some audit rules generate large volumes of log data

---

## Real World Integration Challenges

### Integrate with Wazuh

**The goal:**
Send cisaudit results to a Wazuh SIEM for centralized compliance monitoring.

**What you'll need:**
- A Wazuh server (can be deployed with Docker)
- Understanding of Wazuh's log collection and rule engine

**Implementation plan:**
1. Output cisaudit results as syslog-formatted messages
2. Configure Wazuh agent to read cisaudit logs
3. Create Wazuh rules that generate alerts for CIS failures
4. Build a Wazuh dashboard showing compliance posture across hosts

### Integrate with Prometheus/Grafana

**The goal:**
Expose cisaudit scores as Prometheus metrics for visualization in Grafana.

**Implementation plan:**
1. Add a `prometheus` output format that emits metrics in OpenMetrics format
2. Write a textfile collector script that runs cisaudit and writes metrics to `/var/lib/node_exporter/textfile_collector/`
3. Create a Grafana dashboard with compliance gauges per section and a trend line over time

**Metrics to expose:**
```
cisaudit_score_overall{hostname="web01"} 82.5
cisaudit_score_section{section="Initial Setup"} 88.9
cisaudit_controls_pass{hostname="web01"} 72
cisaudit_controls_fail{hostname="web01"} 18
```

---

## Challenge Completion

Track your progress:

- [ ] Easy Challenge 1: CSV Report
- [ ] Easy Challenge 2: Control Count Summary
- [ ] Easy Challenge 3: Color Toggle
- [ ] Intermediate Challenge 4: RHEL/CentOS Support
- [ ] Intermediate Challenge 5: Markdown Report
- [ ] Intermediate Challenge 6: Parallel Execution
- [ ] Advanced Challenge 7: Auto-Remediation
- [ ] Advanced Challenge 8: Ansible Playbook Generation
- [ ] Advanced Challenge 9: Configuration Profiles
- [ ] Expert Challenge 10: Multi-Host SSH Scanning
- [ ] Expert Challenge 11: Continuous Monitoring
- [ ] Security Challenge: Pass CIS Level 2
- [ ] Integration: Wazuh
- [ ] Integration: Prometheus/Grafana

Completed all of them? You have built a production-grade compliance platform. Consider contributing enhancements back to the project or using the patterns you learned to build compliance tooling for other benchmarks (CIS AWS, CIS Kubernetes, CIS Docker).
