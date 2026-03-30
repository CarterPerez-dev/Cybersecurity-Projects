<!-- © AngelaMos | 2026 | 00-OVERVIEW.md -->

# Linux CIS Hardening Auditor

## What This Is

A command-line tool written entirely in Bash that audits Linux systems against 104 controls from the CIS Debian Linux 12 Benchmark. It checks filesystem hardening, service minimization, network parameters, logging configuration, access controls, and system maintenance. It produces scored compliance reports in terminal, JSON, or HTML format, and it can compare results against a saved baseline to track drift over time.

## Why This Matters

In December 2019, a misconfigured Citrix server (CVE-2019-19781) gave attackers a foothold into hundreds of organizations because basic CIS controls were not enforced. The patch existed. The advisory existed. But the systems were not hardened, and no automated audit caught the exposure before it was exploited. The attackers did not need a zero-day. They needed one server where IP forwarding was enabled, SSH root login was permitted, and audit logging was turned off.

Capital One's 2019 breach exposed 100 million credit applications. The root cause was a misconfigured WAF on an EC2 instance with excessive IAM permissions. But the forensic investigation revealed that basic system hardening controls, the exact kind CIS benchmarks define, were absent on the compromised servers. There was no file integrity monitoring, no restrictive mount options on /tmp, and the audit subsystem was not enabled.

CIS benchmarks exist because security teams kept seeing the same misconfigurations cause breaches. The Center for Internet Security formalized these lessons into prescriptive hardening guides that map directly to regulatory frameworks like NIST 800-53, PCI DSS, SOC 2, and HIPAA. If you run a CIS audit and score 85%, you can tell an auditor exactly which 15% you have not addressed and why. Without a benchmark, you are guessing.

**Real world scenarios where this applies:**
- A SOC analyst needs to verify that newly provisioned servers meet the organization's hardening standard before they go into production
- An incident responder wants to quickly assess whether a compromised host had basic security controls in place when the breach occurred
- A compliance team needs evidence that Linux servers meet CIS Level 1 benchmarks for a SOC 2 Type II audit

## What You'll Learn

This project teaches you how CIS benchmarks translate from PDF documents into automated compliance checks. By building it yourself, you understand what each control actually verifies at the system level.

**Security Concepts:**
- CIS Benchmark structure: how controls are organized into sections, levels, and scored vs. unscored categories
- Linux system hardening: what kernel parameters, mount options, service states, and file permissions matter and why
- Compliance scoring: how to quantify a system's security posture as a percentage and track it over time
- Defense in depth: how 104 small controls layer together to create a hardened system

**Technical Skills:**
- Bash architecture: building a modular CLI tool with a registry pattern, pluggable check functions, and multiple output formatters
- System inspection: reading /proc, parsing config files, checking systemd service states, and querying sysctl values without external dependencies
- Test fixtures: running compliance checks against mock filesystem trees so tests work without root access or a live system

**Tools and Techniques:**
- `sysctl` and `/proc/sys` for reading kernel parameters
- `modprobe` configuration for disabling kernel modules
- `auditd` rules for tracking security-relevant system calls
- PAM configuration for password policies and account lockout
- `iptables` for verifying firewall default policies

## Prerequisites

**Required knowledge:**
- Comfortable reading and writing Bash scripts (functions, arrays, conditionals, string manipulation)
- Basic Linux administration: you know what `/etc/passwd`, `/etc/ssh/sshd_config`, and `systemctl` do
- Understanding of file permissions (owner, group, mode bits like 644 and 600)

**Tools you'll need:**
- Bash 4+ (ships with every modern Linux distribution)
- `just` command runner (optional but recommended for running tasks)
- `shellcheck` for linting (optional, offered during install)

**Helpful but not required:**
- Familiarity with the CIS Benchmark PDF documents (reading them alongside the code makes the controls click faster)
- Experience with `auditd` and PAM configuration

## Quick Start

```bash
cd PROJECTS/beginner/linux-cis-hardening-auditor
./install.sh
sudo cisaudit
```

Expected output: a terminal report showing the CIS ASCII banner, an overall compliance score, a section breakdown table with pass/fail/warn/skip counts and progress bars, and detailed results for each of the 104 controls. Failed controls include evidence explaining what was found and a remediation command.

To run without root access, use the test fixtures:

```bash
cisaudit -t testdata/fixtures -f terminal
```

This runs the full audit against the mock filesystem in `testdata/fixtures/` and produces the same report format. Every control that can be evaluated from config files will produce a result.

## Project Structure

```
linux-cis-hardening-auditor/
├── src/
│   ├── cisaudit.sh              # Entry point: CLI parsing, orchestration
│   ├── lib/
│   │   ├── constants.sh         # Version, colors, status codes, section names
│   │   ├── utils.sh             # Logging, OS detection, file/sysctl helpers
│   │   ├── registry.sh          # Control registration and result recording
│   │   ├── engine.sh            # Score computation per section and level
│   │   ├── report_terminal.sh   # Terminal report with ASCII art and progress bars
│   │   ├── report_json.sh       # Machine-readable JSON report
│   │   ├── report_html.sh       # Standalone HTML report with dark theme
│   │   └── baseline.sh          # Save and diff baselines for drift detection
│   ├── controls/
│   │   └── registry_data.sh     # All 104 control definitions with metadata
│   └── checks/
│       ├── 01_initial_setup.sh  # Filesystem, bootloader, ASLR, core dumps
│       ├── 02_services.sh       # Unnecessary service detection
│       ├── 03_network.sh        # Kernel network params, firewall, protocols
│       ├── 04_logging.sh        # auditd, rsyslog, audit rules
│       ├── 05_access.sh         # cron, SSH configuration
│       ├── 05_access_password.sh # PAM, password policies, account lockout
│       └── 06_maintenance.sh    # File permissions, duplicate UIDs, legacy entries
├── tests/
│   ├── test_runner.sh           # Custom test framework runner
│   ├── test_helpers.sh          # assert_status, assert_evidence_contains
│   └── test_*.sh                # One test file per section + engine/baseline
├── testdata/
│   ├── fixtures/                # Mock filesystem that passes most controls
│   └── fixtures_fail/           # Mock filesystem designed to fail controls
├── install.sh                   # One-command setup with PATH integration
├── Justfile                     # Command runner for audit, test, lint, baseline
└── learn/                       # You are here
```

## Next Steps

1. **Understand the concepts** - Read [01-CONCEPTS.md](./01-CONCEPTS.md) to learn CIS benchmarks, system hardening principles, and the real breaches that motivated these controls
2. **Study the architecture** - Read [02-ARCHITECTURE.md](./02-ARCHITECTURE.md) to see how the registry pattern, check engine, and report formatters fit together
3. **Walk through the code** - Read [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) for a function-by-function walkthrough of the core modules
4. **Extend the project** - Read [04-CHALLENGES.md](./04-CHALLENGES.md) for ideas like adding RHEL support, auto-remediation mode, and Ansible playbook generation

## Common Issues

**"Bash 4+ required" error**
```
[✖] Bash 4+ required (found 3.2.57)
```
Solution: macOS ships with Bash 3.2 due to licensing. Install Bash 5 via `brew install bash` and run with `/opt/homebrew/bin/bash src/cisaudit.sh`.

**Most controls show SKIP in test mode**
Solution: Controls that require live system access (checking running services with `systemctl`, querying `iptables` rules, inspecting running kernel modules with `lsmod`) will skip when using `-t testdata/fixtures` because those commands are not available in test mode. This is expected. File-based checks will still produce PASS/FAIL results.

**Low score on a real system**
Solution: Most Linux installations are not CIS-hardened out of the box. A fresh Debian install typically scores 40-60%. This is normal. Use the remediation commands in the report to harden the system, then re-run the audit.

## Related Projects

If you found this interesting, check out:
- **Firewall Rule Engine** (intermediate) - builds the iptables/nftables rule management that CIS Section 3.3 checks for
- **Network Traffic Analyzer** (beginner) - captures and analyzes the traffic that CIS network controls are designed to restrict
