```ruby
 ██████╗██╗███████╗ █████╗ ██╗   ██╗██████╗ ██╗████████╗
██╔════╝██║██╔════╝██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
██║     ██║███████╗███████║██║   ██║██║  ██║██║   ██║
██║     ██║╚════██║██╔══██║██║   ██║██║  ██║██║   ██║
╚██████╗██║███████║██║  ██║╚██████╔╝██████╔╝██║   ██║
 ╚═════╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝
```

[![Cybersecurity Projects](https://img.shields.io/badge/Cybersecurity--Projects-Project%20%2321-red?style=flat&logo=github)](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/beginner/linux-cis-hardening-auditor)
[![Bash](https://img.shields.io/badge/Bash-4%2B-4EAA25?style=flat&logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)

> CIS Benchmark compliance auditor for Linux systems with scored reporting, baseline comparison, and remediation guidance.

*This is a quick overview — security theory, architecture, and full walkthroughs are in the [learn modules](#learn).*

## What It Does

- Audit Linux systems against 104 CIS Benchmark controls (Debian/Ubuntu)
- Check filesystem hardening, services, network parameters, logging, SSH, and user accounts
- Generate scored compliance reports in terminal, JSON, or HTML format
- Compare results against a saved baseline to detect regressions and improvements
- Provide specific remediation commands for every failed control
- Support Level 1 and Level 2 benchmark profiles
- Run in test mode against mock fixtures without root access

## Quick Start

```bash
./install.sh
sudo cisaudit
```

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` to see all available commands.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## Commands

| Command | Description |
|---------|-------------|
| `sudo cisaudit` | Run full audit with terminal output |
| `sudo cisaudit -l 1` | Audit Level 1 controls only |
| `sudo cisaudit -f json -o report.json` | Generate JSON report |
| `sudo cisaudit -f html -o report.html` | Generate HTML report |
| `sudo cisaudit -c 5` | Audit only Section 5 (Access/Auth) |
| `cisaudit --list-controls` | List all 104 registered controls |
| `sudo cisaudit -s baseline.json` | Save current results as baseline |
| `sudo cisaudit -b baseline.json` | Compare against a previous baseline |
| `cisaudit -t testdata/fixtures` | Run against test fixtures (no root needed) |

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-l, --level` | `all` | Benchmark level: `1`, `2`, or `all` |
| `-f, --format` | `terminal` | Output format: `terminal`, `json`, `html` |
| `-o, --output` | stdout | Write report to file |
| `-c, --categories` | `all` | Categories to audit: `1,2,3,4,5,6` |
| `-t, --test-root` | `/` | System root for testing |
| `--threshold` | `0` | Minimum pass % to exit 0 |
| `-q, --quiet` | off | Suppress progress output |

## CIS Benchmark Sections

| # | Section | Controls |
|---|---------|----------|
| 1 | Initial Setup | 20 |
| 2 | Services | 18 |
| 3 | Network Configuration | 20 |
| 4 | Logging and Auditing | 18 |
| 5 | Access, Authentication and Authorization | 18 |
| 6 | System Maintenance | 10 |
| | **Total** | **104** |

## Examples

```bash
sudo cisaudit -l 1 -f json -o report.json

sudo cisaudit -c 3,5 -f terminal

sudo cisaudit -s baselines/march.json
sudo cisaudit -b baselines/march.json

cisaudit -t testdata/fixtures -f json | python3 -m json.tool
```

## Learn

This project includes step-by-step learning materials covering security theory, architecture, and implementation.

| Module | Topic |
|--------|-------|
| [00 - Overview](learn/00-OVERVIEW.md) | Prerequisites and quick start |
| [01 - Concepts](learn/01-CONCEPTS.md) | CIS benchmarks, real breaches, and compliance frameworks |
| [02 - Architecture](learn/02-ARCHITECTURE.md) | System design, module layout, and data flow |
| [03 - Implementation](learn/03-IMPLEMENTATION.md) | Code walkthrough with file references |
| [04 - Challenges](learn/04-CHALLENGES.md) | Extension ideas and exercises |

## License

AGPL 3.0
