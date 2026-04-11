```ruby
███████╗██████╗ ██████╗ ███████╗    ████████╗██████╗  █████╗  ██████╗███████╗██████╗
██╔════╝██╔══██╗██╔══██╗██╔════╝    ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗
█████╗  ██████╔╝██████╔╝█████╗         ██║   ██████╔╝███████║██║     █████╗  ██████╔╝
██╔══╝  ██╔══██╗██╔═══╝ ██╔══╝         ██║   ██╔══██╗██╔══██║██║     ██╔══╝  ██╔══██╗
███████╗██████╔╝██║     ██║            ██║   ██║  ██║██║  ██║╚██████╗███████╗██║  ██║
╚══════╝╚═════╝ ╚═╝     ╚═╝            ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝  ╚═╝
```

[![Cybersecurity Projects](https://img.shields.io/badge/Cybersecurity--Projects-Project%20%2322-red?style=flat&logo=github)](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/beginner/linux-ebpf-security-tracer)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![C](https://img.shields.io/badge/C-eBPF-A8B9CC?style=flat&logo=c&logoColor=black)](https://ebpf.io)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)

> Real-time syscall tracing tool using eBPF for security observability — monitors process execution, file access, network connections, privilege changes, and system operations to detect suspicious behavior.

*This is a quick overview — security theory, architecture, and full walkthroughs are in the [learn modules](#learn).*

## What It Does

- Real-time syscall monitoring via eBPF tracepoints (process, file, network, privilege, system)
- 10 built-in detection rules mapped to MITRE ATT&CK techniques
- Correlated event analysis for multi-step attacks (reverse shell detection, privilege escalation chains)
- Multiple output formats: live color-coded stream, JSON, table summary
- Configurable severity filtering (LOW, MEDIUM, HIGH, CRITICAL)
- Event enrichment from /proc filesystem (parent process, username)
- Clean signal handling and eBPF program cleanup

## Quick Start

```bash
./install.sh
sudo uv run ebpf-tracer
```

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` to see all available commands.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## Usage

```bash
sudo uv run ebpf-tracer                       # trace all syscalls (live mode)
sudo uv run ebpf-tracer -f json -s MEDIUM      # JSON output, MEDIUM+ severity
sudo uv run ebpf-tracer -t network             # only network events
sudo uv run ebpf-tracer --detections           # only show detection alerts
sudo uv run ebpf-tracer -c nginx               # filter by process name
sudo uv run ebpf-tracer -o events.jsonl        # write events to file while streaming
```

## Detection Rules

| ID | Name | Severity | MITRE ATT&CK | Trigger |
|----|------|----------|--------------|---------|
| D001 | Privilege Escalation | CRITICAL | T1548 | setuid(0) by non-root |
| D002 | Sensitive File Read | MEDIUM | T1003.008 | /etc/shadow access by non-root |
| D003 | SSH Key Access | MEDIUM | T1552.004 | SSH key file access |
| D004 | Process Injection | MEDIUM | T1055.008 | ptrace ATTACH/SEIZE |
| D005 | Kernel Module Load | HIGH | T1547.006 | init_module syscall |
| D006 | Reverse Shell | CRITICAL | T1059.004 | connect + shell execve sequence |
| D007 | Persistence via Cron | MEDIUM | T1053.003 | Write to cron directories |
| D008 | Persistence via Systemd | MEDIUM | T1543.002 | Write to systemd unit dirs |
| D009 | Log Tampering | MEDIUM | T1070.002 | Log file deletion/truncation |
| D010 | Suspicious Mount | HIGH | T1611 | mount syscall |

## Learn

This project includes step-by-step learning materials covering security theory, architecture, and implementation.

| Module | Topic |
|--------|-------|
| [00 - Overview](learn/00-OVERVIEW.md) | Prerequisites and quick start |
| [01 - Concepts](learn/01-CONCEPTS.md) | eBPF theory and security observability |
| [02 - Architecture](learn/02-ARCHITECTURE.md) | System design and data flow |
| [03 - Implementation](learn/03-IMPLEMENTATION.md) | Code walkthrough |
| [04 - Challenges](learn/04-CHALLENGES.md) | Extension ideas and exercises |

## License

AGPL 3.0
