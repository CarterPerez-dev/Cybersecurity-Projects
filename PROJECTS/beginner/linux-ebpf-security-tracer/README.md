# Linux eBPF Security Tracer

Real-time syscall tracing tool using eBPF for security observability. Monitors process execution, file access, network connections, privilege changes, and system operations to detect suspicious behavior patterns.

## Features

- Real-time syscall monitoring via eBPF tracepoints
- 10 built-in detection rules mapped to MITRE ATT&CK techniques
- Correlated event analysis (reverse shell detection, privilege escalation)
- Multiple output formats: live color-coded stream, JSON, table summary
- Configurable severity filtering (LOW, MEDIUM, HIGH, CRITICAL)
- Process, file, network, privilege, and system event categories
- Event enrichment from /proc filesystem
- Clean signal handling and eBPF program cleanup

## Prerequisites

- Linux kernel 5.8+ (ring buffer support)
- Root privileges (required for eBPF)
- Python 3.10+
- BCC (BPF Compiler Collection) with Python bindings

## Quick Start

```bash
# Install system dependencies and Python packages
./install.sh

# Start tracing all syscalls
sudo uv run ebpf-tracer

# JSON output, only MEDIUM+ severity
sudo uv run ebpf-tracer -f json -s MEDIUM

# Only network events
sudo uv run ebpf-tracer -t network

# Only show detection alerts
sudo uv run ebpf-tracer --detections

# Filter by process name
sudo uv run ebpf-tracer -c nginx

# Write events to file while streaming
sudo uv run ebpf-tracer -o events.jsonl
```

## Usage

```
ebpf-tracer [OPTIONS]

Options:
  -f, --format    Output format: json, table, live     [default: live]
  -s, --severity  Minimum severity: LOW, MEDIUM,       [default: LOW]
                  HIGH, CRITICAL
  -p, --pid       Filter by specific PID
  -c, --comm      Filter by process name
  -t, --type      Event category: process, file,       [default: all]
                  network, privilege, system, all
  --no-enrich     Disable /proc enrichment
  -o, --output    Also write events to file
  --detections    Show only detection alerts
  --version       Show version
  --help          Show help
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

## Architecture

```
User Space
┌─────────┐   ┌──────────────┐   ┌─────────────────┐
│   CLI   │──▶│ Event Engine │──▶│ Output Renderer  │
│ (Typer) │   │ (Processor + │   │ (JSON / Table /  │
│         │   │  Detector)   │   │  Live Stream)    │
└─────────┘   └──────┬───────┘   └─────────────────┘
                     │
              ┌──────┴───────┐
              │  BPF Loader  │
              │  (BCC/Python)│
              └──────┬───────┘
─────────────────────┼──────────────────────────────
Kernel Space         │
              ┌──────┴───────┐
              │  Ring Buffer │
              └──────┬───────┘
     ┌───────────────┼───────────────────┐
     │      eBPF C Tracepoint Programs   │
     │  ┌─────────┐┌────────┐┌─────────┐ │
     │  │ Process ││  File  ││ Network │ │
     │  └─────────┘└────────┘└─────────┘ │
     │  ┌──────────┐┌────────┐           │
     │  │Privilege ││ System │           │
     │  └──────────┘└────────┘           │
     └───────────────────────────────────┘
```

## Monitored Syscalls

| Category | Syscalls | Purpose |
|----------|----------|---------|
| Process | execve, clone | New process creation |
| File | openat, unlinkat, renameat2 | File access and manipulation |
| Network | connect, accept4, bind, listen | Network activity |
| Privilege | setuid, setgid | Privilege changes |
| System | ptrace, mount, init_module | System-level operations |

## Project Structure

```
src/
├── main.py          # CLI entrypoint (Typer)
├── config.py        # Constants, event types, detection rules
├── loader.py        # BCC program loader and ring buffer setup
├── processor.py     # Event parsing, enrichment, filtering
├── detector.py      # Detection engine with stateless and stateful rules
├── renderer.py      # Output formatters (JSON, live, table)
└── ebpf/
    ├── process_tracer.c    # execve, clone tracepoints
    ├── file_tracer.c       # openat, unlinkat, renameat2 tracepoints
    ├── network_tracer.c    # connect, accept4, bind, listen tracepoints
    ├── privilege_tracer.c  # setuid, setgid tracepoints
    └── system_tracer.c     # ptrace, mount, init_module tracepoints
```

## Example Output

### Live Mode (default)

```
[14:30:01] LOW      execve         pid=1234 comm=bash /usr/bin/curl
[14:30:01] CRITICAL connect        pid=1234 comm=nc 10.0.0.1:4444 [Reverse Shell]
[14:30:02] MEDIUM   openat         pid=5678 comm=python3 /etc/shadow [Sensitive File Read]
[14:30:03] HIGH     init_module    pid=9012 comm=insmod [Kernel Module Load]
```

### JSON Mode

```json
{"timestamp":"2026-04-08T14:30:01+00:00","event_type":"connect","pid":1234,"comm":"nc","severity":"CRITICAL","detection":"Reverse Shell","mitre_id":"T1059.004","dest_ip":"10.0.0.1","dest_port":4444}
```

## Development

```bash
# Install dev dependencies
uv sync

# Run unit tests
just test

# Lint
just lint

# Format
just format
```

## How It Works

1. **eBPF C programs** attach to kernel tracepoints for specific syscalls
2. When a traced syscall fires, the eBPF program captures event data (PID, UID, filename, etc.) and pushes it to a shared ring buffer
3. **Python (BCC)** polls the ring buffer and deserializes events via ctypes
4. The **processor** enriches events with data from /proc (parent process, username)
5. The **detection engine** evaluates each event against stateless rules (single-event patterns) and stateful rules (correlated event sequences)
6. The **renderer** outputs events in the selected format with severity-based color coding

## License

MIT
