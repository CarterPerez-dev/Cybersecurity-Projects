# eBPF Security Tracer - Overview

## What This Is

A real-time Linux syscall tracer built on eBPF that monitors process execution, file access, network connections, privilege changes, and system operations. It evaluates events against detection rules mapped to MITRE ATT&CK techniques and outputs color-coded alerts.

## Why This Matters

Traditional security monitoring relies on log aggregation after the fact. By the time you check syslog, an attacker may have already wiped it. eBPF lets you observe syscalls as they happen, at the kernel level, with near-zero overhead. This is how modern security tools like Falco, Tetragon, and Tracee work under the hood.

### Real World Scenarios

1. **Incident Response**: During a live breach, you need to see what processes are running, what files they're touching, and where they're connecting. This tool provides that visibility in real time without deploying a full SIEM stack.

2. **Server Hardening Validation**: After locking down a production server, run the tracer to verify that only expected processes access sensitive files like `/etc/shadow` or SSH keys. Any unexpected access triggers an alert.

3. **Container Security**: In Kubernetes environments, containers should never load kernel modules or mount host filesystems. eBPF-based tracing catches these escape attempts at the syscall level before they succeed.

## What You'll Learn

### Security Concepts
- Syscall-level observability and why it matters for defense
- MITRE ATT&CK technique identification from raw syscall data
- Detection engineering: turning syscall patterns into security rules
- Behavioral analysis vs signature-based detection

### Technical Skills
- Writing eBPF C programs that attach to kernel tracepoints
- Using BCC (BPF Compiler Collection) Python bindings
- Ring buffer architecture for kernel-to-userspace communication
- Event correlation with sliding window algorithms
- Structured security event output (JSON, severity classification)

### Tools
- BCC framework and eBPF compilation pipeline
- Python CLI tooling with Typer and Rich
- ruff, mypy, yapf for code quality
- uv for Python package management

## Prerequisites

### Required Knowledge
- Basic Linux administration (processes, files, permissions, networking)
- Python fundamentals (functions, classes, data structures)
- Some familiarity with C syntax (the eBPF programs are small but you need to read them)
- Understanding of what system calls are (even if you've never traced them)

### Required Tools
- Linux with kernel 5.8+ (check with `uname -r`)
- Root access (eBPF requires CAP_SYS_ADMIN)
- Python 3.10+
- uv package manager
- BCC tools (installed via `install.sh`)

### Nice to Have
- Familiarity with strace or ltrace
- Basic networking concepts (TCP/IP, sockets)
- Experience with security monitoring or SIEM tools

## Quick Start

```bash
git clone https://github.com/CarterPerez-dev/Cybersecurity-Projects.git
cd Cybersecurity-Projects/PROJECTS/beginner/linux-ebpf-security-tracer

# Install everything
./install.sh

# Start tracing
sudo uv run ebpf-tracer

# In another terminal, trigger a detection:
cat /etc/shadow    # triggers "Sensitive File Read"
```

Expected output:

```
eBPF Security Tracer v1.0.0
Format: live | Min severity: LOW | Type: all
Press Ctrl+C to stop

[14:30:01] LOW      execve         pid=1234 comm=bash /usr/bin/cat
[14:30:01] MEDIUM   openat         pid=1234 comm=cat /etc/shadow [Sensitive File Read]
```

## Project Structure

```
src/
├── main.py          # CLI entrypoint
├── config.py        # All constants and detection rule metadata
├── loader.py        # BCC loader, ring buffer setup, signal handling
├── processor.py     # Raw event parsing, enrichment, filtering
├── detector.py      # Detection engine (stateless + stateful rules)
├── renderer.py      # Output formatters (JSON, live, table)
└── ebpf/            # eBPF C programs compiled by BCC at runtime
    ├── process_tracer.c
    ├── file_tracer.c
    ├── network_tracer.c
    ├── privilege_tracer.c
    └── system_tracer.c
```

## Next Steps

- [01-CONCEPTS.md](01-CONCEPTS.md) - eBPF fundamentals, syscall tracing, security observability
- [02-ARCHITECTURE.md](02-ARCHITECTURE.md) - System design, ring buffers, detection pipeline
- [03-IMPLEMENTATION.md](03-IMPLEMENTATION.md) - Code walkthrough of each module
- [04-CHALLENGES.md](04-CHALLENGES.md) - Extension ideas and challenges

## Common Issues

**"Error: eBPF tracing requires root privileges"**
Run with sudo: `sudo uv run ebpf-tracer`. eBPF programs need CAP_SYS_ADMIN to load.

**"Kernel X.Y detected. Requires 5.8+"**
Your kernel is too old for ring buffer support. Upgrade your kernel or use a VM/container with a newer kernel.

**"BCC Python bindings not found"**
Install the system package: `sudo apt install python3-bpfcc` (Debian/Ubuntu) or `sudo dnf install python3-bcc` (Fedora). BCC is not pip-installable, it must come from your distro's package manager.

## Related Projects

- [Simple Port Scanner](../../simple-port-scanner/) - Network reconnaissance basics
- [Simple Vulnerability Scanner](../../simple-vulnerability-scanner/) - Vulnerability identification
- [Linux CIS Hardening Auditor](../../linux-cis-hardening-auditor/) - System hardening
