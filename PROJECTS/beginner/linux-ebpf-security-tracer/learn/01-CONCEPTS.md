# Concepts - eBPF, Syscalls, and Security Observability

## eBPF: Programmable Kernel Observability

### What It Is

eBPF (extended Berkeley Packet Filter) is a technology that lets you run small programs inside the Linux kernel without writing a kernel module or modifying the kernel source. Think of it as a safe, sandboxed scripting language for the kernel.

When you load an eBPF program, the kernel's verifier checks it for safety (no infinite loops, no out-of-bounds memory access, no crashing the kernel), then JIT-compiles it to native machine code. This means eBPF programs run at near-native speed with strong safety guarantees.

### Why It Matters for Security

Before eBPF, you had two options for kernel-level visibility:

1. **Kernel modules** - Full access, but a bug crashes the system. Loading untrusted code into the kernel is inherently risky.
2. **System call tracing (strace/ptrace)** - Safe but slow. ptrace-based tracing introduces 10-100x overhead on traced processes.

eBPF gives you kernel-level visibility with user-space safety. The performance overhead is typically under 1%, and the verifier guarantees your program can't crash the kernel.

This is why every major cloud security tool released since 2020 (Falco, Tetragon, Tracee, Datadog's runtime security) uses eBPF as its foundation.

### How It Works

```
Your Python Script
      │
      ▼
  BCC Compiler
  (Clang/LLVM)
      │
      ▼
 eBPF Bytecode
      │
      ▼
 Kernel Verifier ──▶ Rejects unsafe programs
      │
      ▼
 JIT Compiler
      │
      ▼
 Native Machine Code
 (attached to tracepoint)
      │
      ▼
 Fires on every matching syscall
      │
      ▼
 Ring Buffer ──▶ Your Python callback
```

### BCC vs libbpf

There are two main frameworks for writing eBPF programs:

**BCC (BPF Compiler Collection)** compiles your eBPF C code at runtime using Clang/LLVM. The advantage is rapid development: you write C code as a Python string, load it, and go. The disadvantage is that every host needs LLVM and kernel headers installed, and each program uses ~80MB of memory.

**libbpf with CO-RE** (Compile Once, Run Everywhere) compiles your eBPF program once at build time. The binary works across kernel versions thanks to BTF (BPF Type Format) metadata. Production tools like Tetragon use this approach because it's lighter (~9MB) and doesn't need compiler toolchains on production hosts.

This project uses BCC because we're building a learning tool, not a production agent. The Python API makes the code readable, and runtime compilation lets you experiment without a build step.

## System Calls: The Kernel's Front Door

### What System Calls Are

Every interaction between a user-space program and the kernel goes through system calls. When `cat` reads a file, it calls `openat()` to get a file descriptor, `read()` to get the contents, and `write()` to print to stdout. When `curl` connects to a server, it calls `socket()`, `connect()`, and `read()`.

There's no way around this. Even if malware is fully in-memory, even if it's written in assembly, it still needs to make syscalls to do anything useful. This makes syscall tracing a powerful detection mechanism that's very hard to evade.

### Security-Relevant Syscalls

Not all ~300+ Linux syscalls matter for security. Here are the ones this tool traces and why:

**Process execution** - `execve` fires every time a new program runs. This is the most important syscall for security monitoring. Almost every attack involves executing something, whether it's a shell, a payload, or a legitimate tool being abused.

**File access** - `openat` shows which files processes are reading or writing. An attacker reading `/etc/shadow` or writing to `/etc/cron.d/` tells a clear story.

**Network activity** - `connect` reveals outbound connections. A web server suddenly connecting to an IP in Eastern Europe on port 4444 is a red flag. `bind` and `listen` show processes opening ports for inbound connections (bind shells).

**Privilege changes** - `setuid` and `setgid` show privilege transitions. A process calling `setuid(0)` to become root is exactly what privilege escalation looks like.

**System operations** - `ptrace` is used for debugging but also for process injection (MITRE ATT&CK T1055.008). `mount` can indicate container escape attempts. `init_module` loads kernel modules, which is how rootkits install themselves.

### The Syscall Tracing Surface

```
User Space Process
        │
        │  execve("/bin/bash", ...)
        │  openat("/etc/shadow", O_RDONLY)
        │  connect(sockfd, {ip=10.0.0.1, port=4444})
        │  setuid(0)
        │
        ▼
  ┌─────────────────────────┐
  │   Syscall Entry Point   │◀── eBPF tracepoint here
  │   (kernel boundary)     │
  └─────────────────────────┘
        │
        ▼
  Kernel implementation
```

## Detection Engineering

### From Syscalls to Security Alerts

A single syscall in isolation is rarely suspicious. `openat` fires thousands of times per second on a busy system. The art of detection engineering is identifying which patterns, either single events with unusual parameters or sequences of events, indicate malicious activity.

### Stateless Detection

Some events are suspicious on their own:

- `setuid(0)` called by a process running as UID 1000 is almost always an escalation attempt
- `openat("/etc/shadow")` by a Python script is worth investigating
- `init_module()` loading a kernel module is always notable
- `ptrace(PTRACE_ATTACH, target_pid)` is a code injection primitive

These are "stateless" detections because each event is evaluated independently.

### Stateful Detection (Event Correlation)

Other threats only become visible when you correlate multiple events:

**Reverse shell pattern**: An attacker on a compromised server needs to get an interactive shell back to their machine. The classic approach:

```
1. socket(AF_INET, SOCK_STREAM)    # create TCP socket
2. connect(sockfd, attacker_ip)     # connect to attacker
3. dup2(sockfd, 0)                  # redirect stdin to socket
4. dup2(sockfd, 1)                  # redirect stdout to socket
5. dup2(sockfd, 2)                  # redirect stderr to socket
6. execve("/bin/bash")              # spawn shell
```

No single syscall here is suspicious. Programs create sockets and connect to servers all the time. Shells are spawned constantly. But a `connect` followed by a shell `execve` from the same PID within seconds is a strong reverse shell indicator.

This tool implements this as a stateful rule: it maintains a sliding window of recent events per PID. When a shell execve arrives, it checks if there was a recent `connect` from the same PID or its parent.

### Real World Examples

**2021 Log4Shell (CVE-2021-44228)**: The initial exploit triggered a JNDI lookup that downloaded and executed a payload. From a syscall perspective: the Java process (unexpected) called `connect()` to an external LDAP server, downloaded a class file, and then `execve()` spawned a shell. eBPF-based tools detected this in real time while WAFs were still being updated with signatures.

**2020 SolarWinds Supply Chain Attack**: The compromised Orion software made unusual outbound connections to `avsvmcloud.com`. Syscall tracing would have shown the Orion process calling `connect()` to DNS/HTTP endpoints that weren't in its normal communication pattern.

**Kubernetes Container Escapes**: CVE-2022-0185 exploited a heap overflow in the kernel's filesystem context handling. The exploit sequence involved `mount()` syscalls with crafted parameters from within a container, something that eBPF-based tools like Tetragon are specifically designed to catch.

## MITRE ATT&CK Mapping

The MITRE ATT&CK framework provides a common language for categorizing adversary behavior. This tool maps each detection rule to specific ATT&CK techniques:

| Detection | Technique | Tactic |
|-----------|-----------|--------|
| Privilege Escalation | T1548 - Abuse Elevation Control | Privilege Escalation |
| Sensitive File Read | T1003.008 - /etc/passwd and /etc/shadow | Credential Access |
| SSH Key Access | T1552.004 - Private Keys | Credential Access |
| Process Injection | T1055.008 - Ptrace System Calls | Defense Evasion |
| Kernel Module Load | T1547.006 - Kernel Modules | Persistence |
| Reverse Shell | T1059.004 - Unix Shell | Execution |
| Persistence via Cron | T1053.003 - Cron | Persistence |
| Log Tampering | T1070.002 - Clear Linux Logs | Defense Evasion |

## Common Pitfalls

### Pitfall: Assuming Syscall Names Are Stable

System call naming varies between architectures and kernel versions. On x86_64, `open()` was replaced by `openat()` as the primary file-opening syscall. Always use the tracepoint interface (`syscalls:sys_enter_openat`) rather than kprobes on raw syscall functions, because tracepoints are stable ABI.

### Pitfall: Ignoring Event Volume

On a busy server, `execve` and `openat` fire hundreds of times per second. A detection engine that does expensive processing per event will fall behind. This tool uses a ring buffer (not perf buffer) and keeps detection logic simple for this reason.

### Pitfall: Over-Alerting

If every `openat` of `/etc/passwd` triggers an alert, operators will disable the tool within a day. Good detection engineering means understanding what's normal. Root reading `/etc/shadow` is expected (PAM does this for every login). A Python script reading it is unusual. Context matters.

## How Concepts Connect

```
eBPF Programs ──────────────────┐
(C code in kernel)              │
  │                             │
  │ capture syscall args        │ compile + load
  │                             │
  ▼                             │
Ring Buffer ◀───────────────────┘
  │                        via BCC Python
  │ events flow to
  │ user space
  ▼
Detection Engine
  │
  │ evaluate against rules
  │ correlate sequences
  │
  ▼
MITRE ATT&CK Mapping
  │
  │ classify severity
  │
  ▼
Alert Output
```

## Industry Standards

- **MITRE ATT&CK for Linux** - Framework for categorizing adversary behavior on Linux systems
- **NIST SP 800-137** - Information Security Continuous Monitoring, which eBPF-based tools directly support
- **CIS Controls v8, Control 8** - Audit Log Management. eBPF tracing provides the raw audit data

## Testing Your Understanding

1. Why can't malware avoid syscall-based detection by using direct kernel memory access from user space?

2. You see this sequence from PID 4521: `socket(AF_INET, SOCK_STREAM)`, then `connect(10.0.0.5:443)`, then `execve("/usr/bin/curl")`. Is this a reverse shell? Why or why not?

3. A detection rule triggers on every `openat("/etc/passwd")`. On a server with 100 users logging in per hour, how many false positives per hour would you expect? How would you reduce them?

4. What's the difference between attaching an eBPF program to a kprobe vs a tracepoint? Which is more reliable for production use?

## Further Reading

### Essential
- [ebpf.io](https://ebpf.io) - Official eBPF documentation and learning resources
- [BCC Reference Guide](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md) - API reference for all BCC features
- [MITRE ATT&CK for Linux](https://attack.mitre.org/matrices/enterprise/linux/) - Full technique matrix

### Deep Dive
- [Learning eBPF by Liz Rice](https://www.oreilly.com/library/view/learning-ebpf/9781098135119/) - Comprehensive book on eBPF programming
- [BPF Performance Tools by Brendan Gregg](https://www.brendangregg.com/bpf-performance-tools-book.html) - Reference for eBPF-based system analysis
- [Falco Rules Repository](https://github.com/falcosecurity/rules) - See how a production tool defines detection rules
