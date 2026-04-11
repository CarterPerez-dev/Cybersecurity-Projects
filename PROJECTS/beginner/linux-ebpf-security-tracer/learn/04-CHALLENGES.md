# Challenges - Extend the eBPF Security Tracer

## Easy Challenges

### 1. Add IPv6 Support

**What to build**: Extend the network tracer to parse `sockaddr_in6` and display IPv6 addresses.

**Why it's useful**: Many modern services and cloud environments use IPv6. Attackers can use IPv6 to bypass IPv4-only monitoring.

**What you'll learn**: IPv6 address structure, handling multiple address families in eBPF, expanding the event struct.

**Hints**:
- Add a `u8 addr_v6[16]` field to the event struct
- Check `sa.sin_family == AF_INET6` in `parse_sockaddr`
- Use Python's `ipaddress.IPv6Address(bytes(addr_v6))` for conversion
- Don't forget to update the ctypes `RawEvent` definition

**Test it works**: Run `curl -6 http://ipv6.google.com` while tracing and verify the IPv6 address appears in output.

### 2. Add Process Ancestry Chain

**What to build**: For each event, walk up the process tree (via /proc/<pid>/status) to show the full ancestry: `bash -> python -> curl`.

**Why it's useful**: Knowing that a suspicious `connect` came from `systemd -> sshd -> bash -> python -> nc` tells a much richer story than just "nc connected somewhere."

**What you'll learn**: /proc filesystem, process tree walking, performance tradeoffs of enrichment.

**Hints**:
- Read `/proc/<pid>/status` and parse the `PPid:` line
- Walk up until PID 1 or a read error
- Cache results aggressively, process trees don't change often
- Consider a max depth (8-10) to avoid pathological cases

**Test it works**: Run `bash -c "python3 -c 'import os; os.system(\"ls\")'` and verify the ancestry chain appears.

### 3. Add an Event Counter Summary

**What to build**: When the tool exits (Ctrl+C), print a summary table showing total events by type, total detections by severity, and top 10 processes by event count.

**Why it's useful**: After a tracing session, you want a quick overview of what happened without scrolling through thousands of events.

**What you'll learn**: Data aggregation, Rich table formatting, clean shutdown patterns.

**Hints**:
- Add counters to the event processing pipeline (use `collections.Counter`)
- Register a cleanup function that prints the summary
- The `TableRenderer` already shows how to use Rich tables

**Test it works**: Run the tracer for 30 seconds on a busy system, then Ctrl+C and verify the summary appears.

## Intermediate Challenges

### 4. Add Container-Aware Detection

**What to build**: Detect whether events originate from inside a container and include the container ID in the output. Flag kernel module loads and mount operations from containers as CRITICAL.

**Why it's useful**: Container escapes are a major attack vector in Kubernetes. Detecting `mount` or `init_module` from inside a container namespace is a strong indicator of an escape attempt.

**What you'll learn**: Linux namespaces, cgroups, container runtime detection, how containers are just processes with extra isolation.

**Hints**:
- Read `/proc/<pid>/cgroup` to detect container membership
- Docker containers have cgroup paths like `/docker/<container_id>`
- Kubernetes pods have paths like `/kubepods/pod<uid>/<container_id>`
- PID 1 inside a container maps to a regular PID on the host
- Add a `container_id` field to `TracerEvent`

**Test it works**: Run `docker run --rm alpine sh -c "ls /etc"` while tracing and verify the container ID appears. Test that `mount` from a container triggers a CRITICAL detection.

### 5. Add Rate-Based Anomaly Detection

**What to build**: Detect abnormal syscall rates. If a process makes more than N `openat` calls in T seconds (e.g., 100 opens in 5 seconds), flag it as "Rapid File Scanning."

**Why it's useful**: Automated tools scanning for credentials, sensitive files, or exploitable configurations generate distinctive patterns of rapid file access that normal usage doesn't produce.

**What you'll learn**: Sliding window rate calculation, threshold-based anomaly detection, tuning false positive rates.

**Hints**:
- Use the existing per-PID deque in the detection engine
- Count events of each type in the window
- Start with high thresholds to avoid noise, then tune down
- Consider different thresholds per event type (openat is naturally high-volume, ptrace is not)
- Add a `D011` rule to `DETECTION_RULES`

**Test it works**: Write a script that opens 200 files in a loop and verify the detection triggers. Verify that normal `ls` of a large directory does not trigger it.

### 6. Add Syslog/JSON-over-UDP Output

**What to build**: Add an output mode that sends events to a remote syslog server or as JSON over UDP.

**Why it's useful**: In production, you'd feed eBPF events into a SIEM (Splunk, Elastic, Wazuh). UDP/syslog is the simplest integration point.

**What you'll learn**: Network programming in Python, syslog protocol (RFC 5424), structured logging for SIEM integration.

**Hints**:
- `socket.socket(socket.AF_INET, socket.SOCK_DGRAM)` for UDP
- Syslog format: `<priority>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID MSG`
- Map severity levels to syslog priorities (CRITICAL -> LOG_CRIT, etc.)
- Add `--syslog host:port` CLI option

**Test it works**: Run `nc -ul 1514` in one terminal, start the tracer with `--syslog localhost:1514`, and verify events arrive.

## Advanced Challenges

### 7. Add eBPF-Level Filtering

**What to build**: Move PID and comm filtering into the eBPF programs so filtered events never reach userspace. Currently, all events flow through the ring buffer and get filtered in Python.

**Why it's useful**: On a busy server generating 50K+ events per second, userspace filtering wastes ring buffer bandwidth. eBPF-level filtering reduces overhead by 10-100x for filtered workloads.

**What you'll learn**: BPF hash maps for configuration, passing filter state from Python to eBPF, verifier-safe conditional logic.

**Hints**:
- Use `BPF_HASH(pid_filter, u32, u32)` as a set of PIDs to include
- Populate the map from Python: `b["pid_filter"][ctypes.c_uint32(pid)] = ctypes.c_uint32(1)`
- In the eBPF program, check: `if (pid_filter.lookup(&pid) == NULL) return 0;`
- For comm filtering, use `BPF_HASH(comm_filter, char[16], u32)`
- An empty filter map means "trace all"

**Test it works**: Benchmark event rate with and without eBPF-level filtering on a process spawning 1000 child processes per second. Measure CPU usage difference.

### 8. Build a Real-Time Dashboard

**What to build**: A terminal-based dashboard using Rich's Live display that shows: event rate graph, active detections, top processes, and a scrolling event log, all updating in real time.

**Why it's useful**: Operational security monitoring needs at-a-glance visibility. A dashboard lets you watch system behavior during incident response without reading individual log lines.

**What you'll learn**: Rich Live and Layout for TUI design, concurrent data aggregation, refresh rate management.

**Hints**:
- Use `rich.live.Live` with `rich.layout.Layout` for multi-panel display
- Update every 500ms (2 FPS is enough for human readability)
- Track event rate with a 1-second rolling window
- Use `rich.panel.Panel` for each section
- Consider `rich.progress.SparklineColumn` for rate visualization

**Test it works**: Run the dashboard on a system under load (e.g., `stress-ng --cpu 4 --io 4`) and verify all panels update correctly.

## Expert Challenges

### 9. Build a Detection Rule DSL

**What to build**: Replace the hardcoded detection logic in `detector.py` with a rule engine that loads detection rules from YAML files, similar to Falco's rule format:

```yaml
- rule: Reverse Shell Detected
  condition:
    sequence:
      - event_type: connect
        within: 10s
      - event_type: execve
        comm_in: [sh, bash, dash, zsh]
    group_by: pid
  severity: CRITICAL
  mitre: T1059.004
  description: Shell execution following outbound connection
```

**Why it's useful**: Hardcoded detection rules require code changes and redeployment. A DSL lets security teams write and modify rules without touching Python code, which is how Falco, Sigma, and YARA work.

**What you'll learn**: Rule engine design, YAML schema validation, temporal pattern matching, DSL design principles.

**Hints**:
- Start with stateless rules (single event matching) before tackling sequences
- Use Pydantic for rule schema validation
- Support operators: `eq`, `in`, `startswith`, `regex`, `gt`, `lt`
- For sequence rules, reuse the existing deque-based correlation but make it configurable
- Add `--rules-dir` CLI option to load rules from a directory
- Consider rule priorities (first match vs best match)

**Test it works**: Port all 10 existing detection rules to YAML. Verify all existing tests still pass against the YAML-loaded rules. Add a custom rule and verify it detects correctly.

## Mix and Match

- **Container + Rate Anomaly**: Detect rapid file scanning inside containers (strong indicator of container reconnaissance before an escape attempt)
- **IPv6 + Syslog**: Full-stack monitoring with IPv6 support piped to a SIEM
- **Dashboard + eBPF Filtering**: High-performance dashboard that only shows filtered events

## Real World Integration

- **Wazuh**: Pipe JSON output to Wazuh's `ossec.log` or use the API for real-time event ingestion
- **Elastic SIEM**: Send JSONL output to Filebeat, which ships it to Elasticsearch
- **Grafana/Loki**: Use promtail to ship events, build dashboards for event rates and detection counts
- **Slack/PagerDuty**: Add a webhook renderer that sends CRITICAL detections to Slack or triggers PagerDuty incidents

## Performance Challenges

### Benchmark and Optimize

1. Generate load with `stress-ng --syscall 0 --timeout 60s`
2. Measure events/second throughput
3. Profile with `py-spy` to find Python bottlenecks
4. Target: handle 50K+ events/second without dropping events

### Ring Buffer Tuning

1. Start with 256KB ring buffer
2. Under load, check drop rate (add a lost event callback)
3. Experiment with 512KB, 1MB, 4MB buffers
4. Find the minimum buffer size that achieves zero drops for your workload

## Security Challenges

### Add File Integrity Monitoring

Monitor writes to critical system files (`/etc/passwd`, `/etc/sudoers`, `/etc/ssh/sshd_config`) and alert on any modification. This is what tools like AIDE and Tripwire do, but in real time.

### Add Network Allowlist/Denylist

Maintain a list of expected outbound connections per process. Alert when a process connects to an IP or port not in its allowlist. Start with a learning mode that auto-generates the allowlist.

### Add Anti-Evasion Detection

Detect processes that try to evade tracing: renaming themselves to look like system processes, forking rapidly to confuse PID-based tracking, or using `prctl(PR_SET_NAME)` to change their comm.

## Contribution Ideas

- Port the eBPF programs from BCC to libbpf for production readiness
- Add eBPF LSM hooks for enforcement (block, not just detect)
- Build a web UI with WebSocket-based real-time event streaming
- Add Sigma rule format support (industry standard detection rules)
- Create systemd unit file for running as a daemon

## Challenge Completion

- [ ] Easy 1: IPv6 Support
- [ ] Easy 2: Process Ancestry Chain
- [ ] Easy 3: Event Counter Summary
- [ ] Intermediate 4: Container-Aware Detection
- [ ] Intermediate 5: Rate-Based Anomaly Detection
- [ ] Intermediate 6: Syslog/UDP Output
- [ ] Advanced 7: eBPF-Level Filtering
- [ ] Advanced 8: Real-Time Dashboard
- [ ] Expert 9: Detection Rule DSL

## Getting Help

**Debugging eBPF programs**: Add `bpf_trace_printk("debug: %d\n", value)` to your C code and read output with `sudo cat /sys/kernel/debug/tracing/trace_pipe`. This is the printf-debugging equivalent for eBPF.

**Verifier errors**: The eBPF verifier prints cryptic messages. Common causes: unbounded loop, memory access without bounds check, stack overflow (>512 bytes). Reduce struct sizes or use BPF maps for large data.

**BCC issues**: If BCC fails to compile, check that kernel headers match your running kernel: `uname -r` should match a directory in `/lib/modules/`.

**Community resources**:
- [iovisor/bcc GitHub Issues](https://github.com/iovisor/bcc/issues) - BCC-specific questions
- [eBPF Slack](https://ebpf.io/slack) - Community chat
- [Brendan Gregg's Blog](https://www.brendangregg.com/blog/) - eBPF performance analysis
