# Architecture - System Design and Technical Decisions

## High Level Architecture

```
┌────────────────────────────────────────────────────────┐
│                      User Space                        │
│                                                        │
│  ┌─────────┐                                           │
│  │  main.py │ CLI entrypoint                           │
│  │  (Typer) │ parses args, wires components            │
│  └────┬─────┘                                          │
│       │                                                │
│       ▼                                                │
│  ┌──────────┐   ┌─────────────┐   ┌────────────────┐  │
│  │loader.py │──▶│processor.py │──▶│  renderer.py   │  │
│  │          │   │             │   │                │  │
│  │ Compiles │   │ Parses raw  │   │ JSON / Live /  │  │
│  │ & loads  │   │ events,     │   │ Table output   │  │
│  │ eBPF C   │   │ enriches    │   │                │  │
│  │ programs │   │ from /proc  │   └────────────────┘  │
│  │          │   │             │                        │
│  │ Sets up  │   │ Filters by  │                        │
│  │ ring buf │   │ severity,   │                        │
│  │ callback │   │ PID, comm   │   ┌────────────────┐  │
│  └──────────┘   │             │──▶│  detector.py   │  │
│                 └─────────────┘   │                │  │
│                                   │ Stateless      │  │
│                                   │ rules +        │  │
│                                   │ stateful       │  │
│                                   │ correlation    │  │
│                                   └────────────────┘  │
├────────────────────────────────────────────────────────┤
│                     Kernel Space                       │
│                                                        │
│  ┌──────────────────────────────────────────────┐      │
│  │              Ring Buffer (shared)            │      │
│  │         BPF_RINGBUF_OUTPUT, 256KB            │      │
│  └──────────┬──────────┬──────────┬─────────────┘      │
│             │          │          │                     │
│  ┌──────────┴───┐ ┌────┴────┐ ┌──┴──────────┐         │
│  │process_tracer│ │file_    │ │network_     │         │
│  │   .c        │ │tracer.c │ │tracer.c     │         │
│  │             │ │         │ │             │         │
│  │ sys_enter_  │ │sys_enter│ │sys_enter_   │         │
│  │ execve      │ │_openat  │ │connect      │         │
│  │ sys_enter_  │ │sys_enter│ │sys_enter_   │         │
│  │ clone       │ │_unlinkat│ │accept4      │         │
│  │             │ │sys_enter│ │sys_enter_   │         │
│  │             │ │_rename  │ │bind/listen  │         │
│  └─────────────┘ └─────────┘ └─────────────┘         │
│  ┌─────────────┐ ┌─────────────┐                      │
│  │privilege_   │ │system_      │                      │
│  │tracer.c     │ │tracer.c     │                      │
│  │             │ │             │                      │
│  │sys_enter_   │ │sys_enter_   │                      │
│  │setuid       │ │ptrace       │                      │
│  │sys_enter_   │ │sys_enter_   │                      │
│  │setgid       │ │mount        │                      │
│  │             │ │sys_enter_   │                      │
│  │             │ │init_module  │                      │
│  └─────────────┘ └─────────────┘                      │
└────────────────────────────────────────────────────────┘
```

## Component Breakdown

### main.py - CLI and Orchestration
Parses command line arguments via Typer and wires together the loader, processor, detector, and renderer. Handles signal-based shutdown. This is the thinnest layer: it contains no business logic, just plumbing.

### loader.py - eBPF Program Lifecycle
Reads `.c` files from the `ebpf/` directory, compiles them via BCC, attaches them to kernel tracepoints, and sets up ring buffer polling. Also handles cleanup: detaching eBPF programs and freeing BPF objects when the tool stops.

### processor.py - Event Parsing and Enrichment
Defines `RawEvent` (a ctypes Structure mirroring the C struct) and `TracerEvent` (a Python dataclass with enriched fields). Converts raw bytes from the ring buffer into structured Python objects. Enriches events with data from `/proc` (parent process name, username resolution). Implements filtering logic.

### detector.py - Detection Engine
Contains all security detection logic. Stateless rules evaluate individual events (e.g., "is this a setuid(0) by non-root?"). Stateful rules correlate events across time using a per-PID sliding window (e.g., "was there a connect before this shell execve?"). Returns Detection objects that get stamped onto events.

### renderer.py - Output Formatting
Three output modes. `LiveRenderer` uses Rich for color-coded streaming. `JsonRenderer` writes one JSON object per line to stdout. `TableRenderer` buffers events and periodically renders Rich tables. `FileRenderer` writes JSON to a file alongside any other output mode.

### config.py - Constants and Rule Metadata
All magic numbers, file paths, detection rule definitions, severity levels, and event type mappings live here. Nothing is hardcoded elsewhere. Changing a detection rule's severity or adding a new sensitive file path only requires editing this file.

### ebpf/*.c - Kernel-Space Programs
Five C files, one per syscall category. Each defines a `TRACEPOINT_PROBE` that fires on the corresponding `syscalls:sys_enter_*` event. Programs capture event data into a shared struct and push it to the ring buffer. The C code is intentionally minimal, all detection logic stays in Python.

## Data Flow

### Step by Step: From Syscall to Alert

```
1. Process calls execve("/bin/bash")
       │
2. Kernel hits tracepoint syscalls:sys_enter_execve
       │
3. eBPF program (process_tracer.c) fires:
   - Reserves space in ring buffer
   - Fills struct: pid, ppid, uid, comm, filename, timestamp
   - Submits to ring buffer
       │
4. Python callback (on_event in main.py) fires:
   - parse_raw_event() casts raw bytes to RawEvent ctypes struct
   - Converts to TracerEvent dataclass
   - Decodes comm/filename from null-terminated bytes
   - Converts kernel timestamp to wall clock datetime
   - Resolves UID to username via pwd module
       │
5. enrich_event() adds parent process name from /proc
       │
6. detector.evaluate() checks:
   - Stateless: Is the event itself suspicious? No.
   - Stateful: Is this a shell? Yes (bash). Was there a
     recent connect from this PID? Check history deque.
     If yes -> Detection("Reverse Shell", CRITICAL)
       │
7. should_include() applies user's filters:
   - Severity >= minimum? PID matches? Comm matches?
       │
8. renderer.render() outputs:
   [14:30:01] CRITICAL  execve  pid=1234 comm=bash
              /bin/bash [Reverse Shell]
```

## Design Patterns

### Pattern: Kernel Simplicity, Userspace Complexity

The eBPF C programs do the bare minimum: read syscall arguments, fill a struct, push to ring buffer. All the interesting work (detection, correlation, enrichment, formatting) happens in Python.

Why? eBPF programs run inside the kernel with strict constraints:
- 512-byte stack limit
- No dynamic memory allocation
- No string manipulation beyond `bpf_probe_read_*`
- The verifier rejects anything complex

Moving logic to userspace also means you can change detection rules without recompiling eBPF programs, and you can unit test detection logic without root privileges.

### Pattern: Single Event Struct

All five eBPF programs use the same `struct event` layout, even though not every field is relevant to every event type. A process event doesn't need `addr_v4` and a network event doesn't need `filename`, but they share the same struct.

This seems wasteful (the struct is ~300 bytes with mostly-zero fields for most events), but it has major advantages:
- One `RawEvent` ctypes definition in Python, not five
- One ring buffer callback, not five
- Simpler code, fewer bugs

The alternative (per-type structs with discriminated unions) would save memory but add complexity that isn't justified at this scale.

### Pattern: Deque-Based Correlation

The detection engine maintains a `collections.deque` per PID with a max length. Events older than the correlation window are pruned on each evaluation. This gives O(1) append and O(n) scanning where n is small (max 64 events per PID, 10-second window).

For a tool tracing a typical server, this means ~1000 deques in memory (one per active PID), each holding a few events. Total memory for correlation: a few megabytes at most.

### Trade-offs

**Ring buffer vs perf buffer**: Ring buffer (used here) requires kernel 5.8+ but provides event ordering guarantees and lower overhead via the reserve/submit zero-copy API. Perf buffer works on older kernels (4.4+) but has per-CPU allocation waste and no ordering guarantee.

**BCC vs libbpf**: BCC requires LLVM on the host and uses ~80MB per tool. libbpf with CO-RE produces ~9MB standalone binaries. For a learning tool, BCC's Python API and iterative development experience win. For production, you'd switch to libbpf.

**Tracepoints vs kprobes**: Tracepoints are stable ABI, they won't break between kernel versions. Kprobes hook arbitrary kernel functions and can break when internal APIs change. This tool uses tracepoints exclusively.

## Data Models

### RawEvent (C struct / ctypes)

| Field | Type | Bytes | Purpose |
|-------|------|-------|---------|
| timestamp_ns | u64 | 8 | Kernel monotonic clock |
| pid | u32 | 4 | Process ID |
| ppid | u32 | 4 | Parent process ID |
| uid | u32 | 4 | User ID |
| gid | u32 | 4 | Group ID |
| event_type | u32 | 4 | Enum: EXECVE=1...INIT_MODULE=14 |
| ret_val | u32 | 4 | Return value or flags |
| comm | char[16] | 16 | Process name (TASK_COMM_LEN) |
| filename | char[256] | 256 | File path or device name |
| addr_v4 | u32 | 4 | IPv4 address (network order) |
| port | u16 | 2 | Port number (host order) |
| protocol | u16 | 2 | Address family (AF_INET=2) |
| target_uid | u32 | 4 | Target UID for setuid |
| target_gid | u32 | 4 | Target GID for setgid |
| ptrace_request | u32 | 4 | ptrace operation type |
| target_pid | u32 | 4 | Target PID for ptrace |
| **Total** | | **324** | |

### TracerEvent (Python dataclass)

Extends RawEvent with:
- `timestamp` as `datetime` (converted from kernel nanoseconds)
- `username` resolved from UID
- `severity`, `detection`, `detection_id`, `mitre_id` from detection engine
- `extra` dict for enrichment data (parent_comm, etc.)

## Security Architecture

### Privilege Model
The tool requires root (CAP_SYS_ADMIN) to load eBPF programs. It checks at startup with `os.geteuid()` and exits with a clear message if not root.

### eBPF Safety
The kernel verifier ensures eBPF programs cannot:
- Access memory outside their stack or BPF maps
- Execute unbounded loops
- Call arbitrary kernel functions
- Crash the kernel

### Cleanup
Signal handlers (SIGINT, SIGTERM) trigger clean shutdown. The `TracerLoader.cleanup()` method calls `bpf.cleanup()` on each BPF object, which detaches tracepoints and frees kernel resources. A `try/finally` block in `main.py` ensures cleanup runs even on exceptions.

### Input Validation
The tool reads from kernel ring buffers (trusted) and /proc (trusted). There's no user input beyond CLI arguments, which Typer validates via type annotations.

## Configuration

All configuration lives in `config.py` as module-level constants:

| Setting | Value | Purpose |
|---------|-------|---------|
| RING_BUFFER_BYTES | 256KB | Size of shared ring buffer |
| CORRELATION_WINDOW_SEC | 10 | Sliding window for stateful detection |
| MAX_EVENTS_PER_PID | 64 | Max events in correlation deque |
| MIN_KERNEL_MAJOR/MINOR | 5.8 | Minimum kernel version |
| SENSITIVE_READ_PATHS | /etc/shadow, etc. | Files that trigger D002 |
| SHELL_BINARIES | sh, bash, etc. | Binaries that count as "shells" |

## Performance Considerations

**Ring buffer sizing**: 256KB is enough for typical workloads. Under extreme syscall rates (>100K/sec), events may be dropped when `ringbuf_reserve` returns NULL. Increase `RING_BUFFER_BYTES` for high-throughput environments.

**Event enrichment**: Reading `/proc/<pid>/comm` for every event adds latency. The `--no-enrich` flag disables this for high-volume scenarios.

**Username caching**: UID-to-username resolution uses a dict cache to avoid repeated `pwd.getpwuid()` calls.

**Detection engine**: Stateless rules are O(1) per event. Stateful rules scan the deque, which is bounded at 64 entries, so worst case is O(64) comparisons.

## Design Decisions

### Why Python, not Go or Rust?

BCC has mature, well-documented Python bindings. Go bindings exist (via cilium/ebpf) but use libbpf, not BCC. Rust has libbpf-rs. For a beginner project focused on teaching eBPF concepts, Python lets readers focus on the eBPF and security concepts rather than language complexity.

### Why one ring buffer, not per-tracer?

Each BPF program gets its own `BPF_RINGBUF_OUTPUT`, but they all use the same struct layout and the same Python callback. This keeps the callback logic simple. The alternative (per-tracer callbacks with per-tracer structs) would require five separate parsing paths.

### Why tracepoints, not raw_tracepoints?

Raw tracepoints provide a `bpf_raw_tp_args` struct with fewer abstractions. They're slightly faster but harder to work with, you need to manually cast arguments. Standard tracepoints provide `args->` access with named fields, which is much more readable for a learning project.

### Why Typer for CLI?

Consistency with other projects in the repository. Typer provides automatic help generation, type validation, and shell completion with minimal code.

## Extensibility

### Adding a New Syscall

1. Add the event type to `EventType` enum in `config.py`
2. Add it to `EVENT_TYPE_CATEGORIES`
3. Write a `TRACEPOINT_PROBE` in the appropriate `.c` file (or create a new one)
4. If it needs a new detection rule, add to `DETECTION_RULES` and implement in `detector.py`

### Adding a New Detection Rule

1. Add a `DetectionRule` entry to `DETECTION_RULES` in `config.py`
2. Implement the check in `_check_stateless()` or `_check_stateful()` in `detector.py`
3. Add a test in `test_detector.py`

### Adding a New Output Format

1. Create a new renderer class in `renderer.py` with a `render(event)` method
2. Add the format name to the `OutputFormat` literal type in `config.py`
3. Handle it in `create_renderer()`

## Limitations

- **IPv6**: Network tracer only parses IPv4 (`sockaddr_in`). IPv6 support would require handling `sockaddr_in6` and a 128-bit address field.
- **Container awareness**: No container ID or namespace detection. Adding this would require reading `/proc/<pid>/cgroup` or using BPF helpers for namespace IDs.
- **Argument capture**: Only the first argument (filename) is captured for execve. Full argv capture requires reading the pointer array, which is complex in eBPF due to verifier constraints.
- **File descriptor tracking**: The tool doesn't track fd-to-file mappings, so it can't correlate a `connect()` fd with a subsequent `dup2()` call.
- **No persistence**: Events are not stored. For historical analysis, pipe JSON output to a file or a log aggregation system.

## Comparison with Production Tools

| Feature | This Tool | Falco | Tetragon | Tracee |
|---------|-----------|-------|----------|--------|
| eBPF backend | BCC (Python) | libs (C) | libbpf (Go) | libbpf (Go) |
| Syscall coverage | 14 | 50+ | 30+ | 40+ |
| Detection rules | 10 | 100+ | Policy-based | 70+ |
| Enforcement | Detect only | Detect only | Detect + block | Detect only |
| Container awareness | No | Yes | Yes | Yes |
| Memory usage | ~80MB | ~50MB | ~30MB | ~60MB |
| Production ready | No (learning) | Yes | Yes | Yes |

This tool is a learning resource. It teaches the same fundamentals that power Falco and Tetragon, but at a scale where every line of code is readable and understandable.
