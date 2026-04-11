# Implementation - Code Walkthrough

## File Structure

```
src/
├── __init__.py
├── main.py          # 140 lines - CLI orchestration
├── config.py        # 180 lines - Constants and rule definitions
├── loader.py        # 130 lines - BCC loading and ring buffer setup
├── processor.py     # 190 lines - Event parsing and enrichment
├── detector.py      # 280 lines - Detection engine
├── renderer.py      # 250 lines - Output formatting
└── ebpf/
    ├── __init__.py
    ├── process_tracer.c   # 70 lines - execve, clone
    ├── file_tracer.c      # 80 lines - openat, unlinkat, renameat2
    ├── network_tracer.c   # 100 lines - connect, accept4, bind, listen
    ├── privilege_tracer.c # 80 lines - setuid, setgid
    └── system_tracer.c    # 80 lines - ptrace, mount, init_module
```

## Building the eBPF Programs

### The Event Struct

Every eBPF program shares the same struct layout. Here's the definition from `process_tracer.c`:

```c
struct event {
    u64 timestamp_ns;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    u32 event_type;
    u32 ret_val;
    char comm[TASK_COMM_LEN];
    char filename[FILENAME_LEN];
    u32 addr_v4;
    u16 port;
    u16 protocol;
    u32 target_uid;
    u32 target_gid;
    u32 ptrace_request;
    u32 target_pid;
};
```

This struct is duplicated in each `.c` file because BCC compiles each file independently, there's no shared header mechanism in BCC's compilation model. The Python side mirrors this with a `ctypes.Structure` in `processor.py`.

Key sizing decisions:
- `comm` is `TASK_COMM_LEN` (16 bytes), the kernel's maximum process name length
- `filename` is 256 bytes, enough for most paths without hitting the 512-byte stack limit
- Network fields use `u32` for IPv4 and `u16` for port, matching `sockaddr_in` layout

### Tracepoint Attachment

The `TRACEPOINT_PROBE` macro is BCC syntactic sugar. When you write:

```c
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    // args->filename gives you the first argument
}
```

BCC generates the attachment code. The `args` struct is auto-generated from the tracepoint format file at `/sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format`. You can inspect it:

```bash
cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
```

### Ring Buffer Usage

The reserve/submit pattern avoids unnecessary memory copies:

```c
BPF_RINGBUF_OUTPUT(events, 1 << 18);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event *e = events.ringbuf_reserve(sizeof(*e));
    if (!e)
        return 0;

    // Fill the struct directly in ring buffer memory
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    // ...

    events.ringbuf_submit(e, 0);
    return 0;
}
```

If `ringbuf_reserve` returns NULL, the buffer is full. The program returns 0 (required by the verifier) and the event is silently dropped. This is a deliberate design choice: dropping events is better than blocking the syscall or crashing.

### Reading Process Context

Getting the current process's parent PID requires reading from `task_struct`:

```c
struct task_struct *task =
    (struct task_struct *)bpf_get_current_task();
bpf_probe_read_kernel(
    &e->ppid, sizeof(e->ppid),
    &task->real_parent->tgid
);
```

`bpf_get_current_task()` returns the current `task_struct` pointer. We can't dereference it directly (verifier would reject it), so we use `bpf_probe_read_kernel()` to safely copy the parent's tgid.

### Network Address Parsing

The network tracer needs to extract IP and port from `sockaddr_in`:

```c
static __always_inline int parse_sockaddr(
    struct event *e, const void *uaddr
) {
    struct sockaddr_in sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), uaddr);

    if (sa.sin_family == AF_INET) {
        e->addr_v4 = sa.sin_addr.s_addr;
        e->port = __builtin_bswap16(sa.sin_port);
        e->protocol = AF_INET;
    }
    return 0;
}
```

The address is in network byte order (big-endian), so we use `__builtin_bswap16` to convert the port to host byte order. The IPv4 address stays in network order and gets converted to dotted notation in Python.

## Building the Python Loader

### BCC Compilation

`loader.py` reads each `.c` file and passes it to BCC:

```python
from bcc import BPF

c_text = src_path.read_text()
bpf = BPF(text=c_text)
bpf["events"].open_ring_buffer(self._callback)
```

BCC compiles the C code using Clang/LLVM at runtime. If there's a syntax error in the C code, it fails here with a compilation error. The compiled eBPF bytecode is automatically loaded into the kernel and attached to the tracepoints declared via `TRACEPOINT_PROBE`.

### Signal Handling

Clean shutdown is critical. eBPF programs stay attached to the kernel until explicitly detached. If the Python process dies without cleanup, the programs keep running (wasting kernel resources) until the BPF objects are garbage collected.

```python
def _handle_stop(signum, frame):
    self._running = False

signal.signal(signal.SIGINT, _handle_stop)
signal.signal(signal.SIGTERM, _handle_stop)

try:
    while self._running:
        for bpf in self._bpf_objects:
            bpf.ring_buffer_poll(timeout=100)
finally:
    self.cleanup()
```

The 100ms poll timeout means the tool checks for shutdown every 100ms. This is a good balance between responsiveness (Ctrl+C works quickly) and CPU usage (not spinning in a tight loop).

## Building the Event Processor

### ctypes Struct Mapping

The `RawEvent` struct mirrors the C layout exactly:

```python
class RawEvent(ctypes.Structure):
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32),
        ("event_type", ctypes.c_uint32),
        ("ret_val", ctypes.c_uint32),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
        ("filename", ctypes.c_char * MAX_FILENAME_LEN),
        ("addr_v4", ctypes.c_uint32),
        ("port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint16),
        ("target_uid", ctypes.c_uint32),
        ("target_gid", ctypes.c_uint32),
        ("ptrace_request", ctypes.c_uint32),
        ("target_pid", ctypes.c_uint32),
    ]
```

Field order and types must match exactly. A mismatch means the Python side reads garbage. The ring buffer callback casts the raw pointer:

```python
raw = ctypes.cast(
    data, ctypes.POINTER(RawEvent)
).contents
```

### Timestamp Conversion

Kernel timestamps from `bpf_ktime_get_ns()` are monotonic nanoseconds since boot, not wall clock time. To convert:

```python
def _boot_time_ns():
    for line in Path("/proc/stat").read_text().splitlines():
        if line.startswith("btime"):
            return int(line.split()[1]) * 1_000_000_000
    return 0

_BOOT_NS = _boot_time_ns()

def _ktime_to_datetime(ktime_ns):
    epoch_ns = _BOOT_NS + ktime_ns
    return datetime.fromtimestamp(
        epoch_ns / 1_000_000_000, tz=timezone.utc
    )
```

`btime` in `/proc/stat` gives the boot time in epoch seconds. Add the kernel nanoseconds to get the wall clock time.

### IPv4 Conversion

The kernel stores IPv4 addresses in network byte order (big endian). Converting to dotted notation:

```python
def _ipv4_to_str(addr):
    if addr == 0:
        return ""
    return ".".join(
        str((addr >> (i * 8)) & 0xFF)
        for i in range(4)
    )
```

For example, `0x0100007F` becomes `127.0.0.1` (byte 0 = 127, byte 1 = 0, byte 2 = 0, byte 3 = 1).

## Building the Detection Engine

### Stateless Rules

Each stateless rule checks a single event against a pattern. The implementation is a series of conditional checks in `_check_stateless()`:

```python
if event.event_type == "setuid":
    if event.target_uid == 0 and event.uid != 0:
        rule = DETECTION_RULES["D001"]
        return Detection(
            rule_id=rule.rule_id,
            name=rule.name,
            severity=rule.severity,
            mitre_id=rule.mitre_id,
            description=rule.description,
        )
```

The rules are data-driven. `DETECTION_RULES` in `config.py` holds the metadata (ID, name, severity, MITRE mapping). The detection engine only contains the matching logic.

### File Path Matching

File-based detections use prefix matching against curated path lists:

```python
SENSITIVE_READ_PATHS = (
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/master.passwd",
)

def _path_matches(filepath, patterns):
    for pattern in patterns:
        if filepath.startswith(pattern):
            return True
    return False
```

Using `startswith` rather than exact match catches paths like `/etc/shadow-` (backup) and `/etc/sudoers.d/custom`.

### Write Detection via Flags

The `openat` syscall's `flags` argument tells us if the file is opened for reading or writing. The eBPF program stores flags in `ret_val`:

```python
O_WRONLY = 1
O_RDWR = 2
O_TRUNC = 512

def _is_write_flags(flags):
    return bool(flags & (O_WRONLY | O_RDWR))
```

This distinguishes reading a cron file (normal) from writing to one (persistence attempt).

### Stateful Correlation

The reverse shell detection maintains a deque per PID:

```python
def _check_stateful(self, event):
    if event.event_type != "execve":
        return None
    if event.comm not in SHELL_BINARIES:
        return None

    hist = self._get_history(event.pid)
    has_connect = any(
        e.event_type == "connect" for e in hist
    )

    if not has_connect:
        ppid_hist = self._history.get(event.ppid)
        if ppid_hist:
            has_connect = any(
                e.event_type == "connect"
                for e in ppid_hist
            )

    if has_connect:
        return Detection(...)
```

The parent PID check handles the case where a process does `connect()` then `fork()` + `execve()`. The shell runs as a child process, so the connect event is in the parent's history.

## Building the Output Renderer

### Live Mode with Rich

```python
class LiveRenderer:
    def render(self, event):
        ts = event.timestamp.strftime("%H:%M:%S")
        color = SEVERITY_COLORS.get(
            event.severity, "white"
        )
        sev = Text(f"{event.severity:8s}", style=color)
        # ... build line with Rich Text objects
        self._console.print(line)
```

Rich's `Text` class supports per-segment styling. CRITICAL events render in bold red, MEDIUM in yellow, LOW in cyan. Detection names appear in bold magenta.

### JSON Mode

```python
class JsonRenderer:
    def render(self, event):
        d = _event_to_dict(event)
        self._stream.write(json.dumps(d) + "\n")
        self._stream.flush()
```

One JSON object per line (JSONL format). `flush()` after each event ensures real-time output when piping to other tools.

## Testing Strategy

### Unit Tests (no root required)

Tests use a `make_event` fixture that creates `TracerEvent` instances without eBPF:

```python
@pytest.fixture()
def make_event():
    def _make(event_type="execve", pid=1000, ...):
        return TracerEvent(
            timestamp=datetime.now(tz=timezone.utc),
            event_type=event_type,
            pid=pid,
            ...
        )
    return _make
```

This lets us test detection rules, filtering, and rendering purely in Python:

```python
def test_setuid_zero_by_nonroot(self, make_event):
    engine = DetectionEngine()
    event = make_event(
        event_type="setuid", uid=1000, target_uid=0,
    )
    result = engine.evaluate(event)
    assert result.detection == "Privilege Escalation"
    assert result.severity == "CRITICAL"
```

### What's Not Tested

Integration tests (loading eBPF programs, tracing real syscalls) require root and a compatible kernel. These can't run in CI. The `@pytest.mark.integration` marker separates them, and `just test` excludes them by default.

## Common Pitfalls

### Pitfall: ctypes Field Order

If the `_fields_` order in `RawEvent` doesn't match the C struct, every field after the mismatch reads wrong data. The symptom is garbage values for seemingly random fields. Always verify field order matches exactly.

### Pitfall: String Decoding

Kernel strings are null-terminated byte arrays. If you forget to split on `\x00`, you'll get trailing garbage bytes in Python:

```python
# Wrong: raw.comm.decode() might include garbage
# Right: split on null first
raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
```

### Pitfall: Network Byte Order

IPv4 addresses and ports come from the kernel in network byte order (big-endian). Ports need `__builtin_bswap16` in C or manual byte swapping in Python. IPv4 addresses can be decomposed byte-by-byte.

### Pitfall: BPF Stack Overflow

The eBPF stack is 512 bytes. The `struct event` alone is ~324 bytes. If you add local variables, you can exceed the limit. The reserve/submit pattern avoids this by writing directly to ring buffer memory instead of using stack-allocated structs.

## Code Organization

### Why No Shared C Header?

BCC compiles each `.c` file independently. There's no `#include "common.h"` mechanism. Each file defines its own copy of `struct event`. This is redundant but matches how BCC works in practice.

### Why config.py Instead of YAML/JSON?

Python constants are type-checked by mypy. They're importable. They don't need a parser. For a tool this size, a config file format adds complexity without benefit.

### Why Dataclass Instead of Pydantic?

`TracerEvent` is a simple data container created thousands of times per second. Pydantic's validation overhead isn't justified when the data source is a trusted kernel ring buffer. Standard `dataclass` is lighter and faster.

## Extending the Code

### Adding a New Syscall Tracer

To trace `mprotect` (memory protection changes, useful for detecting JIT spray attacks):

1. Add `MPROTECT = 15` to `EventType` in `config.py`
2. Add the category mapping: `EventType.MPROTECT: "system"`
3. Add a `TRACEPOINT_PROBE` to `system_tracer.c`:

```c
TRACEPOINT_PROBE(syscalls, sys_enter_mprotect) {
    struct event *e = events.ringbuf_reserve(sizeof(*e));
    if (!e) return 0;
    fill_base(e, 15);
    e->ret_val = args->prot;
    events.ringbuf_submit(e, 0);
    return 0;
}
```

4. Add a detection rule if `prot` includes `PROT_EXEC` on a previously non-executable region.

## Dependencies

| Package | Purpose | Why This One |
|---------|---------|-------------|
| typer | CLI framework | Consistent with repo, auto-help generation |
| rich | Terminal formatting | Color output, tables, text styling |
| bcc | eBPF compilation and loading | Only mature Python eBPF framework |
| pytest | Testing | Standard Python testing framework |
| ruff | Linting | Fast, comprehensive, replaces flake8 |
| mypy | Type checking | Static analysis for Python |
| yapf | Formatting | Repo standard |

BCC is a system package, not pip-installable. Install via `apt install python3-bpfcc` (Debian) or `dnf install python3-bcc` (Fedora).

## Build and Deploy

```bash
# Full setup
./install.sh

# Development
uv sync                    # install Python deps
just lint                  # ruff + mypy
just format                # yapf formatting
just test                  # unit tests (no root)
sudo uv run ebpf-tracer    # run the tool
```

The tool runs in-place, there's no compilation step for the Python code. The eBPF C programs are compiled by BCC at runtime when the tool starts.
