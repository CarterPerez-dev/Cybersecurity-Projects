# Implementation Guide

This document walks through the actual code. We'll build key features step by step and explain the decisions along the way.

## File Structure Walkthrough

```
network-traffic-analyzer/
├── src/netanal/
│   ├── __init__.py          # Package exports, version info
│   ├── __main__.py          # Entry point for python -m netanal
│   ├── main.py              # Typer CLI commands (capture, analyze, export, chart)
│   ├── capture.py           # Producer-consumer packet capture engine
│   ├── analyzer.py          # Protocol dissection using Scapy layers
│   ├── filters.py           # Type-safe BPF filter builder
│   ├── statistics.py        # Thread-safe statistics aggregation
│   ├── models.py            # Data models (PacketInfo, Protocol, CaptureStatistics)
│   ├── visualization.py     # Matplotlib chart generation
│   ├── export.py            # JSON/CSV serialization
│   ├── output.py            # Rich console formatting
│   ├── constants.py         # Configuration constants
│   └── exceptions.py        # Custom exception hierarchy
├── tests/
│   ├── test_filters.py      # FilterBuilder validation tests
│   └── test_models.py       # Data model tests
└── pyproject.toml           # Dependencies and build config
```

## Building the Packet Capture Engine

### Step 1: Producer-Consumer Setup

What we're building: A capture engine that receives packets from Scapy at wire speed while processing them in a separate thread without dropping data.

The core challenge is that packets arrive asynchronously at unpredictable rates. If processing blocks the capture thread, packets get dropped. The solution is a producer-consumer pattern with a bounded queue.

From `capture.py:31-62`:

```python
class CaptureEngine:
    def __init__(
        self,
        config: CaptureConfig,
        on_packet: Callable[[PacketInfo], None] | None = None,
        queue_size: int = CaptureDefaults.QUEUE_SIZE,
    ) -> None:
        self._config = config
        self._on_packet = on_packet
        self._queue: Queue[Packet] = Queue(maxsize = queue_size)
        self._stats = StatisticsCollector()
        self._sniffer: AsyncSniffer | None = None
        self._processor_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._packet_count = 0
        self._dropped_packets = 0
        self._running = False
        self._count_lock = threading.Lock()
```

**Why this code works:**

- **Queue[Packet]**: Bounded buffer between threads. `maxsize = 10000` means if queue fills, producer drops packets rather than blocking. This prevents capture thread from slowing down.

- **StatisticsCollector**: Separate object handles all metrics. Keeps capture logic separate from statistics logic.

- **threading.Event**: stop_event signals both threads when it's time to shut down. Better than flags because Event.wait() is interruptible.

- **Lock**: _count_lock protects _packet_count and _dropped_packets which both threads modify. Without it, race conditions corrupt the counts.

**Common mistakes here:**

```python
# Wrong: unbounded queue
self._queue = Queue()  # Can grow to gigabytes, OOM kills process

# Wrong: no lock on counters
self._packet_count += 1  # Race condition, loses counts

# Wrong: boolean flag for shutdown
self._should_stop = False  # Thread.join() with timeout is better
```

### Step 2: Producer Thread Setup

Now we need to start Scapy's AsyncSniffer as the producer.

In `capture.py:92-131`:

```python
def start(self) -> None:
    if self._running:
        return
    
    self._running = True
    self._stop_event.clear()
    
    with self._count_lock:
        self._packet_count = 0
        self._dropped_packets = 0
    
    self._stats.reset()
    self._stats.start()
    
    self._processor_thread = threading.Thread(
        target = self._process_packets,
        daemon = True,
    )
    self._processor_thread.start()
    
    sniffer_kwargs: dict[str, object] = {
        "prn": self._enqueue_packet,
        "store": self._config.store_packets,
    }
    
    if self._config.interface:
        sniffer_kwargs["iface"] = self._config.interface
    
    if self._config.bpf_filter:
        sniffer_kwargs["filter"] = self._config.bpf_filter
    
    self._sniffer = AsyncSniffer(**sniffer_kwargs)
    self._sniffer.start()
```

**What's happening:**

1. Check _running flag to prevent double-start (would create duplicate threads)
2. Reset counters and statistics to zero (clean slate for new capture)
3. Start consumer thread BEFORE producer (so queue has a consumer when packets arrive)
4. Build sniffer_kwargs dict conditionally (only include non-None config values)
5. Pass _enqueue_packet as callback (`prn` parameter)
6. AsyncSniffer.start() spawns producer thread internally

**Why we do it this way:**

Starting consumer before producer prevents queue overflow during initialization. If producer runs first and consumer thread hasn't started yet, queue fills immediately.

Daemon threads automatically exit when main program exits. Non-daemon threads would keep program alive even after user Ctrl+C's.

**Alternative approaches:**

- **Approach A**: Use `sniff(prn=callback)` - Works but blocks main thread, can't display progress or respond to signals
- **Approach B**: Use `sniff(timeout=1)` in loop - Introduces gaps where packets can be dropped between timeout and restart

### Step 3: Producer Callback

The producer callback runs in Scapy's capture thread for every packet.

In `capture.py:64-70`:

```python
def _enqueue_packet(self, packet: Packet) -> None:
    try:
        self._queue.put_nowait(packet)
    except Full:
        with self._count_lock:
            self._dropped_packets += 1
```

This handles [specific responsibility]: Adding packets to queue without blocking. `put_nowait()` raises Full exception if queue is full. We catch it and increment dropped counter instead of crashing.

**Key parts explained:**

The reason we use `put_nowait()` instead of `put()` is performance. `put()` blocks until space available, which would slow capture to consumer's processing speed. Better to drop packets than slow capture.

The lock on _dropped_packets prevents lost increment operations. If two threads read-modify-write simultaneously without a lock, one increment gets lost.

## Building Protocol Identification

### The Problem

Scapy packets are nested layer objects. We need to identify the highest-level protocol and extract relevant fields without hardcoding every possible protocol combination.

### The Solution

Walk through layers from highest (application) to lowest (link), returning first match.

### Implementation

In `analyzer.py:14-48`:

```python
def identify_protocol(packet: Packet) -> Protocol:
    if packet.haslayer(DNS):
        return Protocol.DNS
    
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        if tcp_layer.dport == Ports.HTTP or tcp_layer.sport == Ports.HTTP:
            return Protocol.HTTP
        if tcp_layer.dport == Ports.HTTPS or tcp_layer.sport == Ports.HTTPS:
            return Protocol.HTTPS
        return Protocol.TCP
    
    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        if udp_layer.dport == Ports.DNS or udp_layer.sport == Ports.DNS:
            return Protocol.DNS
        return Protocol.UDP
    
    if packet.haslayer(ICMP):
        return Protocol.ICMP
    
    if packet.haslayer(ARP):
        return Protocol.ARP
    
    return Protocol.OTHER
```

**Key parts explained:**

**DNS detection first** (`analyzer.py:14-15`)
DNS can run over TCP or UDP. Check for DNS layer before checking transport protocol, otherwise DNS over TCP would be classified as just TCP.

**Port-based protocol detection** (`analyzer.py:20-25`)
HTTP and HTTPS are just TCP with specific ports. Check port numbers to classify further. Both source and destination ports are checked because server responses have HTTP/HTTPS as source port.

**Fallback to OTHER** (`analyzer.py:45`)
Unknown protocols don't crash the analyzer. They're classified as OTHER and counted separately in statistics.

The order matters: application layer protocols (DNS, HTTP) are identified before transport layer (TCP, UDP). This gives more specific classification.

### Testing This Feature

```python
from scapy.layers.inet import IP, TCP
from scapy.layers.dns import DNS
from netanal.analyzer import identify_protocol
from netanal.models import Protocol

# Test HTTP detection
http_packet = IP()/TCP(dport=80)
assert identify_protocol(http_packet) == Protocol.HTTP

# Test DNS detection
dns_packet = IP()/UDP()/DNS()
assert identify_protocol(dns_packet) == Protocol.DNS
```

Expected output: Both assertions pass, showing protocol identification works correctly.

If you see Protocol.TCP for HTTP, it means port checking failed. Verify the port is actually 80 in the packet.

## Thread-Safe Statistics Collection

### The Problem

Multiple threads update the same statistics simultaneously. Without synchronization, counters lose increments and dicts get corrupted.

### The Solution

Use a single lock to protect all shared state. Critical sections (code under lock) stay as short as possible.

### Implementation

File: `statistics.py:47-67`

```python
def record_packet(self, packet: PacketInfo) -> None:
    with self._lock:
        self._total_packets += 1
        self._total_bytes += packet.size
        self._interval_packets += 1
        self._interval_bytes += packet.size
        
        self._protocol_counts[packet.protocol] += 1
        self._protocol_bytes[packet.protocol] += packet.size
        
        self._update_endpoint(packet.src_ip, sent_bytes = packet.size)
        self._update_endpoint(
            packet.dst_ip,
            received_bytes = packet.size
        )
        
        self._update_conversation(
            packet.src_ip,
            packet.dst_ip,
            packet.size
        )
        
        self._check_bandwidth_sample(packet.timestamp)
```

**What this prevents:**

Lost increments. Without the lock:
```
Thread A reads total_packets = 100
Thread B reads total_packets = 100  
Thread A writes 101
Thread B writes 101  # Lost an increment!
```

With lock, operations are atomic:
```
Thread A acquires lock
Thread A reads 100, writes 101
Thread A releases lock
Thread B acquires lock (waits until A finishes)
Thread B reads 101, writes 102
```

**How it works:**

1. `with self._lock:` acquires the lock, blocking if another thread holds it
2. All counter updates happen atomically
3. Helper methods (_update_endpoint, etc) run under the same lock
4. Lock automatically releases when exiting the with block (even on exception)

**What happens if you remove this:**

Run the code under high load. Counters will be lower than actual packet count because increments get lost. Protocol distribution percentages won't add to 100%. Endpoint statistics will have incorrect totals.

### Bandwidth Sampling

Every second, we need to calculate current bandwidth. This runs under the same lock for consistency.

From `statistics.py:112-127`:

```python
def _check_bandwidth_sample(self, timestamp: float) -> None:
    if timestamp - self._last_sample_time >= self._bandwidth_interval:
        elapsed = timestamp - self._last_sample_time
        if elapsed > 0:
            bps = self._interval_bytes / elapsed
            pps = self._interval_packets / elapsed
            self._bandwidth_samples.append(
                BandwidthSample(
                    timestamp = timestamp,
                    bytes_per_second = bps,
                    packets_per_second = pps,
                )
            )
        self._interval_bytes = 0
        self._interval_packets = 0
        self._last_sample_time = timestamp
```

This code samples bandwidth at 1-second intervals (configurable). It calculates bytes/sec and packets/sec from the interval counters, then resets them for the next interval.

The timestamp comes from packets, not system clock. This means bandwidth calculation matches packet timing exactly, even if clock drifts or system pauses.

## BPF Filter Building

### The Problem

BPF syntax is error-prone. Writing `"tcp port 80 and host 192.168.1.1"` by hand risks typos, invalid syntax, and filter injection vulnerabilities.

### The Solution

Builder pattern with type-safe methods and input validation.

### Implementation

From `filters.py:48-175`:

```python
@dataclass(slots = True)
class FilterBuilder:
    _expressions: list[str]
    
    def __init__(self) -> None:
        self._expressions = []
    
    def protocol(self, proto: Protocol) -> FilterBuilder:
        bpf_expr = BPF_PROTOCOL_MAP.get(proto)
        if bpf_expr:
            self._expressions.append(f"({bpf_expr})")
        return self
    
    def port(self, port_number: int) -> FilterBuilder:
        _validate_port(port_number)
        self._expressions.append(f"port {port_number}")
        return self
    
    def host(self, ip_address: str) -> FilterBuilder:
        _validate_ip_address(ip_address)
        self._expressions.append(f"host {ip_address}")
        return self
    
    def build(self, operator: Literal["and", "or"] = "and") -> str | None:
        if not self._expressions:
            return None
        return f" {operator} ".join(self._expressions)
```

**Important details:**

**Returning self** (`return self` in each method)
Enables method chaining: `FilterBuilder().port(80).host("192.168.1.1").build()`

**Validation before building** (`_validate_port`, `_validate_ip_address`)
```python
def _validate_port(port_number: int) -> None:
    if not PortRange.MIN <= port_number <= PortRange.MAX:
        raise ValidationError(
            f"Port must be {PortRange.MIN}-{PortRange.MAX}, got {port_number}"
        )
```

Port must be 0-65535. IP must parse with `ipaddress.ip_address()`. Fails fast with clear errors before passing to kernel.

**Wrapping expressions in parentheses**
```python
self._expressions.append(f"({bpf_expr})")
```

BPF has operator precedence rules. Wrapping ensures correct parsing. `tcp and port 80 or port 443` could mean `(tcp and port 80) or (port 443)` [wrong] or `tcp and (port 80 or port 443)` [intended]. Explicit parens prevent ambiguity.

## Data Flow Example

Let's trace a complete request through the system.

**Scenario:** User runs `sudo netanal capture -i lo -c 5 --verbose`

### Request Comes In

```python
# Entry point: main.py:110-181
@app.command()
def capture(
    interface: str | None = None,
    filter_expr: str | None = None,
    count: int | None = None,
    timeout: float | None = None,
    output: Path | None = None,
    verbose: bool = False,
) -> None:
```

At this point:
- Typer has parsed command line arguments
- interface = "lo", count = 5, verbose = True
- Need to validate permissions and create capture config

Permission check happens at `main.py:139-143`:
```python
can_capture, msg = check_capture_permissions()
if not can_capture:
    print_error(f"Cannot capture packets: {msg}")
    raise typer.Exit(1)
```

This calls `capture.py:341-347` which tests raw socket creation on Linux, /dev/bpf access on macOS, or checks for Npcap+Admin on Windows.

### Processing Layer

Config creation at `main.py:149-154`:
```python
config = CaptureConfig(
    interface = interface,
    bpf_filter = filter_expr,
    packet_count = count,
    timeout_seconds = timeout,
)
```

CaptureConfig is a frozen dataclass (`models.py:135-145`). Immutable after creation, passed to CaptureEngine.

Capture starts at `main.py:159-167`:
```python
engine = CaptureEngine(
    config = config,
    on_packet = on_packet if verbose or output else None
)

with GracefulCapture(engine) as cap:
    stats = cap.wait()
```

GracefulCapture context manager (`capture.py:197-230`) installs signal handlers, starts capture, waits for completion, then cleans up. Even if user Ctrl+C's, cleanup runs.

### Packet Processing Flow

For each packet captured:

1. Scapy calls `_enqueue_packet` callback (`capture.py:64-70`)
2. Packet goes into bounded queue
3. Consumer thread gets packet from queue (`capture.py:76-78`)
4. `extract_packet_info()` parses packet (`analyzer.py:51-103`)
5. `record_packet()` updates statistics (`statistics.py:47-67`)
6. If verbose, `on_packet()` callback displays packet (`output.py:46-54`)

After 5 packets, count check at `capture.py:88-90` sets stop event:
```python
if self._config.packet_count and current_count >= self._config.packet_count:
    self._stop_event.set()
    break
```

### Storage/Output

The result is CaptureStatistics returned from `cap.wait()` (`capture.py:145-157`).

Display happens at `main.py:169-171`:
```python
print_capture_summary(stats)
print_protocol_table(stats)
print_top_talkers(stats)
```

Each print function uses Rich to format tables. From `output.py:84-111`:
```python
def print_protocol_table(stats: CaptureStatistics) -> None:
    table = Table(title = "Protocol Distribution")
    table.add_column("Protocol", style = "cyan", justify = "left")
    table.add_column("Packets", style = "green", justify = "right")
    table.add_column("Bytes", style = "yellow", justify = "right")
    table.add_column("Percentage", style = "magenta", justify = "right")
    
    percentages = stats.get_protocol_percentages()
    
    for protocol in sorted(stats.protocol_distribution.keys(),
                           key = lambda p: p.value):
        count = stats.protocol_distribution[protocol]
        bytes_count = stats.protocol_bytes.get(protocol, 0)
        pct = percentages.get(protocol, 0.0)
        table.add_row(
            protocol.value,
            f"{count:,}",
            format_bytes(bytes_count),
            f"{pct:.1f}%",
        )
    
    console.print(table)
```

## Error Handling Patterns

### Permission Errors

When user lacks packet capture permissions, we want clear actionable errors.

```python
# capture.py:341-347
def check_capture_permissions() -> tuple[bool, str]:
    system = platform.system()
    
    if system == "Linux":
        return _check_linux_permissions()
    elif system == "Darwin":
        return _check_macos_permissions()
    elif system == "Windows":
        return _check_windows_permissions()
    
    return False, f"Unknown platform: {system}"
```

**Why this specific handling:**
Returns (bool, str) tuple instead of raising exception. Caller decides whether to error or warn. Clear messages tell user exactly what's needed ("Requires root or CAP_NET_RAW capability" vs generic "Permission denied").

Platform-specific checks because requirements differ:
- Linux: CAP_NET_RAW capability or root
- macOS: root or /dev/bpf* access
- Windows: Administrator + Npcap installed

**What NOT to do:**
```python
# Bad: catching everything silently
try:
    start_capture()
except Exception:
    pass  # User gets no feedback, waste time debugging
```

This hides actual problems. Always handle specific exceptions and provide actionable feedback.

### BPF Filter Validation

Invalid filters crash Scapy with cryptic kernel errors. Validate early.

From `filters.py:227-235`:
```python
def validate_bpf_filter(filter_str: str) -> bool:
    try:
        from scapy.arch import compile_filter
        compile_filter(filter_str)
        return True
    except Exception:
        return False
```

Usage in `main.py:145-147`:
```python
if filter_expr and not validate_bpf_filter(filter_expr):
    print_error(f"Invalid BPF filter: {filter_expr}")
    raise typer.Exit(1)
```

Fails fast before starting capture. User sees clear error immediately instead of cryptic kernel message after waiting.

## Performance Optimizations

### Optimization 1: Dataclass Slots

**Before:**
```python
@dataclass
class PacketInfo:
    timestamp: float
    src_ip: str
    # ... 8 more fields
```

This was slow because each instance uses a `__dict__` to store attributes. With 1 million packets, that's ~40MB wasted on dict overhead.

**After:**
```python
@dataclass(frozen = True, slots = True)
class PacketInfo:
    timestamp: float
    src_ip: str
    # ... 8 more fields
```

**What changed:**
- Added `slots = True` to dataclass decorator
- Attributes stored in fixed slots, not dict
- Also added `frozen = True` for immutability

**Benchmarks:**
- Before: 1M packets = ~100MB memory
- After: 1M packets = ~60MB memory  
- Improvement: 40% memory reduction

Measured with:
```python
import sys
packet = PacketInfo(...)
print(sys.getsizeof(packet))
```

### Optimization 2: BPF Kernel Filtering

**Before:**
```python
# Capture all packets, filter in Python
for packet in capture_all():
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        process(packet)
```

This was slow because every packet triggers context switch from kernel to userspace, then Python code checks each one.

**After:**
```python
# Filter in kernel with BPF
AsyncSniffer(filter="tcp port 80", prn=process)
```

**What changed:**
BPF runs in kernel, dropping unwanted packets before userspace sees them. No context switch for filtered packets.

**Benchmarks:**
On busy network (1000 packets/sec, 95% irrelevant):
- Before: 80% CPU, 950 unnecessary context switches/sec
- After: 5% CPU, only 50 relevant packets reach userspace

The kernel does simple comparisons (port == 80) extremely fast. Python does the same check thousands of times slower.

## Common Implementation Pitfalls

### Pitfall 1: Forgetting Queue Bounds

**Symptom:**
Process memory grows to gigabytes, system freezes, OOM killer terminates process.

**Cause:**
```python
# The problematic code
self._queue = Queue()  # Unbounded!
```

Unbounded queue grows forever if producer is faster than consumer. With 10K packets/sec and 1KB average size, unbounded queue grows at 10MB/sec.

**Fix:**
```python
# Correct approach
self._queue: Queue[Packet] = Queue(maxsize = 10000)
```

Bounded queue raises Full when capacity reached. Producer drops packet with counter increment instead of consuming infinite memory.

**Why this matters:**
Production packet capture tools run for hours or days. Memory leaks crash the monitoring system, creating blind spots during incidents.

### Pitfall 2: Lock-Free "Optimization"

**Symptom:**
Packet counts don't match reality. Protocol percentages don't sum to 100%. Statistics corrupted randomly.

**Cause:**
```python
# Bad: "optimization" that removes lock
def record_packet(self, packet: PacketInfo) -> None:
    # No lock!
    self._total_packets += 1
    self._protocol_counts[packet.protocol] += 1
```

Thought process: "Locks are slow, let's skip it". But Python's `+=` is NOT atomic. It's actually three operations:
```
1. Read value
2. Add 1
3. Write result
```

Two threads can interleave, causing lost updates.

**Fix:**
```python
# Correct: use lock
def record_packet(self, packet: PacketInfo) -> None:
    with self._lock:
        self._total_packets += 1
        self._protocol_counts[packet.protocol] += 1
```

**Why this matters:**
Statistics are useless if they're incorrect. Security incidents get missed because baseline detection uses wrong numbers.

### Pitfall 3: String Concatenation for Filters

**Symptom:**
BPF syntax errors, filter injection vulnerabilities, crashes.

**Cause:**
```python
# Vulnerable code
user_ip = input("Enter IP: ")  # User enters: 1.2.3.4 or 1=1
filter_str = f"host {user_ip}"  # Results in "host 1.2.3.4 or 1=1"
```

Filter injection attack. Attacker can bypass intended restrictions or craft filters that match everything.

**Fix:**
```python
# Correct: validate first
def host(self, ip_address: str) -> FilterBuilder:
    _validate_ip_address(ip_address)  # Raises on invalid input
    self._expressions.append(f"host {ip_address}")
    return self
```

Validation with `ipaddress.ip_address()` ensures input is actually an IP, not arbitrary BPF syntax.

**Why this matters:**
If monitoring tools have filter injection vulns, attackers can blind monitoring by making filters match nothing, or overload systems by making filters match everything.

## Debugging Tips

### Issue Type 1: No Packets Captured

**Problem:** Total packets = 0 even though network is active

**How to debug:**

1. Check interface is correct: `netanal interfaces` shows available interfaces
2. Check BPF filter isn't too restrictive: Remove filter and try again
3. Verify permissions: `netanal capture` without sudo shows permission error
4. Check promiscuous mode: Some wireless adapters block it

**Common causes:**
- Wrong interface name ("eth0" vs "ens33")
- Filter matches nothing ("tcp port 12345" on HTTP-only network)
- Wireless adapter in managed mode (needs monitor mode)
- Firewall blocking packet capture

Add debug output to see packets hitting queue:
```python
def _enqueue_packet(self, packet: Packet) -> None:
    print(f"DEBUG: Enqueued packet from {packet[IP].src if packet.haslayer(IP) else 'unknown'}")
    self._queue.put_nowait(packet)
```

If queue receives packets but stats show zero, problem is in consumer thread.

### Issue Type 2: High Dropped Packet Count

**Problem:** Statistics show thousands of dropped packets

**How to debug:**

1. Check queue size: `constants.py:QUEUE_SIZE = 10000` may be too small
2. Profile consumer thread: Is processing slow?
3. Monitor CPU usage: Is system overloaded?
4. Check callbacks: Is verbose printing slowing processing?

**Common causes:**
- Queue too small for traffic rate
- Consumer thread blocked on I/O (writing to disk)
- CPU maxed out
- Verbose mode enabled during high traffic

Increase queue size:
```python
engine = CaptureEngine(config=config, queue_size=50000)
```

Profile consumer:
```python
import cProfile
cProfile.run('engine.wait()')
```

### Issue Type 3: Memory Growing Unbounded

**Problem:** Process memory grows continuously until OOM

**How to debug:**

1. Check queue is bounded: `Queue(maxsize=10000)` not `Queue()`
2. Check packet storage: `store_packets=False` in config
3. Monitor bandwidth samples: Does list grow forever?
4. Check for reference cycles: Are old packets staying in memory?

**Common causes:**
- Unbounded queue
- store_packets=True keeps all packets in memory
- Bandwidth samples not cleaned up
- Circular references preventing GC

Fix unbounded growth:
```python
# Limit bandwidth samples
if len(self._bandwidth_samples) > 3600:  # Max 1 hour at 1/sec
    self._bandwidth_samples = self._bandwidth_samples[-3600:]
```

## Code Organization Principles

### Why capture.py is Structured This Way

```
capture.py:
├── CaptureEngine class        # Main producer-consumer implementation
│   ├── __init__               # Setup queue, threads, locks
│   ├── _enqueue_packet        # Producer callback (Scapy calls this)
│   ├── _process_packets       # Consumer loop (runs in thread)
│   ├── start/stop/wait        # Public lifecycle methods
│   └── Properties             # is_running, dropped_packets
├── GracefulCapture            # Context manager for signal handling
└── Helper functions           # check_permissions, get_interfaces
```

We separate concerns:
- CaptureEngine handles threading and queue management
- GracefulCapture handles signal cleanup
- Permission checking is standalone function (reusable)

This makes testing easier. You can test permission checking without starting a capture. You can test queue behavior without Scapy.

### Naming Conventions

- `_private_method`: Leading underscore means internal implementation
- `public_method`: No underscore means part of public API
- `CamelCase`: Classes
- `snake_case`: Functions and variables
- `SCREAMING_SNAKE`: Constants

Following these patterns makes it easier to understand what's private vs public API just from the name.

## Extending the Code

### Adding a New Protocol

Want to detect BitTorrent traffic? Here's the process:

1. **Add to Protocol enum** in `models.py:11-21`
   ```python
   class Protocol(StrEnum):
       TCP = "TCP"
       # ... existing protocols
       BITTORRENT = "BITTORRENT"
   ```

2. **Update protocol identification** in `analyzer.py:14-48`
   ```python
   def identify_protocol(packet: Packet) -> Protocol:
       # Check BitTorrent before TCP fallback
       if packet.haslayer(TCP):
           tcp_layer = packet[TCP]
           if tcp_layer.dport in range(6881, 6890) or tcp_layer.sport in range(6881, 6890):
               return Protocol.BITTORRENT
           # ... existing HTTP/HTTPS checks
           return Protocol.TCP
   ```

3. **Add color mapping** in `constants.py:63-84`
   ```python
   class ProtocolColors:
       RICH: Final[dict[str, str]] = {
           # ... existing colors
           "BITTORRENT": "red",
       }
       
       HEX: Final[dict[str, str]] = {
           # ... existing colors
           "BITTORRENT": "#ff0000",
       }
   ```

4. **Add BPF filter support** in `filters.py:16-26`
   ```python
   BPF_PROTOCOL_MAP: dict[Protocol, str] = {
       # ... existing protocols
       Protocol.BITTORRENT: "tcp portrange 6881-6889",
   }
   ```

5. **Add tests** in `tests/test_models.py`
   ```python
   def test_bittorrent_protocol():
       assert Protocol.BITTORRENT.value == "BITTORRENT"
   ```

Now BitTorrent appears in protocol distribution, top talkers, and charts automatically.

## Dependencies

### Why Each Dependency

- **typer (0.21.1+)**: CLI framework. Provides argument parsing, help generation, command routing. Chosen over argparse because it uses type hints for automatic validation. Chosen over click because it's newer with better defaults.

- **rich (14.3.1+)**: Terminal formatting. Provides colored tables, progress bars, syntax highlighting. Creates professional-looking CLI output without manual ANSI codes. Used by GitHub CLI and other modern CLI tools.

- **scapy (2.6.1+)**: Packet manipulation. Only library with comprehensive protocol support and pcap file handling. Alternatives (dpkt, pyshark) lack protocol dissection features or require external tools.

- **matplotlib (3.10.0+)**: Visualization. Industry standard for scientific plotting. Charts generated match analyst expectations. Alternatives (plotly, bokeh) generate HTML not PNG, less suitable for reports.

### Dependency Security

Check for vulnerabilities:
```bash
pip install pip-audit
pip-audit
```

If you see vulnerability in dependencies:
1. Check if it affects how we use the library
2. Update to patched version if available
3. Consider alternative library if no patch
4. Add to known issues if must stay on vulnerable version

Example: CVE in old Scapy versions. Update to 2.6.1+ which patches the issue.

## Next Steps

You've seen how the code works. Now:

1. **Try the challenges** - [04-CHALLENGES.md](./04-CHALLENGES.md) has extension ideas like TCP stream reassembly and anomaly detection
2. **Modify the code** - Change protocol identification in analyzer.py to detect your own protocols
3. **Profile performance** - Use cProfile to find bottlenecks in your extensions
