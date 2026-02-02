# System Architecture

This document breaks down how the system is designed and why certain architectural decisions were made.

## High Level Architecture

```
┌──────────────────────────────────────────────────────────┐
│                   CLI Interface (Typer)                  │
│                      main.py                             │
└────────────────────┬─────────────────────────────────────┘
                     │
         ┌───────────┼───────────┐
         │           │           │
         ▼           ▼           ▼
    ┌────────┐  ┌────────┐  ┌──────────┐
    │Capture │  │Analyze │  │Visualize │
    │ Engine │  │ PCAP   │  │ Charts   │
    └───┬────┘  └───┬────┘  └────┬─────┘
        │           │             │
        │     ┌─────┴──────┐      │
        │     │            │      │
        ▼     ▼            ▼      ▼
    ┌─────────────────────────────────┐
    │    Producer-Consumer Queue      │
    │                                 │
    │  ┌──────────┐   ┌─────────────┐│
    │  │ Producer │──>│    Queue    ││
    │  │ (Scapy)  │   │  (bounded)  ││
    │  └──────────┘   └──────┬──────┘│
    │                        │       │
    │                        ▼       │
    │                  ┌───────────┐ │
    │                  │ Consumer  │ │
    │                  │ (Process) │ │
    │                  └─────┬─────┘ │
    └────────────────────────┼───────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │   Statistics    │
                    │   Collector     │
                    │ (Thread-Safe)   │
                    └────────┬────────┘
                             │
         ┌───────────────────┼────────────────┐
         │                   │                │
         ▼                   ▼                ▼
    ┌────────┐         ┌─────────┐      ┌────────┐
    │Console │         │  Export │      │ Charts │
    │ Output │         │JSON/CSV │      │  PNG   │
    └────────┘         └─────────┘      └────────┘
```

### Component Breakdown

**CLI Interface (main.py)**
- Purpose: Provides user-facing commands (capture, analyze, export, chart)
- Responsibilities: Argument parsing, command routing, error display
- Interfaces: Calls CaptureEngine, analyze_pcap_file, and visualization functions

**Capture Engine (capture.py)**
- Purpose: Real-time packet capture with producer-consumer threading
- Responsibilities: Raw socket management, privilege checking, graceful shutdown
- Interfaces: AsyncSniffer from Scapy, Queue for threading, StatisticsCollector for metrics

**Analyzer (analyzer.py)**
- Purpose: Protocol identification and packet field extraction
- Responsibilities: Layer dissection, protocol classification, data structure conversion
- Interfaces: Accepts Scapy Packet objects, returns PacketInfo dataclasses

**Statistics Collector (statistics.py)**
- Purpose: Thread-safe aggregation of packet metrics
- Responsibilities: Counter management, bandwidth sampling, endpoint tracking
- Interfaces: record_packet() called from consumer thread, get_statistics() for snapshots

**Filter Builder (filters.py)**
- Purpose: Type-safe BPF filter expression construction
- Responsibilities: Input validation, expression combination, BPF syntax generation
- Interfaces: Fluent API for chaining filters, build() produces BPF string

**Visualization (visualization.py)**
- Purpose: Generate charts from capture statistics
- Responsibilities: Matplotlib figure creation, chart styling, file export
- Interfaces: Accepts CaptureStatistics, produces Figure objects

**Export (export.py)**
- Purpose: Serialize capture data to disk formats
- Responsibilities: JSON/CSV formatting, data structure conversion
- Interfaces: Takes CaptureStatistics and PacketInfo lists, writes files

**Output (output.py)**
- Purpose: Rich console formatting for terminal display
- Responsibilities: Table generation, progress bars, colored output
- Interfaces: Console singleton, print_* functions for different data types

## Data Flow

### Live Packet Capture Flow

Step by step walkthrough of what happens during live capture:

```
1. User runs command → main.py:capture() (line 110)
   Parses arguments (interface, filter, count, timeout)
   Creates CaptureConfig dataclass

2. Config → CaptureEngine.__init__() (line 46)
   Initializes Queue(maxsize=10000)
   Creates StatisticsCollector
   Sets up threading.Event for shutdown coordination

3. CaptureEngine.start() → AsyncSniffer.start() (line 112)
   Scapy starts producer thread
   Calls _enqueue_packet callback for each packet
   Producer: packet → Queue.put_nowait()

4. Consumer thread _process_packets() runs in parallel (line 72)
   Loop: Queue.get() → extract_packet_info() → record_packet()
   Packet → analyzer.py:extract_packet_info() (line 51)
   PacketInfo → statistics.py:record_packet() (line 47)

5. Statistics update (thread-safe with lock) (line 48-67)
   Increment counters (total_packets, total_bytes)
   Update protocol_distribution dict
   Update endpoint statistics
   Check if bandwidth sample interval elapsed

6. User presses Ctrl+C → GracefulCapture handles signal
   Sets stop_event → consumer thread exits
   Calls sniffer.stop() → producer thread exits
   Returns final CaptureStatistics snapshot

7. Statistics → output.py:print_*() functions (line 84-170)
   Formats Rich tables for protocols, top talkers
   Displays bandwidth graphs
   Shows capture summary panel
```

Example with code references:

```python
# Entry point: main.py:159
def capture(interface, filter_expr, count, timeout, output, verbose):
    config = CaptureConfig(
        interface = interface,
        bpf_filter = filter_expr,
        packet_count = count,
        timeout_seconds = timeout,
    )
    
    # Producer-consumer setup: capture.py:112-131
    engine = CaptureEngine(config=config)
    engine.start()  # Spawns threads
    
    # Processing loop: capture.py:72-90
    while not self._stop_event.is_set():
        packet = self._queue.get()
        info = extract_packet_info(packet)  # analyzer.py:51
        self._stats.record_packet(info)     # statistics.py:47
```

### PCAP File Analysis Flow

```
1. User: netanal analyze traffic.pcap
   ↓
2. main.py:analyze() (line 237)
   Validates file exists
   ↓
3. analyzer.py:analyze_pcap_file() (line 162)
   Opens PcapReader (memory efficient iteration)
   ↓
4. For each packet in file:
   extract_packet_info() → PacketInfo
   StatisticsCollector.record_packet()
   ↓
5. Returns CaptureStatistics
   ↓
6. output.py formats and displays
   Protocol table, top talkers, summary
```

## Design Patterns

### Producer-Consumer Pattern

**What it is:**
Separates data generation from data processing using a queue buffer. Producer threads add items to queue, consumer threads remove and process items. Decouples rate of production from rate of consumption.

**Where we use it:**
`capture.py:46-90` implements the full pattern. AsyncSniffer is the producer, _process_packets loop is the consumer.

**Why we chose it:**
Packet capture must run at wire speed without dropping packets. Processing (protocol identification, statistics updates, optional callbacks) is slower. Buffering in a queue prevents packet loss when processing lags.

**Trade-offs:**
- Pros: Prevents packet loss, decouples concerns, enables parallelism
- Cons: Uses memory for queue buffer, adds latency (packets delayed in queue), requires thread synchronization

Example implementation:
```python
# capture.py:64-70 - Producer callback
def _enqueue_packet(self, packet: Packet) -> None:
    try:
        self._queue.put_nowait(packet)
    except Full:
        with self._count_lock:
            self._dropped_packets += 1

# capture.py:72-90 - Consumer loop
def _process_packets(self) -> None:
    while not self._stop_event.is_set():
        try:
            packet = self._queue.get(timeout=0.1)
        except Empty:
            continue
        
        info = extract_packet_info(packet)
        self._stats.record_packet(info)
```

The producer never blocks on slow processing. The consumer processes at its own pace. If queue fills, packets drop with counter increment rather than crashing.

### Builder Pattern

**What it is:**
Constructs complex objects step by step through a fluent interface. Each method returns self, enabling method chaining. Final build() call produces the result.

**Where we use it:**
`filters.py:48-175` implements FilterBuilder for BPF expressions.

**Why we chose it:**
BPF syntax is error-prone. Users can build type-safe filters with validation at each step rather than error-prone string concatenation.

**Trade-offs:**
- Pros: Type safety, input validation, readable API, prevents injection
- Cons: More code than raw strings, requires understanding the builder

Example:
```python
# filters.py:48-175
filter_expr = (
    FilterBuilder()
    .protocol(Protocol.TCP)
    .port(443)
    .host("192.168.1.1")
    .build()
)
# Result: "(tcp) and port 443 and host 192.168.1.1"

# Validates each input:
# filters.py:30-37
def _validate_port(port_number: int) -> None:
    if not PortRange.MIN <= port_number <= PortRange.MAX:
        raise ValidationError(f"Port must be 0-65535, got {port_number}")
```

### Dataclass with Slots Pattern

**What it is:**
Python dataclasses with `slots=True` reduce memory usage by storing attributes in fixed slots instead of a dict. Frozen dataclasses are immutable.

**Where we use it:**
All models in `models.py:11-159` use dataclasses with slots.

**Why we chose it:**
Packet captures generate thousands to millions of PacketInfo objects. Slots reduce per-object memory by ~40%. Immutability prevents accidental modification.

**Trade-offs:**
- Pros: Lower memory usage, immutability safety, clear schema
- Cons: Cannot add attributes dynamically, slightly slower instantiation

Example:
```python
# models.py:22-35
@dataclass(frozen = True, slots = True)
class PacketInfo:
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: Protocol
    size: int
    src_port: int | None = None
    dst_port: int | None = None
    src_mac: str | None = None
    dst_mac: str | None = None
```

With 1 million packets, slots save ~40MB compared to dict-based attributes.

### Context Manager Pattern

**What it is:**
Objects implementing `__enter__` and `__exit__` for resource setup and cleanup. Used with `with` statements to ensure cleanup even on exceptions.

**Where we use it:**
`capture.py:197-230` implements GracefulCapture context manager.

**Why we chose it:**
Ensures graceful shutdown even if user Ctrl+C's or exceptions occur. Signal handlers restore properly and capture stops cleanly.

**Trade-offs:**
- Pros: Guaranteed cleanup, clean syntax, exception safe
- Cons: Additional boilerplate, understanding `__enter__/__exit__` protocol

Example:
```python
# capture.py:197-230
class GracefulCapture:
    def __enter__(self) -> CaptureEngine:
        # Setup: Install signal handlers
        self._original_sigint = signal.signal(signal.SIGINT, self._handle_signal)
        self._engine.start()
        return self._engine
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Cleanup: Restore handlers, stop capture
        signal.signal(signal.SIGINT, self._original_sigint)
        self._engine.stop()

# Usage: main.py:159-167
with GracefulCapture(engine) as cap:
    stats = cap.wait()
```

## Layer Separation

```
┌────────────────────────────────────┐
│    CLI Layer (main.py)             │
│    - Command definitions           │
│    - Argument parsing              │
│    - User interaction              │
└────────────────────────────────────┘
           ↓ calls
┌────────────────────────────────────┐
│    Service Layer                   │
│    - capture.py: CaptureEngine     │
│    - analyzer.py: Protocol logic   │
│    - filters.py: Filter building   │
└────────────────────────────────────┘
           ↓ uses
┌────────────────────────────────────┐
│    Data Layer                      │
│    - statistics.py: Aggregation    │
│    - models.py: Data structures    │
│    - constants.py: Configuration   │
└────────────────────────────────────┘
           ↓ produces
┌────────────────────────────────────┐
│    Output Layer                    │
│    - output.py: Console display    │
│    - visualization.py: Charts      │
│    - export.py: File I/O           │
└────────────────────────────────────┘
```

### Why Layers?

Separation of concerns prevents tight coupling. CLI commands don't know about Scapy internals. CaptureEngine doesn't know about Rich formatting. Changes to visualization don't affect statistics collection.

### What Lives Where

**CLI Layer (main.py):**
- Files: main.py, __main__.py
- Imports: Can import from all layers
- Forbidden: Direct Scapy usage, Rich formatting (delegate to output.py), Matplotlib (delegate to visualization.py)

**Service Layer:**
- Files: capture.py, analyzer.py, filters.py
- Imports: Data layer only, no CLI or output dependencies
- Forbidden: print statements (return data instead), sys.exit() (raise exceptions)

**Data Layer:**
- Files: statistics.py, models.py, constants.py, exceptions.py
- Imports: Only standard library and type hints
- Forbidden: Any I/O, any third-party imports (except type checking)

**Output Layer:**
- Files: output.py, visualization.py, export.py
- Imports: Data layer for models, third-party formatting libraries
- Forbidden: Business logic, packet processing

## Data Models

### PacketInfo

```python
# models.py:22-35
@dataclass(frozen = True, slots = True)
class PacketInfo:
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: Protocol
    size: int
    src_port: int | None = None
    dst_port: int | None = None
    src_mac: str | None = None
    dst_mac: str | None = None
```

**Fields explained:**
- `timestamp`: Unix epoch time from packet capture. Float for microsecond precision. Used for bandwidth calculations and time-series analysis.
- `src_ip/dst_ip`: String IP addresses (IPv4 or IPv6). Not validated at model level (analyzer validates). Used for endpoint tracking.
- `protocol`: Protocol enum (TCP, UDP, ICMP, etc). Determined by analyzer.identify_protocol(). Used for distribution statistics.
- `size`: Total packet size in bytes including all headers. Used for bandwidth and traffic volume calculations.
- `src_port/dst_port`: Optional because ICMP/ARP don't have ports. None means not applicable or not extracted.
- `src_mac/dst_mac`: Optional Layer 2 addresses. Useful for local network analysis, less relevant for routed traffic.

**Relationships:**
- Frozen dataclass prevents accidental modification after creation
- Created by analyzer.extract_packet_info() from Scapy Packet objects
- Consumed by statistics.StatisticsCollector.record_packet()
- Stored in lists for export but not kept in memory during live capture (only statistics)

### EndpointStats

```python
# models.py:38-61
@dataclass(slots = True)
class EndpointStats:
    ip_address: str
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    
    @property
    def total_packets(self) -> int:
        return self.packets_sent + self.packets_received
    
    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_received
```

**Purpose:** Track bidirectional traffic for each IP address. Used for "top talkers" identification and baseline establishment.

**Relationships:**
- Mutable (not frozen) because counters increment throughout capture
- One instance per unique IP address seen
- Stored in statistics.StatisticsCollector._endpoints dict
- Properties enable sorting by total volume without storing redundant fields

## Security Architecture

### Threat Model

What we're protecting against:

1. **Privilege escalation** - Ensure packet capture only works with proper permissions. No bypassing OS security. Check capabilities explicitly before attempting capture.

2. **Filter injection** - Malicious filter strings could crash the kernel or bypass intended restrictions. Validate all user input before passing to BPF compiler.

3. **Resource exhaustion** - Unbounded queues or memory usage could DoS the monitoring system. Use bounded buffers and reasonable limits.

What we're NOT protecting against (out of scope):

- **Physical network access** - Assume attacker can plug into the network. This tool doesn't prevent that.
- **Encrypted payload inspection** - We analyze metadata and headers, not encrypted content. TLS decryption requires MITM proxies.
- **Quantum computing threats** - Future attacks on cryptographic protocols aren't addressed by packet capture tools.

### Defense Layers

```
Layer 1: Privilege Validation
    ↓ (capture.py:341-375)
Layer 2: Input Validation
    ↓ (filters.py:30-66, main.py)
Layer 3: Resource Limits
    ↓ (capture.py:46, constants.py)
Layer 4: Error Handling
    ↓ (exceptions.py, try/except throughout)
```

**Why multiple layers?**

Defense in depth. If input validation has a bug, resource limits prevent DoS. If privilege check bypasses, kernel still enforces permissions. Each layer catches different attack vectors.

## Storage Strategy

### In-Memory Statistics

**What we store:**
- Aggregate counters (total packets, bytes)
- Per-protocol distributions
- Per-endpoint statistics  
- Bandwidth samples (time-series)

**Why in-memory:**
Performance. Disk I/O during high-speed capture drops packets. Statistics update on every packet, requiring nanosecond latency. RAM provides this, disk does not.

**Memory management:**
```python
# constants.py:36-41
class CaptureDefaults:
    QUEUE_SIZE: Final[int] = 10_000
    BANDWIDTH_SAMPLE_INTERVAL_SECONDS: Final[float] = 1.0
```

Queue size limits memory to ~10K packets × ~1.5KB = 15MB max. Bandwidth samples at 1/second means 3600 samples/hour = ~100KB/hour. Endpoint stats depend on unique IPs seen.

### Disk Export

Optional export to JSON/CSV for persistence:
```python
# export.py:80-107
def export_to_json(
    stats: CaptureStatistics,
    filepath: Path,
    packets: list[PacketInfo] | None = None,
    options: ExportOptions | None = None,
) -> None:
```

Only happens on demand, not during capture. Separates hot path (capture) from cold path (analysis).

## Configuration

### Environment Variables

```bash
NO_COLOR=1           # Disables colored output for CI/CD environments
CI=1                 # Optimizes output for continuous integration
PYTHONUNBUFFERED=1   # Forces unbuffered stdout for real-time logs
```

### Configuration Strategy

Constants in `constants.py` provide sensible defaults. Command-line arguments override defaults. No config files to avoid complexity for a simple tool.

**Development:**
```python
# constants.py provides overridable defaults
CaptureDefaults.QUEUE_SIZE = 10_000  # Balance memory vs packet loss
```

**Production:**
Adjust queue size based on available memory and expected packet rate. 10K queue handles ~1-2 Gbps sustained traffic.

## Performance Considerations

### Bottlenecks

Where this system gets slow under load:

1. **Queue contention** - Producer and consumer both access queue. At extreme rates (10+ Gbps), queue operations become serialization point. Mitigate with multiple queues and worker threads.

2. **Statistics lock** - Every packet acquisition requires lock in record_packet(). At millions of packets/second, lock contention dominates. Mitigate with lock-free counters or per-thread statistics with periodic merging.

### Optimizations

What we did to make it faster:

- **BPF filtering in kernel**: Drops ~99% of irrelevant packets before userspace sees them. Moving from userspace to BPF filter reduced CPU usage from 80% to 5% in testing with port 80 filter on busy network.

- **Bounded queue with non-blocking put**: Using `put_nowait()` with explicit dropped counter prevents producer blocking. Capture thread never waits on slow consumer.

- **Dataclass slots**: Reduces memory per packet by 40%. With 10K queue, saves 6MB. Allows larger queues in same memory budget.

- **Minimal string formatting**: Only format output when displaying, not during capture. `print_packet()` only called if `--verbose` flag set.

### Scalability

**Vertical scaling:**
Add more CPU/RAM to single machine. Packet capture is CPU-bound (protocol parsing) and memory-bound (queue storage). 8-core system with 32GB RAM can handle ~5-10 Gbps depending on traffic mix.

**Horizontal scaling:**
Requires architectural changes:
- Mirror traffic to multiple capture hosts
- Use distributed queue (Kafka/RabbitMQ) instead of in-memory Queue
- Aggregate statistics from multiple collectors
- Current code doesn't support this without modification

## Design Decisions

### Decision 1: AsyncSniffer vs sync sniff()

**What we chose:**
AsyncSniffer with background thread

**Alternatives considered:**
- `sniff(prn=callback)` - Rejected because blocks the main thread, preventing graceful shutdown and progress display
- `sniff(timeout=1)` in loop - Rejected because introduces gaps where packets can be lost between timeout and restart

**Trade-offs:**
Gained: Responsive UI, graceful shutdown, concurrent processing
Lost: Slightly more complex threading logic, need for queue management

### Decision 2: Thread locks vs lock-free algorithms

**What we chose:**
`threading.Lock()` for statistics protection

**Alternatives considered:**
- Lock-free atomics - Rejected because Python doesn't have true atomic operations (GIL exists but doesn't help here)
- No synchronization - Rejected because causes race conditions and data corruption

**Trade-offs:**
Gained: Correctness, simplicity, standard patterns
Lost: Some performance at extreme packet rates (millions/sec), potential for lock contention

### Decision 3: Dataclasses vs named tuples

**What we chose:**
Frozen dataclasses with slots

**Alternatives considered:**
- Named tuples - Rejected because lack type checking, no default values, harder to extend
- Regular classes - Rejected because boilerplate code, no automatic `__repr__`, more memory

**Trade-offs:**
Gained: Type safety, defaults, less boilerplate, better memory usage
Lost: Requires Python 3.10+ for slots in dataclasses

## Next Steps

Now that you understand the architecture:

1. Read [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) for code walkthrough showing how each component actually works
2. Try modifying queue size in constants.py and observe impact on packet loss under load
3. Trace a single packet from capture through statistics to output by adding debug prints
