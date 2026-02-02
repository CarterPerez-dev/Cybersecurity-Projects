# Core Security Concepts

This document explains the security concepts you'll encounter while building this project. These are not just definitions. We'll dig into why they matter and how they actually work.

## Packet Capture and Raw Sockets

### What It Is

Packet capture means reading network frames directly from the network interface before the operating system processes them. Normally, your OS only shows applications the data addressed to them. Packet capture lets you see ALL traffic on the network segment, including other machines' communications.

Raw sockets provide direct access to network protocols below the transport layer. Unlike normal TCP sockets where the kernel handles connection state, raw sockets let you craft and inspect packets at the IP level or below.

### Why It Matters

During the 2011 DigiNotar breach, attackers issued fraudulent SSL certificates for Google and other sites. Network monitoring caught this because the fake certificates appeared in TLS handshakes visible to packet capture tools. Certificate pinning wasn't enough because users trusted the CA. Packet-level inspection revealed the forgery.

Without packet capture capability, you're blind to:
- What protocols are actually running on your network (not just what should be running)
- Unencrypted credentials sent over HTTP or FTP
- Data exfiltration via DNS tunneling or ICMP
- Lateral movement between compromised machines

### How It Works

The operating system network stack looks like this:

```
Application Layer
      ↓
  Socket API
      ↓
Transport Layer (TCP/UDP)
      ↓
  Network Layer (IP)
      ↓
   Link Layer (Ethernet)
      ↓
Physical Network Interface
```

Normal applications interact at the Socket API level. They call `socket.connect()` and the kernel handles everything below. Packet capture operates at the Link Layer, seeing raw Ethernet frames before the kernel processes them.

On Linux, this requires the CAP_NET_RAW capability. The kernel checks this permission before allowing AF_PACKET sockets. From `capture.py:354-360`:

```python
def _check_linux_permissions() -> tuple[bool, str]:
    if os.geteuid() == 0:
        return True, "Running as root"
    
    try:
        sock = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(0x0003),
        )
```

The code tries to create a raw packet socket. If it succeeds, you have CAP_NET_RAW. If you get PermissionError, you need elevated privileges.

### Common Attacks

1. **Promiscuous mode sniffing** - Attacker captures all traffic on a network segment, not just traffic addressed to them. On switched networks this requires ARP spoofing to redirect traffic. On wireless, monitor mode captures all frames. Defend with encryption (TLS/SSL) and network segmentation.

2. **Packet injection** - Attacker crafts malicious packets and injects them into the network. TCP sequence prediction attacks work this way. Metasploit's TCP/IP stack spoofing relies on raw sockets. Defend with egress filtering and connection tracking at the firewall.

3. **Protocol analysis for reconnaissance** - Attackers capture packets to map your network topology, identify services, and find vulnerable versions. Passive reconnaissance is hard to detect because it generates no traffic. Defend with encryption and monitoring for unusual packet captures (tools like ArpON detect promiscuous interfaces).

### Defense Strategies

This project implements several protections:

**Privilege checking** - Before starting capture, the code validates permissions (`capture.py:341-347`). This prevents confusing error messages and clearly explains what's needed. Production tools fail fast with actionable errors.

**BPF filtering** - Instead of processing every packet in userspace, BPF filters run in the kernel and drop irrelevant traffic. From `filters.py:83-92`, the FilterBuilder validates inputs before sending filters to the kernel. This prevents filter injection attacks where malicious input could crash the capture engine.

**Read-only operations** - This tool captures and analyzes packets but never modifies or injects them. The principle of least privilege: capture requires elevated permissions, but we don't use those permissions for anything beyond reading.

## Berkeley Packet Filter (BPF)

### What It Is

BPF is a virtual machine inside the Linux/BSD kernel that efficiently filters packets before they reach userspace. You write filter expressions like "tcp port 80" which compile to BPF bytecode. The kernel runs this bytecode against every packet, keeping only matches.

### Why It Matters

Without BPF, packet capture in userspace is too slow for high-speed networks. Every packet triggers a context switch from kernel to userspace. At 10 Gbps, that's millions of interrupts per second. BPF does filtering in the kernel, reducing context switches by orders of magnitude.

The 2016 Mirai botnet overwhelmed networks with simple UDP floods. Network operators used BPF filters to drop attack traffic at the kernel level, keeping their monitoring tools operational. Without BPF, the capture tools themselves would have fallen over.

### How It Works

BPF compiles filter expressions to bytecode that runs in a register-based virtual machine. Here's what happens when you write "tcp port 443":

```
Load protocol field from IP header
Compare with TCP (protocol 6)
If not TCP, reject packet
Load destination port from TCP header  
Compare with 443
If not 443, reject packet
Accept packet
```

This runs in the kernel for every packet before userspace sees it. From `filters.py:136-150`, the FilterBuilder creates these expressions:

```python
def port(self, port_number: int) -> FilterBuilder:
    _validate_port(port_number)
    self._expressions.append(f"port {port_number}")
    return self

def build(self, operator: Literal["and", "or"] = "and") -> str | None:
    if not self._expressions:
        return None
    return f" {operator} ".join(self._expressions)
```

The expressions combine with boolean operators. "tcp and port 443 and host 192.168.1.1" becomes BPF bytecode that checks all three conditions efficiently.

### Common Pitfalls

**Mistake 1: Not validating filter syntax**
```python
# Bad - passes invalid filter to kernel
filter_expr = user_input  # "tcp port foobar"
sniffer = AsyncSniffer(filter=filter_expr)  # Crashes
```

The kernel rejects invalid BPF syntax with cryptic errors. From `filters.py:227-235`:

```python
def validate_bpf_filter(filter_str: str) -> bool:
    try:
        from scapy.arch import compile_filter
        compile_filter(filter_str)
        return True
    except Exception:
        return False
```

Validate before capture starts, not when the user has already waited 5 minutes.

**Mistake 2: Filter injection via unsanitized input**

```python
# Bad - user can inject arbitrary filters  
filter_expr = f"host {user_ip}"  # user_ip = "1.2.3.4 or (tcp port 1-65535)"
```

From `filters.py:35-41`, validation catches this:

```python
def _validate_ip_address(ip_address: str) -> None:
    try:
        ipaddress.ip_address(ip_address)
    except ValueError as e:
        raise ValidationError(f"Invalid IP address: {ip_address}") from e
```

Always validate inputs with proper type checking, not string concatenation.

## Protocol Layer Analysis

### What It Is

Network protocols stack in layers, each adding its own header with metadata. Ethernet frames contain IP packets, which contain TCP segments, which contain HTTP requests. Protocol analysis means dissecting these layers to extract information at each level.

The OSI model defines seven layers, but TCP/IP uses four practical layers:

```
Layer 4: Application  (HTTP, DNS, SSH)
Layer 3: Transport    (TCP, UDP)
Layer 2: Network      (IP)
Layer 1: Link         (Ethernet)
```

### How It Works

From `analyzer.py:14-48`, the identify_protocol function walks through layers:

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
```

Scapy's layer system lets you check `packet.haslayer(TCP)` and access fields like `packet[TCP].dport`. Each layer is a Python object with fields matching the protocol spec.

The extraction happens in `analyzer.py:51-103`:

```python
def extract_packet_info(packet: Packet) -> PacketInfo | None:
    if packet.haslayer(Ether):
        ether_layer = packet[Ether]
        src_mac = ether_layer.src
        dst_mac = ether_layer.dst
    
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
```

Each layer provides different information. Link layer gives MAC addresses, network layer gives IPs, transport layer gives ports.

### Common Attacks

1. **Protocol tunneling** - Attackers hide malicious traffic inside legitimate protocols. DNS tunneling exfiltrates data in DNS queries. ICMP tunneling runs shells over ping packets. HTTP tunneling bypasses firewalls. Detection requires protocol analysis to spot unusual patterns.

2. **Header manipulation** - TCP flag manipulation (FIN scan, NULL scan, Xmas scan) probes ports without completing handshakes. IP fragmentation attacks overwhelm reassembly buffers. Defend by validating protocol conformance.

3. **Encrypted payload inspection** - Even encrypted traffic reveals metadata. TLS handshakes show certificate details, SNI indicates destination hostnames, packet sizes and timing reveal application behavior. Traffic analysis attacks work without decryption.

### Real World Example

The 2013 Snowden revelations showed NSA's XKEYSCORE system performing protocol analysis at scale. It captured metadata from all layers (IPs, ports, protocols, certificate details) and correlated it for target identification. You didn't need to decrypt traffic to identify users and map network relationships.

## Thread Safety and Concurrency

### What It Is

Thread-safe code can be called from multiple threads simultaneously without corrupting data. This requires synchronization primitives like locks, queues, or atomic operations. Without thread safety, concurrent access causes race conditions where the outcome depends on thread timing.

### Why It Matters

Packet capture is inherently concurrent. Packets arrive asynchronously while you're processing previous packets. Drop packets and you miss security events. Block the capture thread and you drop packets. The solution is producer-consumer threading with a queue buffer.

From `capture.py:46-62`:

```python
def __init__(
    self,
    config: CaptureConfig,
    on_packet: Callable[[PacketInfo], None] | None = None,
    queue_size: int = CaptureDefaults.QUEUE_SIZE,
) -> None:
    self._queue: Queue[Packet] = Queue(maxsize = queue_size)
    self._stats = StatisticsCollector()
    self._stop_event = threading.Event()
    self._packet_count = 0
    self._dropped_packets = 0
    self._count_lock = threading.Lock()
```

The Queue is thread-safe by default. The lock protects counter variables that multiple threads modify.

### How It Works

Producer-consumer pattern separates capture from processing:

```
Producer Thread          Consumer Thread
(Scapy AsyncSniffer)     (Processing Loop)
       ↓                        ↓
   Capture packet          Get from queue
       ↓                        ↓
   Put in queue           Analyze packet
       ↓                        ↓
   Repeat                 Update statistics
```

The queue decouples threads. Producer never blocks on slow processing. Consumer processes at its own pace. Buffer size determines memory usage versus packet loss tradeoff.

From `statistics.py:47-67`, the collector uses a lock for thread safety:

```python
def record_packet(self, packet: PacketInfo) -> None:
    with self._lock:
        self._total_packets += 1
        self._total_bytes += packet.size
        self._interval_packets += 1
        self._interval_bytes += packet.size
        
        self._protocol_counts[packet.protocol] += 1
        self._protocol_bytes[packet.protocol] += packet.size
```

The `with self._lock:` ensures only one thread modifies statistics at a time. Without it, counter increments would race and drop counts.

### Common Pitfalls

**Mistake 1: Forgetting to protect shared state**
```python
# Bad - race condition on packet_count
def _process_packet(self, packet):
    self.packet_count += 1  # Not atomic! 
```

Multiple threads read-modify-write the same variable. Thread A reads 100, Thread B reads 100, both write 101. You lost a count. Use locks or atomic operations.

**Mistake 2: Holding locks too long**
```python
# Bad - blocks all threads during slow I/O
with self._lock:
    write_to_disk(data)  # File I/O with lock held
```

Locks serialize execution. Hold them only during the critical section, never during I/O or expensive computation. From `statistics.py:127-143`, the lock protects data copying, not computation:

```python
def get_statistics(self) -> CaptureStatistics:
    with self._lock:
        return CaptureStatistics(
            start_time = self._start_time,
            total_packets = self._total_packets,
            protocol_distribution = dict(self._protocol_counts),
        )
```

The dict() copy happens inside the lock because it modifies shared data. Formatting and processing happen outside the lock.

## Network Baseline and Anomaly Detection

### What It Is

A network baseline describes normal behavior: typical protocol ratios, bandwidth patterns, communication pairs. Anomaly detection compares current traffic against the baseline to identify deviations. Significant deviations trigger alerts for investigation.

### Why It Matters

The 2010 Stuxnet worm spread via USB drives but communicated with command and control servers over HTTP. Network baselines would have flagged unusual HTTP connections from industrial control systems that normally never access the internet. Anomaly detection catches threats that signature-based systems miss.

### How It Works

This project collects the data needed for baseline establishment. From `models.py:95-123`, CaptureStatistics tracks:

```python
@dataclass(slots = True)
class CaptureStatistics:
    protocol_distribution: dict[Protocol, int] = field(default_factory = dict)
    endpoints: dict[str, EndpointStats] = field(default_factory = dict)
    conversations: dict[tuple[str, str], ConversationStats] = field(default_factory = dict)
    bandwidth_samples: list[BandwidthSample] = field(default_factory = list)
```

Protocol distribution shows normal traffic mix. If your network is usually 60% TCP, 30% UDP, 10% other, a sudden shift to 90% ICMP indicates something wrong (possibly a ping flood).

Endpoint statistics track who talks to whom. From `statistics.py:82-96`:

```python
def _update_endpoint(
    self,
    ip_address: str,
    sent_bytes: int = 0,
    received_bytes: int = 0,
) -> None:
    if ip_address not in self._endpoints:
        self._endpoints[ip_address] = EndpointStats(
            ip_address = ip_address
        )
    
    endpoint = self._endpoints[ip_address]
    endpoint.bytes_sent += sent_bytes
    endpoint.bytes_received += received_bytes
```

Track per-IP bandwidth over time. A workstation suddenly transferring gigabytes is worth investigating.

### Detection Techniques

**Statistical anomaly detection:**
- Calculate mean and standard deviation for each metric
- Alert when current value exceeds mean + 3σ
- Works for bandwidth, packet rates, protocol ratios

**Behavioral analysis:**
- Track communication graphs (who talks to whom)
- Alert on new connections to unusual destinations  
- Detect lateral movement in breaches

**Time series analysis:**
- Sample bandwidth every second (`statistics.py:112-127`)
- Look for sudden spikes or drops
- DDoS attacks show as dramatic rate increases

## How These Concepts Relate

The concepts build on each other in layers:

```
Raw Socket Access
      ↓
 BPF Filtering (efficiency)
      ↓
Protocol Analysis (understanding)
      ↓
Thread-Safe Collection (scale)
      ↓
Baseline Establishment (detection)
```

You need raw sockets to see packets. BPF makes it efficient. Protocol analysis extracts meaning. Thread safety enables real-time processing. Baselines enable security monitoring.

## Industry Standards and Frameworks

### OWASP Top 10

This project addresses:

- **A01:2021 - Broken Access Control** - Packet capture requires explicit privilege checking. The code validates CAP_NET_RAW on Linux, Administrator on Windows, and fails clearly when permissions are insufficient (`capture.py:341-375`).

- **A04:2021 - Insecure Design** - Producer-consumer pattern with bounded queues prevents resource exhaustion. Queue size limits memory usage even under packet floods (`capture.py:46-47`).

### MITRE ATT&CK

Relevant techniques:

- **T1040 - Network Sniffing** - This tool implements the technique attackers use. Understanding how packet capture works helps detect when adversaries deploy sniffers. Look for promiscuous mode interfaces and unusual capture process execution.

- **T1071 - Application Layer Protocol** - Protocol identification code shows how to detect command and control traffic hiding in HTTP/HTTPS. C2 frameworks like Cobalt Strike use DNS or HTTP for covert channels.

- **T1048 - Exfiltration Over Alternative Protocol** - DNS tunneling and ICMP exfiltration show up in protocol distributions. Baseline detection flags unusual protocol usage patterns.

### CWE

Common weakness enumerations covered:

- **CWE-362 - Concurrent Execution using Shared Resource with Improper Synchronization** - The project demonstrates proper locking patterns for shared statistics. Race conditions in packet counters would cause incorrect metrics (`statistics.py:47-67`).

- **CWE-400 - Uncontrolled Resource Consumption** - Bounded queue with configurable size prevents memory exhaustion during traffic spikes. Production systems need backpressure mechanisms (`capture.py:77-80`).

## Real World Examples

### Case Study 1: Anthem Health Insurance Breach (2015)

Attackers compromised Anthem's network and exfiltrated 78.8 million records over several months. Network monitoring detected unusual database-to-external connections but alerts were ignored. Proper packet capture and baseline analysis would have flagged:

- Database servers initiating outbound HTTPS connections (unusual behavior)
- Large data transfers during off hours (bandwidth anomaly)
- Connections to newly registered domains (reputation-based detection)

The breach cost $115 million in settlements. Network visibility through packet analysis isn't optional for sensitive data environments.

### Case Study 2: SolarWinds Supply Chain Attack (2020)

The SUNBURST backdoor communicated via DNS for command and control. It resolved subdomains of avsvmcloud.com to receive instructions. Traditional defenses missed this because:

- DNS is allowed outbound on all networks
- TLS encryption hid HTTP callback payload
- Legitimate software (Orion) was doing the communication

However, packet-level analysis revealed anomalies:

- Unusual volume of DNS queries from servers
- Subdomains with high entropy (random-looking)
- DNS responses with suspiciously long TTLs

Network monitoring tools using packet capture techniques eventually identified compromised systems by analyzing DNS metadata patterns, not payload content.

## Testing Your Understanding

Before moving to the architecture, make sure you can answer:

1. Why does packet capture require elevated privileges, and what specific kernel capability does it need on Linux? How would you grant this capability without making a program fully root-privileged?

2. Explain how BPF filtering improves packet capture performance compared to filtering in userspace. Why is this critical for high-speed networks? What happens at 10 Gbps without BPF?

3. In the producer-consumer pattern used by this project, what would happen if the consumer thread blocks for 10 seconds? How does the Queue prevent data loss? What's the tradeoff between queue size and memory usage?

If these questions feel unclear, re-read the relevant sections. The implementation will make more sense once these fundamentals click.

## Further Reading

**Essential:**

- **"The TCP/IP Guide" by Charles Kozierok** - Comprehensive protocol reference. Read the sections on Ethernet framing, IP routing, TCP connection management, and UDP datagram handling. These are the protocols you'll dissect in packet captures.

- **"Building an IDS" (SANS Reading Room)** - Explains network monitoring architecture patterns. The producer-consumer pattern, signature matching, and statistical analysis concepts apply directly to this project.

**Deep dives:**

- **"The BSD Packet Filter: A New Architecture for User-level Packet Capture" (McCanne & Jacobson, 1993)** - Original BPF paper. Explains the virtual machine design and why kernel-level filtering is necessary. Read this when you want to understand BPF internals.

- **PCAP API documentation (tcpdump.org)** - Scapy wraps libpcap/WinPcap/Npcap. Understanding the underlying C API helps debug capture issues and explains Scapy's design decisions.

**Historical context:**

- **"A Look Back at 'Security Problems in the TCP/IP Protocol Suite'" (Bellovin, 1989)** - Shows that many network attacks are decades old. Protocol design flaws from 1989 still affect security today. Understanding the history prevents repeating mistakes.
