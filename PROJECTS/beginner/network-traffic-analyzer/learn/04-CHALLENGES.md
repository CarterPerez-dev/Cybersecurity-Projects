# Extension Challenges

You've built the base project. Now make it yours by extending it with new features.

These challenges are ordered by difficulty. Start with the easier ones to build confidence, then tackle the harder ones when you want to dive deeper.

## Easy Challenges

### Challenge 1: Add IPv6 Support Display

**What to build:**
Enhance the protocol identification to explicitly recognize and display IPv6 packets separately from IPv4. Currently both show as IP addresses but aren't distinguished.

**Why it's useful:**
IPv6 adoption is growing. Network monitoring tools need to track IPv4 vs IPv6 traffic separately to understand migration progress and troubleshoot dual-stack issues.

**What you'll learn:**
- Working with Scapy's IPv6 layer
- Extending the Protocol enum
- Modifying analyzer logic

**Hints:**
- Look at `analyzer.py:51-103` where extract_packet_info() handles IP layer
- Add check for `packet.haslayer(IPv6)` alongside IP check
- May want to add Protocol.IPv6 to enum or track as metadata
- Don't forget to handle cases where both IPv4 and IPv6 are present (tunnels)

**Test it works:**
```bash
# Generate IPv6 traffic
ping6 ::1

# Capture and verify IPv6 shows separately
sudo netanal capture -i lo -c 10 --verbose
```

You should see IPv6 addresses in output and statistics tracking both protocol versions.

### Challenge 2: MAC Address OUI Lookup

**What to build:**
Add manufacturer identification from MAC addresses using the OUI (first 3 bytes). Display "Apple Inc." instead of just "a4:83:e7:..."

**Why it's useful:**
During incident response, knowing device manufacturers helps identify what's on the network. "Unknown Apple device" is more useful than cryptic MAC address.

**What you'll learn:**
- MAC address parsing
- OUI database lookups
- Caching strategies

**Implementation approach:**

1. **Download OUI database** from IEEE
   - File: http://standards-oui.ieee.org/oui/oui.txt
   - Parse into dict: `{"A483E7": "Apple, Inc."}`

2. **Add lookup function** in new file `netanal/mac_lookup.py`
   ```python
   def lookup_manufacturer(mac_address: str) -> str:
       oui = mac_address.replace(":", "")[:6].upper()
       return OUI_DATABASE.get(oui, "Unknown")
   ```

3. **Integrate with output** in `output.py:print_packet()`
   - Show manufacturer after MAC address
   - Example: "a4:83:e7:12:34:56 (Apple Inc.)"

**Test it works:**
Capture traffic on your local network. Manufacturers should appear for recognized devices.

### Challenge 3: Bandwidth Alert Threshold

**What to build:**
Add command-line argument `--alert-threshold` that triggers visual alert when bandwidth exceeds specified MB/s.

**Why it's useful:**
Real-time alerting during capture lets operators react immediately to traffic spikes, potential attacks, or misconfigurations.

**What you'll learn:**
- Real-time monitoring patterns
- Console notification techniques
- Threshold comparisons in streaming data

**Hints:**
- Add to CaptureConfig in `models.py:135-145`
- Check threshold in `statistics.py:112-127` when recording bandwidth samples
- Use `output.py:print_warning()` or print_error() for alerts
- Consider using Rich's Panel for prominent alerts

**Test it works:**
```bash
# Alert on >1 MB/s
sudo netanal capture -i eth0 --alert-threshold 1.0

# Generate traffic to trigger
curl -O https://speed.hetzner.de/100MB.bin
```

Alert should appear in red when threshold exceeded.

## Intermediate Challenges

### Challenge 4: TCP Connection Tracking

**What to build:**
Track TCP three-way handshakes and connection states (SYN, SYN-ACK, ACK, FIN). Display incomplete handshakes (potential SYN floods) and long-lived connections.

**Real world application:**
SYN flood DDoS attacks send SYN packets without completing handshake. Detecting incomplete handshakes identifies attacks in progress. Long-lived connections might indicate persistent backdoors.

**What you'll learn:**
- TCP state machine
- Connection tuple tracking (src_ip, src_port, dst_ip, dst_port)
- Time-series data with connection lifetimes

**Implementation approach:**

1. **Create connection state tracker** in new file `netanal/tcp_tracker.py`
   ```python
   @dataclass
   class TCPConnection:
       src_ip: str
       src_port: int
       dst_ip: str
       dst_port: int
       state: str  # SYN_SENT, ESTABLISHED, FIN_WAIT, etc.
       start_time: float
       last_seen: float
   
   class TCPTracker:
       def __init__(self):
           self._connections: dict[tuple, TCPConnection] = {}
       
       def process_packet(self, packet: PacketInfo):
           # Extract TCP flags
           # Update connection state based on flags
           # Track in dict keyed by (src_ip, src_port, dst_ip, dst_port)
   ```

2. **Integrate with statistics collector**
   - Add TCPTracker to StatisticsCollector
   - Call tracker.process_packet() in record_packet()

3. **Add reporting** to show:
   - Incomplete handshakes (SYN without SYN-ACK)
   - Connections in each state
   - Longest-lived connections

**Gotchas:**
- TCP flags in Scapy: `packet[TCP].flags` is bitmask, check specific flags
- Connection direction matters: (A→B) is different from (B→A) 
- Timeout old connections to prevent memory leak

**Extra credit:**
Detect port scans by tracking many connections from one IP to different ports with SYN flags only.

### Challenge 5: DNS Query/Response Correlation

**What to build:**
Match DNS queries with their responses. Track query latency, failed queries, and which domains get queried most.

**Real world application:**
DNS is often the first indicator of compromise. Tracking query patterns detects DNS tunneling, C2 beaconing, and DGA (domain generation algorithm) malware.

**What you'll learn:**
- Request/response correlation using transaction IDs
- DNS protocol structure (query vs response flag)
- Time-based pattern detection

**Implementation approach:**

1. **Enhance DNS extraction** in `analyzer.py`
   ```python
   def extract_dns_info(packet: Packet) -> dict | None:
       if not packet.haslayer(DNS):
           return None
       
       dns = packet[DNS]
       return {
           "transaction_id": dns.id,
           "query": dns.qr == 0,  # 0 = query, 1 = response
           "domain": dns.qd.qname.decode() if dns.qd else None,
           "response_code": dns.rcode if dns.qr == 1 else None,
           "answers": [str(rr.rdata) for rr in dns.an] if dns.an else []
       }
   ```

2. **Track queries** in new DNSTracker class
   - Store pending queries keyed by transaction ID
   - Match responses to queries
   - Calculate latency: response_time - query_time
   - Track failures (NXDOMAIN, SERVFAIL)

3. **Report statistics**:
   - Average DNS latency
   - Most queried domains
   - Failed query percentage
   - Suspicious patterns (too many unique domains, high entropy domains)

**Testing:**
```bash
# Generate DNS traffic
nslookup google.com
nslookup nonexistent-domain-12345.com

# Capture and analyze
sudo netanal capture -i lo -c 20
```

Should show both successful and failed queries with latency measurements.

### Challenge 6: Packet Size Distribution Histogram

**What to build:**
Track distribution of packet sizes and generate histogram chart. Useful for detecting unusual traffic patterns.

**Real world application:**
Packet size distributions reveal application types. VoIP has consistent small packets. File transfers have large packets. DDoS attacks often use specific sizes (tiny for amplification, large for volumetric).

**What you'll learn:**
- Histogram generation with bins
- Statistical distribution analysis
- Custom matplotlib visualizations

**Implementation approach:**

1. **Add size tracking** to StatisticsCollector
   ```python
   # In statistics.py
   def __init__(self):
       # ... existing init
       self._size_buckets: dict[int, int] = defaultdict(int)
       self._size_bins = [64, 128, 256, 512, 1024, 1500, 9000]
   
   def _get_size_bucket(self, size: int) -> int:
       for bin_size in self._size_bins:
           if size <= bin_size:
               return bin_size
       return self._size_bins[-1]
   ```

2. **Create histogram chart** in `visualization.py`
   ```python
   def create_size_histogram(
       stats: CaptureStatistics,
       title: str = "Packet Size Distribution"
   ) -> Figure:
       # Create bar chart with size bins
       # X-axis: packet size ranges
       # Y-axis: count or percentage
   ```

3. **Add to CLI** in `main.py:chart()` command
   - New chart type: `--type size-histogram`

**Test it works:**
Mix traffic types and observe distribution differences:
```bash
# HTTP traffic (varied sizes)
curl http://example.com

# DNS traffic (small consistent sizes)  
for i in {1..10}; do nslookup google.com; done

# Analyze
sudo netanal capture -i lo -c 100
netanal chart captured.pcap --type size-histogram
```

## Advanced Challenges

### Challenge 7: Geolocation IP Mapping

**What to build:**
Add GeoIP lookup to show country/city for external IPs. Display top talkers with geographic location and generate world map visualization.

**Why this is hard:**
Requires external GeoIP database, coordinate transformation for map plotting, and handling edge cases (private IPs, localhost, unknown locations).

**What you'll learn:**
- GeoIP database integration (MaxMind or IP2Location)
- Geographic data visualization
- Coordinate system transformations
- Database file handling and updates

**Architecture changes needed:**

```
New Components:
- netanal/geoip.py → GeoIP lookup class
- Matplotlib basemap → World map plotting
- Database file → GeoLite2 or similar

Modified:
- EndpointStats → Add location fields
- statistics.py → Call GeoIP on new endpoints
- visualization.py → New map chart function
```

**Implementation steps:**

1. **Research phase**
   - Read MaxMind GeoLite2 documentation
   - Understand database format (MMDB)
   - Look at geoip2 Python library

2. **Design phase**
   - Decide: bundled database vs user download?
   - Consider: cache lookups to avoid repeated database hits
   - Plan: what to do with private IPs (don't lookup)

3. **Implementation phase**
   - Start with simple country lookup
   - Add city and lat/long
   - Create world map scatter plot with matplotlib
   - Size points by traffic volume

4. **Testing phase**
   - Test with public IPs (8.8.8.8, 1.1.1.1)
   - Verify private IPs skip lookup
   - Check map rendering with actual traffic

**Gotchas:**
- MaxMind requires free account signup for database download
- Private IPs (192.168.x.x, 10.x.x.x) should skip lookup
- Localhost (127.0.0.1) has no geographic location
- Database files are large (~100MB), consider gitignore

**Resources:**
- MaxMind GeoLite2 (https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
- geoip2 Python library documentation
- matplotlib Basemap tutorial

### Challenge 8: SSL/TLS Certificate Extraction

**What to build:**
Extract and display SSL/TLS certificate information from HTTPS handshakes. Show certificate subject, issuer, validity dates, and certificate chain.

**Why this is hard:**
Requires parsing TLS handshake protocol, handling multiple TLS versions, extracting X.509 certificates, and dealing with fragmented handshakes.

**What you'll learn:**
- TLS handshake protocol structure
- X.509 certificate format
- Scapy TLS layer usage
- Certificate chain validation concepts

**Implementation steps:**

**Phase 1: Basic Certificate Extraction** (8-10 hours)
```python
# In analyzer.py, add TLS extraction
from scapy.layers.tls.record import TLS
from scapy.layers.tls.handshake import TLSServerHello, TLSCertificate

def extract_tls_info(packet: Packet) -> dict | None:
    if not packet.haslayer(TLS):
        return None
    
    # Extract certificates from TLS handshake
    # Parse X.509 certificate fields
    # Return dict with subject, issuer, dates
```

**Phase 2: Certificate Chain Handling** (10-12 hours)
- Handle multiple certificates in chain
- Track root, intermediate, and leaf certificates
- Show certificate hierarchy

**Phase 3: Integration and Display** (6-8 hours)
- Add to statistics tracking
- Create certificate report table
- Flag expired or self-signed certificates

**Phase 4: Advanced Features** (8-10 hours)
- SNI (Server Name Indication) extraction
- Cipher suite detection
- TLS version tracking
- Weak cipher alerts

**Testing strategy:**
```bash
# Generate HTTPS traffic
curl https://google.com
curl https://expired.badssl.com  # Test expired cert

# Capture and analyze
sudo netanal capture -i eth0 --filter "tcp port 443" -c 50
```

**Known challenges:**

1. **TLS fragmentation**
   - Problem: Certificates span multiple TCP segments
   - Hint: May need TCP stream reassembly (Challenge 4 helps)

2. **TLS versions**
   - Problem: TLS 1.0, 1.1, 1.2, 1.3 have different structures
   - Hint: Use Scapy's TLS layer which abstracts versions

**Success criteria:**
Your implementation should:
- [ ] Extract certificate subject and issuer
- [ ] Show validity dates (not before, not after)
- [ ] Handle certificate chains
- [ ] Display SNI hostname
- [ ] Flag expired certificates
- [ ] Work with TLS 1.2 and 1.3

### Challenge 9: Real-Time Anomaly Detection

**What to build:**
Implement statistical anomaly detection that alerts on unusual traffic patterns in real time during capture. Detect bandwidth spikes, unusual protocol ratios, and new connections to strange ports.

**Estimated time:**
2-3 weeks for full implementation

**Prerequisites:**
Complete Challenge 4 (TCP tracking) and Challenge 6 (size distribution) first, as this builds on those patterns.

**What you'll learn:**
- Statistical process control
- Z-score calculations for outlier detection  
- Moving averages and standard deviations
- Real-time alert generation
- Baseline learning vs anomaly detection modes

**Planning this feature:**

Before you code, think through:
- How do you establish a baseline? (Need "learning mode" period)
- What metrics indicate anomalies? (Bandwidth, protocol ratio, connection rate)
- How do you avoid alert fatigue? (Threshold tuning, cooldown periods)
- What's your false positive tolerance? (Z-score thresholds)

**High level architecture:**

```
┌─────────────────────────────────────┐
│     Baseline Establishment          │
│   (Learning Mode: 5-10 minutes)     │
│                                     │
│  - Collect normal traffic samples   │
│  - Calculate mean & std dev         │
│  - Store baseline metrics           │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│      Real-Time Detection            │
│   (Detection Mode: Continuous)      │
│                                     │
│  - Compare current vs baseline      │
│  - Calculate Z-scores               │
│  - Trigger alerts on outliers       │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│         Alert Handler               │
│                                     │
│  - Log anomaly details              │
│  - Display terminal alert           │
│  - Optional: webhook notification   │
└─────────────────────────────────────┘
```

**Implementation phases:**

**Phase 1: Baseline Collection** (12-16 hours)
Create new file `netanal/anomaly.py`:
```python
@dataclass
class BaselineMetrics:
    bandwidth_mean: float
    bandwidth_stddev: float
    protocol_ratios: dict[Protocol, float]
    connection_rate_mean: float
    connection_rate_stddev: float
    
class AnomalyDetector:
    def __init__(self, learning_period: int = 300):  # 5 minutes
        self._learning_mode = True
        self._samples: list[float] = []
        # ... more init
    
    def learn(self, stats: CaptureStatistics):
        # Collect samples during learning period
        # Calculate statistics
        pass
    
    def detect(self, stats: CaptureStatistics) -> list[Anomaly]:
        # Compare against baseline
        # Return list of detected anomalies
        pass
```

**Phase 2: Statistical Detection** (16-20 hours)
Implement Z-score calculations:
```python
def calculate_zscore(value: float, mean: float, stddev: float) -> float:
    if stddev == 0:
        return 0
    return (value - mean) / stddev

def is_anomaly(zscore: float, threshold: float = 3.0) -> bool:
    return abs(zscore) > threshold
```

Track multiple metrics:
- Bandwidth (bytes/second)
- Packet rate (packets/second)
- Protocol distribution (% TCP vs UDP vs other)
- Connection rate (new connections/second)
- Unique destination ports

**Phase 3: Alert Generation** (8-10 hours)
Create alert types:
```python
@dataclass
class Anomaly:
    timestamp: float
    metric: str  # "bandwidth", "protocol_ratio", etc.
    value: float
    expected: float
    severity: str  # "low", "medium", "high"
    description: str

def format_alert(anomaly: Anomaly) -> str:
    # Create human-readable alert message
    # Include what's unusual and by how much
```

**Phase 4: Integration** (6-8 hours)
- Add to CaptureEngine
- Call detector during bandwidth sampling
- Display alerts in real-time
- Log anomalies to file

**Testing strategy:**

Test with synthetic anomalies:
```python
# Test 1: Bandwidth spike
# Baseline: normal traffic
# Inject: large file download
# Expected: bandwidth anomaly alert

# Test 2: Protocol shift
# Baseline: 80% TCP, 20% UDP
# Inject: UDP flood
# Expected: protocol ratio anomaly

# Test 3: Port scan
# Baseline: connections to normal ports
# Inject: nmap scan
# Expected: high connection rate + unusual ports
```

**Known challenges:**

1. **Cold start problem**
   - Problem: No baseline on first run
   - Hint: Save learned baselines to disk, load on subsequent runs

2. **Concept drift**
   - Problem: Network behavior changes over time (new services, time of day)
   - Hint: Implement adaptive baselines that slowly update

**Success criteria:**
Your implementation should:
- [ ] Learn baseline in 5-10 minute period
- [ ] Detect bandwidth spikes (>3 std devs)
- [ ] Detect unusual protocol distributions
- [ ] Detect connection rate anomalies
- [ ] Display alerts in real time
- [ ] Include confidence score/severity
- [ ] Avoid excessive false positives (<10% during normal traffic)
- [ ] Save and load learned baselines

## Performance Challenges

### Challenge: Handle 10 Gbps Traffic

**The goal:**
Optimize the capture engine to handle 10 gigabit per second traffic without dropping packets.

**Current bottleneck:**
At 10 Gbps, you're processing ~10 million packets/second. Current code drops packets because:
- Queue fills (10K buffer is too small)
- Statistics lock contention (millions of lock acquisitions/sec)
- Python GIL limits parallelism
- Memory allocations slow garbage collection

**Optimization approaches:**

**Approach 1: Multiple Processing Threads**
- How: Use thread pool with N workers pulling from queue
- Gain: N× processing throughput
- Tradeoff: Need lock-free statistics or per-thread aggregation

**Approach 2: Lock-Free Statistics**
- How: Use per-thread counters, periodic aggregation
- Gain: Eliminates lock contention bottleneck
- Tradeoff: More complex code, eventual consistency

**Approach 3: Sampling**
- How: Process 1 out of every N packets
- Gain: Reduces CPU load proportionally
- Tradeoff: Statistical approximation, might miss rare events

**Approach 4: BPF Aggregation**
- How: Use eBPF to aggregate in kernel before userspace
- Gain: Massive performance improvement
- Tradeoff: Requires Linux, eBPF programming skills

**Benchmark it:**
```bash
# Generate high-speed traffic with iperf3
iperf3 -s &  # Server
iperf3 -c localhost -b 10G  # Client

# Monitor dropped packets
sudo netanal capture -i lo --verbose | grep "Dropped"
```

Target metrics:
- Dropped packets: <1% at 10 Gbps
- CPU usage: <80% on 8-core system
- Memory: <4 GB

## Security Challenges

### Challenge: Add PCAP Encryption

**What to implement:**
Encrypt captured PCAP files to protect sensitive network data. Add `--encrypt` flag that prompts for password and encrypts output using AES-256.

**Threat model:**
This protects against:
- Unauthorized access to captured files
- Accidental disclosure of sensitive traffic
- Compliance requirements (HIPAA, PCI-DSS)

**Implementation:**
Use cryptography library:
```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2

def encrypt_pcap(filepath: Path, password: str):
    # Derive key from password using PBKDF2
    # Encrypt file with Fernet (AES-128-CBC + HMAC)
    # Write encrypted output with .enc extension
```

**Testing the security:**
- Try opening encrypted file with Wireshark (should fail)
- Verify password required for decryption
- Check that weak passwords are rejected

### Challenge: Pass CIS Benchmark Checklist

**The goal:**
Make this project compliant with relevant CIS (Center for Internet Security) controls for network monitoring tools.

**Current gaps:**

**Gap 1: No audit logging**
- Missing: Who ran captures, when, what filters used
- Remediation: Add audit log to ~/.netanal/audit.log

**Gap 2: No input sanitization documentation**
- Missing: Clear documentation of validated inputs
- Remediation: Document all validation in security.md

**Gap 3: No resource limits**
- Missing: Unbounded memory if misconfigured
- Remediation: Add hard limits with configuration

**Gap 4: Privilege escalation without logging**
- Missing: No record of when root privileges used
- Remediation: Log all elevated operations

**Gap 5: No secure defaults**
- Missing: Defaults allow promiscuous mode, any interface
- Remediation: Require explicit interface specification

Each gap maps to specific CIS controls. Implement fixes and document compliance.

## Mix and Match

Combine features for bigger projects:

**Project Idea 1: Network Security Dashboard**
- Combine Challenge 4 (TCP tracking) + Challenge 9 (anomaly detection) + Challenge 7 (geolocation)
- Add web UI showing real-time map of connections with anomaly highlights
- Result: Visual SOC dashboard for network monitoring

**Project Idea 2: DNS Security Monitor**
- Combine Challenge 5 (DNS tracking) + Challenge 9 (anomaly detection)
- Add DGA detection (domain entropy analysis)
- Result: DNS-specific security monitoring tool

**Project Idea 3: Encrypted Traffic Analysis**
- Combine Challenge 8 (TLS extraction) + Challenge 4 (TCP tracking)
- Add JA3 fingerprinting (TLS client identification)
- Result: Detect malware by TLS patterns without decryption

## Real World Integration Challenges

### Integrate with SIEM (Splunk/ELK)

**The goal:**
Send capture statistics to a SIEM for central logging and correlation.

**What you'll need:**
- SIEM instance (free Splunk or ELK stack)
- HTTP Event Collector (Splunk) or Logstash endpoint (ELK)
- JSON formatting for events

**Implementation plan:**
1. Create `netanal/siem.py` with SIEM client
2. Add `--siem-url` CLI argument
3. Serialize statistics to JSON
4. POST to SIEM endpoint every N seconds
5. Handle connection failures gracefully

**Watch out for:**
- Rate limits on SIEM ingestion
- Authentication (API keys)
- Network failures (queue unsent events)
- Data privacy (don't send packet payloads)

**Production checklist:**
- [ ] TLS for SIEM connection
- [ ] API key from environment variable
- [ ] Retry logic with exponential backoff
- [ ] Local queue for offline operation

### Deploy to Kubernetes

**The goal:**
Package the tool as a container and deploy as DaemonSet for cluster-wide network monitoring.

**What you'll learn:**
- Docker containerization
- Kubernetes networking
- Privilege management in containers
- Distributed data collection

**Steps:**

1. **Create Dockerfile**
   ```dockerfile
   FROM python:3.14-slim
   RUN apt-get update && apt-get install -y libpcap-dev
   COPY . /app
   WORKDIR /app
   RUN pip install -e .
   CMD ["netanal", "capture"]
   ```

2. **Build container**
   ```bash
   docker build -t netanal:latest .
   ```

3. **Create Kubernetes manifest**
   ```yaml
   apiVersion: apps/v1
   kind: DaemonSet
   metadata:
     name: netanal
   spec:
     template:
       spec:
         hostNetwork: true  # Required for packet capture
         containers:
         - name: netanal
           image: netanal:latest
           securityContext:
             capabilities:
               add: ["NET_RAW", "NET_ADMIN"]
   ```

4. **Deploy**
   ```bash
   kubectl apply -f netanal-daemonset.yaml
   ```

**Production checklist:**
- [ ] Non-root user in container
- [ ] Only required capabilities (NET_RAW)
- [ ] Resource limits (CPU/memory)
- [ ] Log aggregation to central collector
- [ ] Health check endpoints

## Getting Help

Stuck on a challenge?

1. **Debug systematically**
   - What did you expect to happen?
   - What actually happened?
   - What's the smallest test case that reproduces it?
   - Can you add print statements to narrow down the problem?

2. **Read the existing code**
   - Challenge 4 (TCP tracking) is similar to Challenge 5 (DNS tracking) - use same patterns
   - Visualization code already handles multiple chart types - extend it

3. **Search for similar problems**
   - "Scapy TCP flags" → finds examples of flag parsing
   - "Python statistical anomaly detection" → finds Z-score algorithms
   - "matplotlib world map" → finds basemap examples

4. **Ask for help**
   - Describe what you're trying to build
   - Show what you've tried
   - Explain what went wrong
   - Include relevant code snippets and error messages

Don't just paste "it doesn't work" with a stack trace. Explain your understanding of the problem.

## Challenge Completion

Track your progress:

**Easy:**
- [ ] IPv6 Support Display
- [ ] MAC Address OUI Lookup
- [ ] Bandwidth Alert Threshold

**Intermediate:**
- [ ] TCP Connection Tracking
- [ ] DNS Query/Response Correlation
- [ ] Packet Size Distribution Histogram

**Advanced:**
- [ ] Geolocation IP Mapping
- [ ] SSL/TLS Certificate Extraction
- [ ] Real-Time Anomaly Detection

**Performance:**
- [ ] Handle 10 Gbps Traffic

**Security:**
- [ ] PCAP Encryption
- [ ] CIS Benchmark Compliance

**Integration:**
- [ ] SIEM Integration
- [ ] Kubernetes Deployment

Completed all of them? You've mastered network packet analysis. Consider contributing your solutions back to the project or building something new like an IDS or network forensics tool.

## Challenge Yourself Further

### Build Something New

Use the concepts you learned here to build:
- **Wireless packet analyzer** - Extend to monitor 802.11 frames, detect deauth attacks
- **Industrial protocol analyzer** - Add support for Modbus/SCADA protocols
- **Network forensics tool** - Reconstruct file transfers, extract artifacts from pcaps

### Study Real Implementations

Compare your implementation to production tools:
- **Wireshark/tshark** - Look at display filters vs BPF, protocol dissectors
- **Zeek (formerly Bro)** - Study event-driven architecture, script extensibility
- **Suricata** - Examine multi-threading approach, GPU acceleration

Read their code, understand their tradeoffs, steal their good ideas.

### Write About It

Document your extension:
- Blog post explaining "How I added anomaly detection to a packet analyzer"
- Tutorial for others to implement your feature
- Comparison: Your approach vs how Wireshark does it

Teaching others is the best way to verify you understand it.
