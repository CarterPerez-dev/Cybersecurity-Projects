# Network Traffic Analyzer

## What This Is

A Python-based packet capture and analysis tool that sniffs network traffic in real time, identifies protocols, tracks bandwidth usage, and generates visual reports. Built with Scapy for packet capture, Rich for terminal output, and Matplotlib for charts.

## Why This Matters

Network visibility is the foundation of security monitoring. If you can't see what's happening on your network, you can't detect intrusions, data exfiltration, or policy violations. This project teaches you how packet capture actually works at the kernel level, not just how to run Wireshark.

**Real world scenarios where this applies:**

- **Incident response:** During the 2013 Target breach, network monitoring could have detected unusual connections between POS systems and external servers. Packet-level analysis shows what data is leaving your network and where it's going.

- **Performance troubleshooting:** When applications slow down, packet captures reveal if the issue is network latency, retransmissions, or application-level problems. Network teams use these tools daily to diagnose connectivity issues.

- **Security baseline:** You can't detect anomalies without knowing what normal looks like. Packet analyzers establish baseline traffic patterns, showing typical protocol distributions, bandwidth usage, and communication patterns across your network.

## What You'll Learn

This project teaches you how network packet capture works at the system level. By building it yourself, you'll understand:

**Security Concepts:**

- **Raw socket access** - Why packet capture requires root/administrator privileges, what CAP_NET_RAW does on Linux, and how BPF (Berkeley Packet Filter) enables efficient kernel-level filtering without copying every packet to userspace.

- **Protocol layer inspection** - How to dissect packets from Layer 2 (Ethernet frames with MAC addresses) through Layer 7 (HTTP requests), understanding what information exists at each layer and why attackers target specific layers.

- **Network baseline establishment** - Building statistical profiles of normal traffic to identify anomalies. You'll track protocol distributions, bandwidth patterns, and endpoint behavior that security teams use for threat detection.

**Technical Skills:**

- **Producer-consumer threading patterns** - Implementing thread-safe packet processing where one thread captures packets at wire speed while another analyzes them without dropping data. You'll use Python's Queue and threading.Lock for synchronization.

- **Kernel-level packet filtering** - Writing BPF filters that run in the kernel to efficiently drop unwanted packets before they reach userspace. This is how production monitoring systems handle gigabits of traffic without overwhelming the CPU.

- **Time-series data collection** - Sampling bandwidth and packet rates at regular intervals to build graphs showing traffic patterns over time. Critical for detecting DDoS attacks or unusual data transfers.

**Tools and Techniques:**

- **Scapy packet manipulation** - Using Python's most powerful packet crafting library to capture and dissect network traffic. You'll work with Scapy's layer system to extract IP addresses, ports, protocol types, and payload data from raw packets.

- **Rich terminal interfaces** - Building real-time dashboards that update during packet capture, showing protocol distributions, top talkers, and bandwidth usage with colored tables and progress indicators.

- **Matplotlib visualization** - Generating protocol distribution pie charts, bandwidth timelines, and top talker bar graphs from packet capture data. The same visualizations SOC analysts use to present network behavior.

## Prerequisites

Before starting, you should understand:

**Required knowledge:**

- **Python basics** - You need to read code using dataclasses, type hints, async/await patterns, and context managers. If `with open() as f:` or `async def function():` looks unfamiliar, review Python fundamentals first.

- **TCP/IP networking** - Know what an IP address is, understand the difference between TCP and UDP, recognize common ports (80 for HTTP, 443 for HTTPS, 53 for DNS). You should be able to explain what a three-way handshake does.

- **Command line comfort** - This is a CLI tool. You'll be running commands in a terminal, passing arguments, setting environment variables, and reading output. Basic shell navigation (cd, ls, cat) is assumed.

**Tools you'll need:**

- **Python 3.14+** - The project uses modern Python features like match statements and improved type hints. Earlier versions won't work.

- **Root/admin access** - Packet capture requires raw socket permissions. On Linux you need root or CAP_NET_RAW capability. On macOS you need root or access to /dev/bpf devices. On Windows you need Administrator privileges and Npcap installed.

- **Scapy, Rich, Matplotlib** - Install via pip. Scapy does the packet capture, Rich makes the terminal output pretty, Matplotlib generates charts.

**Helpful but not required:**

- **Wireshark experience** - If you've used Wireshark to analyze pcap files, you'll recognize concepts like protocol hierarchies, filter expressions, and conversation tracking. But it's not necessary.

- **Systems programming** - Understanding how system calls work, what the kernel does versus userspace, and why context switches are expensive will help you appreciate the architecture choices. Not required to build the project though.

## Quick Start

Get the project running locally:

```bash
# Navigate to the project directory
cd network-traffic-analyzer

# Install dependencies
pip install -e .

# List available network interfaces
sudo netanal interfaces

# Capture 50 packets on your loopback interface
sudo netanal capture -i lo -c 50 --verbose

# Analyze an existing pcap file
netanal analyze traffic.pcap --top-talkers 20

# Generate charts from captured data
netanal chart traffic.pcap --type all -d ./charts/
```

Expected output: You'll see a real-time packet stream showing source/destination IPs, protocols, and packet sizes. When capture completes, you get summary statistics showing protocol distribution, top talkers by traffic volume, and bandwidth graphs.

## Project Structure

```
network-traffic-analyzer/
├── src/netanal/
│   ├── capture.py        # Producer-consumer packet capture engine
│   ├── analyzer.py       # Protocol identification and packet parsing
│   ├── filters.py        # BPF filter builder with validation
│   ├── statistics.py     # Thread-safe stats collector
│   ├── models.py         # Data structures (PacketInfo, Protocol enum)
│   ├── visualization.py  # Matplotlib chart generation
│   ├── export.py         # JSON/CSV data export
│   ├── output.py         # Rich console formatting
│   ├── main.py           # Typer CLI command definitions
│   ├── constants.py      # Configuration values
│   └── exceptions.py     # Custom exception hierarchy
├── tests/
│   ├── test_filters.py   # BPF filter builder tests
│   └── test_models.py    # Data model tests
└── pyproject.toml        # Project dependencies and metadata
```

## Next Steps

1. **Understand the concepts** - Read [01-CONCEPTS.md](./01-CONCEPTS.md) to learn about packet capture, protocol analysis, and network monitoring fundamentals
2. **Study the architecture** - Read [02-ARCHITECTURE.md](./02-ARCHITECTURE.md) to see the producer-consumer pattern and thread-safe design
3. **Walk through the code** - Read [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) for detailed code explanations with line numbers
4. **Extend the project** - Read [04-CHALLENGES.md](./04-CHALLENGES.md) for ideas like adding TCP stream reassembly or anomaly detection

## Common Issues

**Permission denied when capturing packets**
```
PermissionError: [Errno 1] Operation not permitted
```
Solution: Packet capture requires root privileges. Run with `sudo netanal capture` or add CAP_NET_RAW capability to your Python binary on Linux: `sudo setcap cap_net_raw+ep $(which python3)`

**Npcap not installed (Windows only)**
```
NpcapNotFoundError: Npcap is not installed
```
Solution: Download and install Npcap from https://npcap.com. This is Windows's packet capture driver. WinPcap is deprecated and won't work with modern Scapy.

**No packets captured on wireless interface**
```
Total Packets: 0
```
Solution: Many wireless adapters don't support promiscuous mode, or your OS blocks it. Try capturing on the loopback interface (`lo` on Linux/Mac, `Loopback Pseudo-Interface 1` on Windows) first to verify the tool works. For wireless, you may need monitor mode which requires different tools.

## Related Projects

If you found this interesting, check out:

- **Port Scanner** - Builds on network programming by actively probing ports instead of passively monitoring. Uses raw sockets to craft custom TCP/UDP packets.

- **Intrusion Detection System** - Takes packet analysis further by matching traffic against signatures of known attacks. Teaches pattern matching and alert generation.

- **SSL/TLS Inspector** - Analyzes encrypted connections by examining certificates and handshake metadata without decrypting payload. Shows what's visible even in encrypted traffic.
