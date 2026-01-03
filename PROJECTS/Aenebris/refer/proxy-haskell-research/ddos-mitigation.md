# DDoS Attack Mitigation: Comprehensive Implementation Guide

Modern DDoS attacks reached unprecedented scale in 2025, with Cloudflare blocking over 20.5 million attacks in Q1 alone—a 358% year-over-year surge. Organizations face multi-vector assaults combining volumetric floods, protocol exploitation, and application-layer attacks capable of exceeding 6.5 Tbps. This guide provides cybersecurity engineers with implementation-ready strategies spanning attack taxonomy, kernel-level optimizations, and behavioral detection to build resilient defense systems against contemporary DDoS threats.

## Attack landscape and defense imperative

The threat environment has fundamentally shifted. Attacks now leverage IoT botnets numbering in the millions, DNS amplification achieving 179x multiplication factors, and sophisticated low-and-slow techniques that evade traditional defenses. **Record-breaking attacks of 5.6 Tbps and 4.8 billion packets per second** demonstrate attackers' growing capabilities, while 30% of campaigns now deploy multiple attack vectors simultaneously to overwhelm single-layer protections.

Effective mitigation requires defense-in-depth: kernel hardening stops attacks at the earliest processing point, application-layer controls distinguish malicious from legitimate traffic, and behavioral analysis identifies coordinated campaigns. Organizations implementing these layered defenses achieve **96-100% detection accuracy** while maintaining service availability for legitimate users, processing millions of requests per second with sub-millisecond latency impact.

## DDoS attack taxonomy and technical specifications

### Volumetric attacks: Bandwidth saturation

Volumetric attacks constitute 75% of all DDoS campaigns, overwhelming network infrastructure through sheer traffic volume measured in gigabits per second or millions of packets per second.

**UDP floods** exploit the connectionless nature of UDP to generate massive packet storms. Attackers send UDP packets to random ports on target servers, forcing each system to check for listening applications and respond with ICMP "Destination Unreachable" messages when none exist. This process consumes CPU, memory, and bandwidth until services become unresponsive. Modern attacks achieve **25+ million packets per second**, with large campaigns exceeding 500 Gbps bandwidth consumption. Detection signatures include abnormally high UDP traffic to random ports, excessive ICMP error responses, and sudden spikes from diverse source IPs. Services relying on UDP—DNS, VoIP, gaming servers—experience degradation as state tables fill and network bandwidth saturates.

**ICMP floods** (ping floods) overwhelm targets with Echo Request packets requiring CPU cycles and network resources to process and generate replies. Each packet consumes both inbound bandwidth for echo-request and outbound for echo-reply, creating symmetrical exhaustion. While ICMP packets are typically small (64 bytes), botnets generating thousands to millions per second quickly saturate links. The "Ping of Death" variant sends oversized packets exceeding 65,535 bytes to trigger buffer overflows, though modern systems have largely mitigated this specific technique. Detection indicators include abnormal spikes in ICMP traffic, high CPU utilization on network devices, and increased latency for all services.

**DNS amplification attacks** represent the most dangerous volumetric vector, exploiting open DNS resolvers to achieve dramatic traffic multiplication. Attackers spoof source IPs to the victim's address, then send small DNS queries (60-80 bytes) requesting "ANY" record types to thousands of open resolvers. Each resolver responds with massive responses (3,000-4,000+ bytes) to the spoofed victim IP, creating **amplification factors of 30-70x** for standard queries and up to 179x for optimized attacks. A botnet with aggregate 10 Mbps bandwidth can generate 667 Mbps attack traffic; scaling to 1,000 devices produces 667 Gbps. Recent attacks routinely exceed 500 Gbps, with the 2018 GitHub attack peaking at 1.35 Tbps. Approximately 27 million DNS resolvers exist globally, with 25 million vulnerable to exploitation. Detection relies on stateful inspection showing DNS responses without corresponding requests, abnormally large response packets exceeding 512 bytes, and traffic concentrating from known open resolvers to single destinations.

### Protocol attacks: State exhaustion

Protocol attacks exploit weaknesses in network protocol implementations, targeting TCP/IP stack vulnerabilities and connection state tables at layers 3-4.

**SYN flood attacks** remain pervasive, representing 15-25% of all DDoS campaigns. The attack exploits TCP's three-way handshake: attackers send massive SYN packet volumes with spoofed source addresses, forcing servers to allocate resources (Transmission Control Blocks) for each half-open connection while waiting for final ACK packets that never arrive. Each TCB consumes 16-256 bytes memory, with typical backlog queues holding 128-1,024 half-open connections. Servers wait 75-511 seconds with exponential backoff before abandoning connections, allowing sustained attacks with moderate packet rates (10,000-50,000 SYN packets per second) to exhaust connection pools. Detection indicators include disproportionate SYN-to-SYN-ACK ratios, large numbers of connections in SYN_RECEIVED state, persistently full backlog queues, and increased SYN-ACK retransmission attempts. The 38-day sustained attack documented by Imperva demonstrates how SYN floods enable persistent denial of service.

**ACK flood attacks** target CPU processing rather than connection state. Attackers flood targets with TCP ACK packets containing invalid sequence numbers or belonging to non-existent connections. Stateful firewalls must process each ACK, checking against connection tables—an operation consuming significant CPU at high packet rates. While causing less state exhaustion than SYN floods, ACK floods at millions of packets per second overwhelm processing capacity, particularly on network devices performing stateful inspection. Detection focuses on high ACK rates without corresponding established connections, ACKs with invalid sequence numbers, and firewall CPU utilization spikes.

**Fragmentation attacks** exploit IP fragmentation mechanics to maximize resource consumption. Normal fragmentation splits large packets into Maximum Transmission Unit-sized pieces; targets buffer fragments and reassemble them—a process consuming more resources than processing complete packets. Attackers send high volumes of fragmented packets, sometimes with overlapping or invalid offset values (Teardrop attack variant), causing memory allocation for fragment buffers, CPU overhead for reassembly processing, and state table exhaustion tracking incomplete fragment sets. Detection indicators include abnormal fragmentation rates, fragments with malformed offset values, incomplete fragment sets timing out, and CPU/memory spikes on devices performing reassembly.

### Application-layer attacks: Resource depletion

Application-layer attacks (Layer 7) target application resources directly, consuming CPU, memory, database connections, and application threads while generating traffic indistinguishable from legitimate requests.

**HTTP floods** send massive HTTP GET or POST request volumes that appear legitimate, forcing servers to parse headers, query databases, and generate dynamic content. Each request consumes 100-1000x more resources than its bandwidth requirement, creating asymmetric impact where attackers with minimal bandwidth exhaust substantial server capacity. Modern attacks achieve **10,000-100,000 requests per second**, with the record 46 million RPS attack blocked by Google in 2022. Sophisticated variants employ cache-busting through randomized query strings, user-agent mimicking to appear as legitimate browsers, and targeting resource-intensive endpoints like search or complex database queries. HTTP DDoS attacks increased 93% year-over-year in 2024, with 60-73% launched by known botnets. Detection relies on identifying sudden request spikes, repetitive patterns with slight variations, abnormal POST request ratios, and origin servers returning high error rates (5xx status codes).

**Slowloris attacks** achieve denial of service with minimal bandwidth by exhausting connection pools rather than bandwidth. Attackers open multiple HTTP connections, send partial request headers without terminating sequences (missing final \\r\\n\\r\\n), then periodically send additional header fragments to prevent timeouts while never completing requests. Thread-based servers like Apache and IIS allocate worker threads to each connection, holding them indefinitely. Just 500-2,000 slow connections suffice to exhaust typical server connection pools of 150-600 concurrent connections. The attack operates with bandwidth under 1 Mbps, making detection challenging. Indicators include multiple connections from same IPs sending partial headers, connections remaining open for minutes to hours, unbalanced TCP handshakes (complete SYN/SYN-ACK but no meaningful data transfer), and increasing memory usage correlating with connection counts.

**Slow POST attacks** (R-U-Dead-Yet) similarly exploit connection holding but target POST body transmission. Attackers send HTTP POST requests with large Content-Length headers declaring gigabyte payloads, then transmit body data at 1 byte per second—just frequently enough to prevent server timeouts. Servers keep connections open awaiting complete POST data, with each connection consuming worker threads and memory buffers. Detection focuses on POST requests with abnormally large Content-Length values, extremely low transmission rates (under 1 KB/sec), long-duration connections with minimal data transfer, and applications showing full worker pools. Differentiation from legitimately slow clients challenges defenders, as traffic appears valid by HTTP standards without malformed packets or protocol violations.

## SYN flood protection mechanisms

### SYN cookies: Stateless handshake completion

SYN cookies provide the most effective SYN flood mitigation by eliminating state allocation during the initial handshake. When the SYN backlog queue fills, Linux automatically activates SYN cookies, encoding connection information (source IP, port, MSS, timestamp) into the sequence number of SYN-ACK responses. **No server-side state is allocated** until the client returns a valid ACK with the encoded sequence number, preventing half-open connection exhaustion.

Enable via sysctl:
```bash
sysctl -w net.ipv4.tcp_syncookies=1
```

Trade-offs include disabling TCP extensions (window scaling, SACK, timestamps) during cookie mode, though this cost is acceptable during attacks when service availability matters most. SYN cookies activate automatically when `tcp_max_syn_backlog` fills, providing last-resort protection while allowing the backlog queue to handle legitimate traffic under normal conditions.

### Rate limiting with iptables

Limit new connection establishment rates using hashlimit for per-IP tracking:

```bash
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW \
  -m hashlimit --hashlimit-above 20/sec --hashlimit-burst 60 \
  --hashlimit-mode srcip --hashlimit-name http --hashlimit-htable-size 32768 -j DROP
```

This configuration allows 20 new connections per second per IP with burst capacity of 60, dropping excess. The hashlimit module implements token bucket algorithm efficiently, with hash table size of 32,768 entries tracking unique source IPs. Tune `--hashlimit-above` based on legitimate client connection patterns—typical values range 10-50/sec for web traffic.

Alternative using limit module for global rate limiting:

```bash
iptables -A INPUT -p tcp -m tcp --syn -m limit --limit 60/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --syn -j DROP
```

This limits total SYN rate to 60/sec across all sources with burst allowance of 20, providing protection when per-IP tracking isn't required.

### Connection tracking optimization

Increase SYN backlog queue and overall connection limits to handle legitimate traffic spikes:

```bash
# Increase SYN backlog queue (default 128-1024)
sysctl -w net.ipv4.tcp_max_syn_backlog=4096

# Increase listen queue size for accept()
sysctl -w net.core.somaxconn=4096

# Reduce SYN-ACK retries to fail faster (default 5)
sysctl -w net.ipv4.tcp_synack_retries=2

# Increase connection tracking table (300 bytes per entry)
sysctl -w net.netfilter.nf_conntrack_max=1048576
```

Calculate `nf_conntrack_max` based on available RAM: each entry consumes approximately 300 bytes. For 1 million connections, allocate ~300 MB memory. Monitor usage:

```bash
cat /proc/sys/net/netfilter/nf_conntrack_count
cat /proc/sys/net/netfilter/nf_conntrack_max
```

When count approaches max, increase limits or reduce timeout values to free entries faster.

## HTTP flood mitigation strategies

### CAPTCHA and challenge-response integration

Deploy CAPTCHA challenges when anomalous request patterns emerge to differentiate humans from bots. Modern implementations use risk-based scoring rather than universal challenges, presenting CAPTCHAs only to suspicious traffic based on behavioral signals.

**Integration approaches:**
- JavaScript challenge validates browser execution capability before serving content
- Cookie validation ensures clients accept and persist session state
- HTTP redirect testing confirms proper HTTP stack implementation

Popular solutions include Google reCAPTCHA v3 (invisible, score-based), hCaptcha (privacy-focused alternative), and Cloudflare Turnstile (non-intrusive verification). Integrate at web application firewall or reverse proxy layer to filter traffic before reaching origin servers.

### Proof-of-work challenges

Client-side computational challenges force requesters to expend CPU cycles before receiving responses, increasing attack cost while minimally impacting legitimate users. Modern browsers solve JavaScript-based PoW puzzles in milliseconds, but bots attacking at scale face significant computational burden.

Implementation pattern: Server sends PoW challenge with difficulty parameter, client performs computation (hash-based puzzle), server validates result before fulfilling request. Calibrate difficulty based on server load—increase during attacks to throttle bot traffic while allowing humans to complete quickly.

### Request validation and filtering

**HTTP header analysis:** Validate User-Agent strings against known patterns, check for required headers (Host, Accept), verify header ordering matches legitimate browsers. Block requests with missing or malformed headers.

**Rate limiting per endpoint:** Apply aggressive limits to resource-intensive paths:

```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
limit_req_zone $binary_remote_addr zone=api:20m rate=100r/s;
limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;

location /login {
    limit_req zone=login burst=3 nodelay;
}
location /api/ {
    limit_req zone=api burst=50;
}
```

**Cookie/session validation:** Require valid session cookies for application access, rejecting requests without proper authentication flow. This filters bots unable to maintain session state.

**JavaScript validation:** Serve JavaScript challenges that set cookies or redirect, filtering non-browser clients. Combine with rate limiting to prevent bypass attempts.

**Web Application Firewall (WAF):** Deploy ModSecurity with OWASP Core Rule Set or commercial WAF to filter malicious patterns, SQL injection attempts, XSS payloads, and anomalous request sequences. WAFs provide signature-based and anomaly-based detection tuned for application-layer threats.

## Slowloris and slow POST attack defenses

### Timeout configuration for Apache

Enable and configure mod_reqtimeout (Apache 2.2.15+) to enforce minimum data rates and maximum header/body timeouts:

```apache
LoadModule reqtimeout_module modules/mod_reqtimeout.so

<IfModule mod_reqtimeout.c>
    # Header: 20-40 seconds total, minimum 500 bytes/sec
    # Body: 20 seconds initial + 1 sec per 500 bytes received
    RequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500
</IfModule>
```

**Parameters explained:**
- `header=20-40`: Initial 20 seconds to start sending headers, maximum 40 seconds total
- `MinRate=500`: Reject connections slower than 500 bytes/sec
- `body=20`: Initial 20 seconds to receive body data, extends by 1 second per 500 bytes

This configuration effectively blocks Slowloris and slow POST by rejecting connections that fail to maintain minimum transfer rates. Servers send 408 REQUEST TIMEOUT responses and close connections when thresholds exceeded.

Additional Apache timeouts:

```apache
# Overall request timeout (default 300)
Timeout 60

# Keep-alive connection timeout (default 5)
KeepAliveTimeout 5

# Maximum requests per keep-alive connection
MaxKeepAliveRequests 100
```

### Timeout configuration for Nginx

Nginx's event-based architecture provides inherent resistance to connection exhaustion, but proper timeout configuration enhances protection:

```nginx
http {
    # Time to read client request header
    client_header_timeout 10s;
    
    # Time between successive body data reads
    client_body_timeout 10s;
    
    # Keep-alive connection timeout
    keepalive_timeout 15s;
    
    # Time between successive writes to client
    send_timeout 10s;
    
    # Buffer limits prevent memory exhaustion
    client_body_buffer_size 128k;
    client_header_buffer_size 2k;
    client_max_body_size 10m;
    large_client_header_buffers 4 4k;
}
```

**Aggressive DDoS protection values:**

```nginx
client_header_timeout 5s;
client_body_timeout 5s;
keepalive_timeout 10s;
send_timeout 10s;
```

These shorter timeouts disconnect slow clients quickly, preventing connection pool exhaustion. Monitor 408 timeout error rates to validate legitimate users aren't impacted.

### Connection management with mod_qos

Deploy Apache mod_qos for comprehensive connection and rate limiting:

```apache
LoadModule qos_module modules/mod_qos.so

<IfModule mod_qos.c>
    # Track 500,000 unique client IPs (150 bytes per entry)
    QS_ClientEntries 500000
    
    # Maximum 20 concurrent connections per IP
    QS_SrvMaxConnPerIP 20
    
    # Maximum 512 total active connections
    QS_SrvMaxConn 512
    
    # Disable keep-alive when 400 connections active
    QS_SrvMaxConnClose 400
    
    # Minimum data rates: 200 bytes/sec download, 1500 upload
    QS_SrvMinDataRate 200 1500
    
    # Protect resource-intensive endpoints
    QS_LocRequestLimit "/login" 5
    QS_LocRequestLimit "/admin" 3
</IfModule>
```

**Key parameters:**
- `QS_SrvMaxConnPerIP`: Limits concurrent connections from single IP, blocking Slowloris attempts
- `QS_SrvMinDataRate`: Enforces minimum transfer rates, rejecting slow connections
- `QS_LocRequestLimit`: Per-endpoint rate limiting for sensitive paths

mod_qos adds 2-5% CPU overhead while blocking 90%+ of connection exhaustion attacks. Memory consumption: 150 bytes × QS_ClientEntries (75 MB for 500,000 entries).

### Connection limits in Nginx

Combine limit_conn for concurrent connections with limit_req for request rates:

```nginx
http {
    # Define zones for tracking
    limit_conn_zone $binary_remote_addr zone=addr:10m;
    limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    
    server {
        # Global: 10 concurrent connections per IP
        limit_conn addr 10;
        
        location / {
            limit_req zone=general burst=20 nodelay;
        }
        
        location /login {
            # Aggressive limits for authentication
            limit_conn addr 3;
            limit_req zone=login burst=2 nodelay;
        }
    }
}
```

**Memory calculation:** 10MB zone stores approximately 160,000 unique IPs (64 bytes per entry on 64-bit systems). Adjust zone size based on expected client diversity.

## Connection limiting and rate control

### Per-IP connection limits with iptables

The connlimit module enforces maximum concurrent connections per IP:

```bash
# Limit to 50 concurrent connections per IP on port 80
iptables -A INPUT -p tcp --syn --dport 80 \
  -m connlimit --connlimit-above 50 --connlimit-mask 32 \
  -j REJECT --reject-with tcp-reset
```

**Parameters:**
- `--connlimit-above N`: Reject when IP exceeds N connections
- `--connlimit-mask 32`: Per-IP tracking (IPv4); use 128 for IPv6
- `--connlimit-mask 24`: Per /24 subnet tracking (for NAT scenarios)

Typical values: 50-100 connections for web traffic, 20-50 for aggressive protection. Adjust based on legitimate client behavior—corporate NATs may require higher limits with subnet masking.

### Rate limiting algorithms

**Token bucket** (implemented by hashlimit): Tokens accumulate at fixed rate; requests consume tokens. Allows bursts while enforcing average rate.

```bash
iptables -A INPUT -p tcp --dport 443 \
  -m hashlimit --hashlimit-mode srcip \
  --hashlimit-upto 50/sec --hashlimit-burst 20 \
  --hashlimit-name https --hashlimit-htable-size 32768 -j ACCEPT
```

**Leaky bucket** (Nginx limit_req): Requests enter bucket, leak out at constant rate. No burst allowance—strict rate enforcement.

```nginx
limit_req_zone $binary_remote_addr zone=strict:10m rate=10r/s;
location / {
    limit_req zone=strict;  # No burst parameter
}
```

**Sliding window counter** (HAProxy stick tables): Most accurate, tracks requests in sliding time windows with weighted counters.

```haproxy
backend rate_limit
    stick-table type ip size 100k expire 60s store http_req_rate(10s)

frontend web
    http-request track-sc0 src table rate_limit
    http-request deny deny_status 429 if { sc0_http_req_rate gt 100 }
```

**Algorithm comparison:**

| Algorithm | Accuracy | Memory | CPU | Bursts | Use Case |
|-----------|----------|--------|-----|--------|----------|
| Token bucket | Good | Low | Low | Yes | Flexible, general |
| Leaky bucket | Excellent | Medium | Low | No | Strict rate control |
| Sliding window | Very good | Low | Low | Moderate | Production scale |
| Fixed window | Fair | Very low | Very low | No | Simple, high-volume |

For production DDoS mitigation, **sliding window counters provide optimal balance** with 99.99% accuracy and minimal memory overhead. Cloudflare reports 0.003% error rate at scale.

### Adaptive throttling strategies

**Dynamic rate adjustment:** Reduce limits as system load increases to maintain service availability.

```python
dynamic_limit = base_limit * (1 - load_factor * 0.75)
```

When CPU reaches 80%, apply 60% of baseline limits. When CPU exceeds 95%, apply 25% of baseline. Monitor system metrics (CPU, memory, connection count) and adjust thresholds in real-time.

**Behavioral-based limiting:** Track client behavior signals to differentiate legitimate users from attackers:
- Request timing and regularity
- Error rates (4xx/5xx responses)
- Session behavior (authentication, navigation patterns)
- Geographic consistency
- User-agent persistence

**HAProxy behavioral filtering:**

```haproxy
backend tracking
    stick-table type ip size 100k store http_req_rate(10s),http_err_rate(10s)

frontend web
    http-request track-sc0 src table tracking
    acl high_errors sc0_http_err_rate gt 10
    acl high_requests sc0_http_req_rate gt 50
    http-request deny if high_errors high_requests
```

**Whitelist management:** Exempt trusted IPs from rate limiting using Nginx geo module:

```nginx
geo $limit {
    default 1;
    10.0.0.0/8 0;           # Internal network
    66.249.64.0/19 0;       # Googlebot
    192.0.2.0/24 0;         # Trusted partners
}

map $limit $limit_key {
    0 "";  # Empty key bypasses rate limit
    1 $binary_remote_addr;
}

limit_req_zone $limit_key zone=req:10m rate=5r/s;
```

## Kernel-level mitigation techniques

### Complete iptables DDoS protection ruleset

Deploy rules in mangle table PREROUTING chain for **2-3x better performance** than filter/INPUT by filtering before connection tracking:

```bash
#!/bin/bash
# DDoS Protection Iptables Script

# Flush existing rules
iptables -F && iptables -X
iptables -t mangle -F && iptables -t mangle -X

### MANGLE TABLE - PREROUTING (Earliest filtering) ###

# Drop invalid packets
iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP

# Drop TCP packets without SYN in NEW state
iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

# Drop packets with invalid TCP MSS
iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW \
  -m tcpmss ! --mss 536:65535 -j DROP

# Drop TCP flag anomalies
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP

# Drop packets from private/bogon networks
iptables -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP
iptables -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP
iptables -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP
iptables -t mangle -A PREROUTING -s 10.0.0.0/8 -j DROP
iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP

# Drop fragmented packets (anti-fragmentation attack)
iptables -t mangle -A PREROUTING -f -j DROP

### INPUT CHAIN - Stateful filtering ###

# Accept established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Per-IP rate limiting (hashlimit - token bucket)
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW \
  -m hashlimit --hashlimit-above 20/sec --hashlimit-burst 60 \
  --hashlimit-mode srcip --hashlimit-name http --hashlimit-htable-size 32768 -j DROP

iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW \
  -m hashlimit --hashlimit-above 20/sec --hashlimit-burst 60 \
  --hashlimit-mode srcip --hashlimit-name https --hashlimit-htable-size 32768 -j DROP

# Per-IP connection limit
iptables -A INPUT -p tcp -m connlimit --connlimit-above 100 --connlimit-mask 32 \
  -j REJECT --reject-with tcp-reset

# SSH brute-force protection (recent module)
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW \
  -m recent --update --seconds 60 --hitcount 5 -j DROP

# Global SYN rate limit
iptables -A INPUT -p tcp --syn -m limit --limit 60/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# Accept localhost
iptables -A INPUT -i lo -j ACCEPT

# Accept specific services (customize as needed)
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Default policy: DROP
iptables -P INPUT DROP
iptables -P FORWARD DROP

# Save rules
iptables-save > /etc/iptables/rules.v4
```

**Module explanations:**
- **hashlimit:** Per-IP token bucket rate limiting, tracks individual sources with configurable hash table
- **connlimit:** Limits concurrent connections per IP/subnet
- **recent:** Lightweight tracking for brute-force protection, maintains recent connection lists
- **limit:** Global rate limiting without per-source tracking

**Performance:** Mangle table rules process packets before connection tracking overhead, achieving 3-5 million pps versus 1-2 million pps with filter table on single core.

### eBPF and XDP for high-performance filtering

eXpress Data Path (XDP) enables packet filtering at the NIC driver level before kernel stack processing, achieving **10-26 million packets per second per core**—10-40x faster than iptables.

**XDP program for rate limiting (xdp_ddos_protection.c):**

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

#define THRESHOLD 250
#define TIME_WINDOW_NS 1000000000

struct rate_limit_entry {
    __u64 last_update;
    __u32 packet_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct rate_limit_entry);
} rate_limit_map SEC(".maps");

SEC("xdp")
int ddos_protection(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;
    
    // Parse IP header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;
    
    __u32 src_ip = iph->saddr;
    struct rate_limit_entry *entry = bpf_map_lookup_elem(&rate_limit_map, &src_ip);
    __u64 current_time = bpf_ktime_get_ns();
    
    if (entry) {
        if (current_time - entry->last_update < TIME_WINDOW_NS) {
            entry->packet_count++;
            if (entry->packet_count > THRESHOLD) return XDP_DROP;
        } else {
            entry->last_update = current_time;
            entry->packet_count = 1;
        }
    } else {
        struct rate_limit_entry new_entry = {
            .last_update = current_time,
            .packet_count = 1
        };
        bpf_map_update_elem(&rate_limit_map, &src_ip, &new_entry, BPF_ANY);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

**Compile and attach:**

```bash
# Install dependencies
sudo apt-get install clang llvm libbpf-dev linux-headers-$(uname -r)

# Compile
clang -O2 -g -target bpf -c xdp_ddos_protection.c -o xdp_ddos_protection.o

# Attach to interface (native mode for best performance)
sudo ip link set dev eth0 xdp obj xdp_ddos_protection.o sec xdp

# Verify attachment
ip link show dev eth0

# Monitor statistics
sudo bpftool prog show
sudo ethtool -S eth0 | grep xdp

# Detach
sudo ip link set dev eth0 xdp off
```

**XDP operation modes:**
1. **Native XDP:** Runs in NIC driver—10-26M pps/core (requires driver support: ixgbe, i40e, mlx5)
2. **Offloaded XDP:** Runs on NIC hardware—100M+ pps (Netronome SmartNICs)
3. **Generic XDP:** Runs in kernel stack—5-10M pps (fallback for any NIC)

**XDP actions:**
- `XDP_DROP`: Drop packet at driver level (DDoS mitigation)
- `XDP_PASS`: Pass to network stack for normal processing
- `XDP_TX`: Hairpin packet back out same NIC (load balancing)
- `XDP_REDIRECT`: Redirect to another NIC or CPU
- `XDP_ABORTED`: Error handling

**Real-world performance:**
- **Cloudflare L4Drop:** 8+ million pps dropped, only 10% CPU increase during attacks
- **Meta Katran:** 20+ million pps L4 load balancing
- **Wikipedia:** 26 million pps packet drops on commodity hardware

**eBPF tools ecosystem:**
- **BCC:** Python/C framework for eBPF development
- **bpftrace:** DTrace-like tracing for monitoring
- **Cilium:** Production Kubernetes networking with eBPF/XDP

### Critical sysctl parameters

Comprehensive kernel hardening configuration (`/etc/sysctl.d/99-ddos-protection.conf`):

```bash
### SYN FLOOD PROTECTION ###
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.core.somaxconn = 4096

### TCP/IP STACK HARDENING ###
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.log_martians = 1

### CONNECTION TRACKING ###
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30

### TCP TIMEOUTS ###
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_tw_reuse = 1

### MEMORY AND BUFFER TUNING ###
net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_default = 262144
net.core.wmem_max = 16777216
net.ipv4.tcp_mem = 786432 1048576 26777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_max_orphans = 65536
net.core.netdev_max_backlog = 5000
net.ipv4.ip_local_port_range = 1024 65535

### FILE LIMITS ###
fs.file-max = 2097152
```

**Apply and verify:**

```bash
# Backup current configuration
sysctl -a > /root/sysctl-backup.txt

# Apply new settings
sysctl -p /etc/sysctl.d/99-ddos-protection.conf

# Verify specific setting
sysctl net.ipv4.tcp_syncookies

# Monitor SYN flood metrics
netstat -s | grep -i syn
watch -n 1 'cat /proc/net/netstat | grep Tcp'

# Check connection tracking usage
cat /proc/sys/net/netfilter/nf_conntrack_count
cat /proc/sys/net/netfilter/nf_conntrack_max
```

**Key parameter explanations:**

**tcp_syncookies (1):** Enables SYN cookies as last-resort protection when SYN backlog fills. Trades TCP extensions (window scaling, SACK, timestamps) for attack resistance.

**tcp_max_syn_backlog (4096):** Maximum size of SYN_RECV queue. Each entry consumes ~256 bytes. Calculate: Available_RAM / 16384 for baseline, increase for high-traffic servers.

**somaxconn (4096):** Maximum ESTABLISHED connection queue awaiting accept() syscall. Should match or exceed application listen() backlog parameter.

**nf_conntrack_max (1048576):** Maximum tracked connections for Netfilter stateful firewall. Each entry ~300 bytes. For 1M connections: 300 MB RAM. Monitor and increase as needed.

**tcp_fin_timeout (15):** Seconds to keep FIN-WAIT-2 sockets. Lower values (15-30) accelerate resource cleanup versus default 60.

**tcp_tw_reuse (1):** Safely reuses TIME-WAIT sockets for new connections when tcp_timestamps enabled. Essential for high connection rates.

**rp_filter (1):** Reverse path filtering via source validation, dropping packets from spoofed IPs. Prevents IP spoofing attacks.

## Behavioral analysis and anomaly detection

### Coordinated attack identification

Botnet-driven DDoS campaigns exhibit distinct patterns across multiple attack phases enabling early detection before full-scale assault begins.

**Attack lifecycle detection:**

1. **Scanning phase:** Botnets probe for vulnerable devices showing **sudden increase in connection attempts to common ports** (23-Telnet, 2323-Telnet alt, 80-HTTP, 8080-HTTP alt). NetFlow data reveals scanning patterns: high connection rates with low byte counts, sequential IP targeting, and consistent source port usage.

2. **C2 communication phase:** Infected devices beacon to command-and-control servers at periodic intervals. Detection methods achieve **100% accuracy with packet-based analysis** and 94% with flow-based methods. Key signatures include:
   - Periodic connection timing (beaconing at fixed intervals)
   - Consistent packet sizes and protocol usage
   - Time-based features account for 36.92% of detection importance
   - Protocol-based features contribute 38.46%

3. **Attack coordination:** Pre-attack indicators include synchronized connection establishment from distributed sources, sudden traffic pattern changes across multiple IPs, and protocol anomalies preceding volume increases.

**Multi-vector correlation:** Modern attacks combine volumetric (UDP/ICMP floods), protocol (SYN floods), and application-layer (HTTP floods) vectors simultaneously. Detection systems must correlate cross-protocol anomalies, analyze temporal synchronization patterns across attack types, and identify IP clustering indicating coordinated sources.

### Traffic pattern analysis methods

**Baseline establishment** forms the foundation for anomaly detection. Collect minimum 6 hours of normal traffic data capturing daily usage cycles, calculate statistical measures (mean, standard deviation, entropy) for packet rates, byte rates, flow duration, and protocol distribution. Establish upper and lower thresholds using 3-sigma rule: values beyond mean ± 3σ indicate potential attacks with 99.7% confidence under normal distribution.

**Shannon entropy analysis** provides highly effective DDoS detection based on traffic distribution randomness:

```
H(X) = -Σ p(xi) log₂ p(xi)
```

Where p(xi) represents probability of each unique value (source IP, destination port). **Normal traffic exhibits high entropy** (>0.25) due to diverse legitimate sources. **Attack traffic shows low entropy** as packets concentrate from limited botnet IPs. Detection accuracy: **98-99%** across multiple research implementations.

**Renyi entropy** offers generalized entropy calculation with tunable parameter 'q', outperforming Shannon entropy for detecting low-rate attacks. Dynamic threshold adaptation using Exponentially Weighted Moving Average (EWMA) maintains accuracy across varying traffic patterns.

**Kullback-Leibler divergence** measures statistical distance between attack and normal traffic distributions:

```
DKL(P||Q) = Σ P(x) log(P(x)/Q(x))
```

Effective for both high-volume floods and low-rate attacks through multi-dimensional analysis of packet size, inter-arrival time, protocol distribution, and port usage patterns.

**Time-series analysis:** Apply GARCH (Generalized Autoregressive Conditional Heteroskedasticity) models for non-stationary network traffic. Fixed time windows optimize detection—1 second intervals for packet-level analysis, 60-120 seconds for flow-based detection. Achieves detection delay under 1 second for packet methods.

### Machine learning detection approaches

**Deep Neural Networks (DNN)** achieve exceptional accuracy with proper architecture. Optimal configurations use **69-79 input features** (packet, byte, flow statistics), **3 hidden layers with 50 units each**, ReLU activation functions, and binary classification output (normal/attack). Performance: **96-99.66% accuracy** on CICIDS2017 and CICDDoS2019 datasets. Training employs back-propagation with dropout regularization preventing overfitting.

**Convolutional Neural Networks (CNN)** excel at spatial feature extraction from traffic patterns. Architecture: convolution layers extract features → pooling layers reduce dimensionality → flattening prepares data → fully connected layers classify. The LUCID approach achieves **98.98-99.99% accuracy** with **40x faster detection** than traditional methods through optimized feature engineering focusing on first-packet statistics.

**Recurrent Neural Networks** capture temporal dependencies in traffic sequences:
- **LSTM (Long Short-Term Memory):** 4-layer architecture achieves **98.88-99.19% accuracy**. Ideal for time-series attack pattern recognition.
- **GRU (Gated Recurrent Unit):** Simplified LSTM variant reaches **99.94% accuracy** with reduced computational cost.

**Hybrid CNN-LSTM models** combine spatial and temporal analysis, achieving **99.03-99.36% F1-score** with **11x faster training** than standalone LSTM implementations. The CNN extracts spatial features from network flow snapshots; LSTM analyzes temporal sequences of these features.

**Autoencoders** enable unsupervised learning requiring only normal traffic data—valuable when labeled attack samples are scarce. Five-layer architecture learns compressed representation of normal traffic, then detects attacks via reconstruction error exceeding threshold. Performance: **98-99% accuracy with under 0.5% false positive rate**. Particularly effective for zero-day attack detection.

**One-Class Classification** algorithms train exclusively on normal traffic:
- **One-Class SVM:** Best performer with **99.98% accuracy, 1.53% FPR**
- **Isolation Forest:** Efficient for high-dimensional data
- **Local Outlier Factor:** Density-based anomaly detection

**K-Means clustering** provides computationally efficient detection through unsupervised grouping. Configure 3 clusters: Normal (high entropy, typical rates), Suspicious (moderate anomalies), Attackers (low entropy, extreme rates). Analysis of entropy ratio changes between clusters enables real-time classification with O(n) computational complexity.

### Open-source detection tools

**Suricata** delivers multi-threaded IDS/IPS with high-performance packet processing. Key capabilities include deep packet inspection at wire speed, hardware acceleration via GPU, TLS/SSL decryption and file extraction, HTTP/DNS/SMB protocol analysis, and LuaJIT scripting for custom detection logic. Supports Linux, Windows, macOS, and OpenBSD. **Best for: Enterprise IDS deployment** requiring comprehensive threat detection beyond DDoS.

**Zeek** (formerly Bro) provides passive network analysis with extensive scripting capabilities. Event-driven architecture enables powerful automation through Bro-Script language. Generates comprehensive logs for forensics: connection logs, protocol-specific logs, file analysis, and SSL certificate tracking. Cluster support distributes processing across multiple nodes. **Best for: Network forensics, security research, and complex behavioral analysis** requiring customization.

**FastNetMon** specializes in high-performance DDoS detection for ISP and telco environments. Supports multiple telemetry sources: NetFlow v5/v9/v10, IPFIX, sFlow, and SPAN port mirroring. Real-time detection with configurable per-protocol thresholds (packets/sec, bits/sec, flows/sec). BGP integration (ExaBGP, GoBGP) enables automatic blackholing of attack traffic. **Best for: ISP/telco networks** requiring integration with routing infrastructure.

**Tool comparison:**

| Capability | Suricata | Zeek | FastNetMon |
|-----------|----------|------|------------|
| Detection | Real-time IDS/IPS | Passive analysis | Real-time DDoS |
| Threading | Multi-threaded | Multi-process | Multi-threaded |
| Focus | General threats | Behavioral | DDoS-specific |
| Telemetry | Packets | Packets | NetFlow/sFlow |
| Automation | Rule-based | Extensive scripting | BGP mitigation |
| Learning curve | Moderate | Steep | Moderate |
| Use case | Enterprise security | Research/forensics | ISP/Telco |

**FastNetMon configuration example:**

```bash
# Install
wget https://install.fastnetmon.com -O install_fastnetmon.sh
sudo bash install_fastnetmon.sh

# Configure thresholds (/etc/fastnetmon.conf)
threshold_pps = 50000
threshold_mbps = 1000
threshold_flows = 3500

ban_time = 1900

# Enable BGP blackholing
exabgp = on
exabgp_community = 65001:666

# View detections
fastnetmon_client
```

**Suricata deployment:**

```bash
# Install
sudo apt-get install suricata

# Update rules
sudo suricata-update

# Run on interface
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

# Monitor alerts
tail -f /var/log/suricata/fast.log

# Performance statistics
sudo suricatasc -c "dump-counters"
```

### Flow-based analysis with NetFlow

NetFlow provides scalable traffic telemetry for high-speed networks by exporting flow records instead of individual packets. Five-tuple flow definition: source IP, destination IP, source port, destination port, protocol.

**Optimal NetFlow configuration:**

```cisco
# Cisco router/switch
ip flow-export version 9
ip flow-export destination <collector-ip> 2055
ip flow-cache timeout active 60
ip flow-cache timeout inactive 5

interface GigabitEthernet0/0
  ip flow ingress
  ip flow egress
```

**Parameters:**
- **Active timer (60s):** Export long-lived flows every 60 seconds for visibility into ongoing connections
- **Inactive timer (5s):** Export completed flows 5 seconds after last packet to minimize memory consumption
- **Sampling:** Use 1:1,000 or 1:1,024 for high-speed links (\u003e10 Gbps)

**Detection performance:** Flow-based analysis achieves **1-second detection latency, 10-second mitigation** response including BGP blackhole propagation. Memory efficiency scales to millions of flows on commodity hardware.

**IPFIX (IP Flow Information Export):** IETF standardized successor to NetFlow v9. Enhanced features include variable-length fields, extensible templates, and additional metadata (TCP flags, timestamps, application IDs). Greater flexibility supports advanced security use cases beyond basic DDoS detection.

**sFlow:** Packet sampling protocol sends first 128 bytes of sampled packets plus interface counters. Real-time streaming without flow cache provides immediate visibility. Well-suited for high-speed networks requiring minimal router/switch overhead. Trade-off: sampling may miss low-rate attacks.

## Implementation deployment guide

### Phased rollout strategy

**Phase 1: Sysctl hardening (Day 1, 30 minutes, Low risk)**

```bash
# Backup current configuration
sysctl -a > /root/sysctl-backup-$(date +%Y%m%d).txt

# Deploy DDoS sysctl configuration
cp 99-ddos-protection.conf /etc/sysctl.d/
sysctl -p /etc/sysctl.d/99-ddos-protection.conf

# Verify critical settings
sysctl net.ipv4.tcp_syncookies
sysctl net.ipv4.tcp_max_syn_backlog
sysctl net.netfilter.nf_conntrack_max

# Monitor effects
watch -n 2 'netstat -s | grep -i syn'
```

**Phase 2: Iptables deployment (Week 1, 2-4 hours, Medium risk)**

```bash
# Backup existing rules
iptables-save > /root/iptables-backup-$(date +%Y%m%d).txt

# Deploy DDoS protection script
chmod +x ddos-iptables.sh
./ddos-iptables.sh

# Test legitimate traffic
curl http://localhost/
ab -n 1000 -c 10 http://localhost/

# Monitor blocking
watch -n 1 'iptables -vnL | head -30'

# Persistence across reboots
apt-get install iptables-persistent
iptables-save > /etc/iptables/rules.v4
```

**Phase 3: Application-layer controls (Week 1-2, 4-8 hours, Medium risk)**

For Apache:
```bash
# Enable mod_reqtimeout
a2enmod reqtimeout

# Install mod_qos
apt-get install libapache2-mod-qos
a2enmod qos

# Deploy configuration
cp ddos-apache.conf /etc/apache2/conf-available/
a2enconf ddos-apache

# Test configuration
apachectl configtest

# Graceful reload
apachectl graceful

# Monitor
tail -f /var/log/apache2/error.log | grep -i timeout
```

For Nginx:
```bash
# Deploy configuration
cp ddos-nginx.conf /etc/nginx/conf.d/

# Test configuration
nginx -t

# Reload
systemctl reload nginx

# Monitor rate limiting
tail -f /var/log/nginx/error.log | grep limiting
```

**Phase 4: XDP deployment (Week 2-3, 8-16 hours, Advanced)**

```bash
# Verify kernel version (≥5.15 recommended)
uname -r

# Check NIC driver support
ethtool -i eth0 | grep driver

# Install build dependencies
apt-get install clang llvm libbpf-dev linux-headers-$(uname -r) build-essential

# Compile XDP program
clang -O2 -g -target bpf -c xdp_ddos_protection.c -o xdp_ddos_protection.o

# Test in generic mode first (fallback)
ip link set dev eth0 xdpgeneric obj xdp_ddos_protection.o sec xdp

# Monitor for 24 hours
watch -n 1 'ethtool -S eth0 | grep xdp'

# If stable, upgrade to native mode
ip link set dev eth0 xdp off
ip link set dev eth0 xdpdrv obj xdp_ddos_protection.o sec xdp

# Continuous monitoring
bpftool prog show
bpftool map dump name rate_limit_map
```

**Phase 5: Behavioral detection (Week 3-4, 8-16 hours, Advanced)**

```bash
# Deploy Suricata
apt-get install suricata
suricata-update

# Configure for DDoS detection
cat >> /etc/suricata/suricata.yaml << EOF
af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    threads: 4
EOF

# Start service
systemctl enable suricata
systemctl start suricata

# Monitor detections
tail -f /var/log/suricata/fast.log

# Install FastNetMon for flow-based detection
wget https://install.fastnetmon.com -O install_fastnetmon.sh
bash install_fastnetmon.sh

# Configure thresholds
nano /etc/fastnetmon.conf

# Integrate with BGP blackholing (if available)
```

### Testing and validation

**Simulate SYN flood (hping3):**

```bash
# Install testing tools
apt-get install hping3

# Test from external system (do not run on production!)
hping3 -S -p 80 --flood --rand-source target.example.com

# Monitor on target
watch -n 1 'netstat -s | grep -i syn'
watch -n 1 'iptables -vnL | grep DROP'
```

**Simulate HTTP flood (Apache Bench):**

```bash
# Moderate load test
ab -n 10000 -c 100 http://target.example.com/

# Aggressive test (adjust based on capacity)
ab -n 100000 -c 500 http://target.example.com/

# Monitor application
watch -n 1 'apachectl status | grep "requests currently"'
# or for Nginx
curl http://localhost/nginx_status
```

**Simulate Slowloris (slowhttptest):**

```bash
# Install
git clone https://github.com/shekyan/slowhttptest.git
cd slowhttptest && ./configure && make && make install

# Test Slowloris
slowhttptest -c 1000 -H -g -o slowloris_test -i 10 -r 200 \
  -t GET -u http://target.example.com -x 240 -p 3

# Test Slow POST
slowhttptest -c 1000 -B -g -o slowpost_test -i 10 -r 200 -s 8192 \
  -t POST -u http://target.example.com/form -x 240 -p 3
```

**Validation checklist:**
- Legitimate traffic flows normally (test from multiple geographic locations)
- Attack simulation triggers mitigation (verify blocking in logs)
- Legitimate clients during attack maintain service (false positive check)
- Monitoring shows expected metrics (connection counts, drop rates)
- No performance degradation under normal load (baseline comparison)

### Monitoring and alerting

**Key metrics to track:**

```bash
# Connection tracking utilization
echo "scale=2; $(cat /proc/sys/net/netfilter/nf_conntrack_count) / \
  $(cat /proc/sys/net/netfilter/nf_conntrack_max) * 100" | bc

# SYN flood indicators
netstat -s | grep -i syn | grep -E 'SYNs|cookies|dropped'

# Iptables rule match rates
iptables -nvL | awk '{print $1, $2, $NF}' | column -t

# Nginx rate limiting
grep "limiting requests" /var/log/nginx/error.log | \
  awk '{print $13}' | sort | uniq -c | sort -rn | head -10

# Apache mod_qos status
curl http://localhost/qos-console

# XDP packet processing
ethtool -S eth0 | grep xdp
bpftool prog show
```

**Prometheus monitoring (recommended):**

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'node'
    static_configs:
      - targets: ['localhost:9100']
    metric_relabel_configs:
      - source_labels: [__name__]
        regex: 'node_network.*|node_netstat.*'
        action: keep

# Alert rules
groups:
  - name: ddos_alerts
    rules:
      - alert: HighSYNRate
        expr: rate(node_netstat_Tcp_PassiveOpens[1m]) > 1000
        for: 2m
        annotations:
          summary: "High SYN rate detected"
          
      - alert: ConntrackTableFull
        expr: node_nf_conntrack_entries / node_nf_conntrack_entries_limit > 0.9
        for: 5m
        annotations:
          summary: "Connection tracking table 90% full"
```

### Performance benchmarks

**Baseline measurements before deployment:**

```bash
# Establish packet processing capacity
hping3 -S -p 80 --flood localhost &
HPING_PID=$!
sleep 10
iptables -nvL | grep "tcp dpt:80" | awk '{print $1}'
kill $HPING_PID

# Measure legitimate request capacity
ab -n 100000 -c 100 http://localhost/ | grep "Requests per second"

# Baseline latency
ping -c 100 -i 0.2 target.example.com | grep avg
```

**Performance comparison:**

| Method | Capacity (pps) | CPU (single core) | Latency | Complexity |
|--------|---------------|-------------------|---------|------------|
| Sysctl only | 500K | Low | Minimal | Low |
| iptables filter | 1-2M | 100% | \u003c1ms | Medium |
| iptables mangle | 3-5M | 100% | \u003c1ms | Medium |
| XDP native | 10-26M | 60-100% | \u003c100μs | High |
| XDP offloaded | 100M+ | \u003c5% | \u003c10μs | High |

**Real-world deployment results:**
- **Cloudflare L4Drop (XDP):** Handled 8M+ pps attack with only 10% CPU increase
- **Wikipedia (XDP):** 26M pps packet drops on commodity hardware
- **Enterprise Apache + mod_qos:** Blocked 90%+ Slowloris attempts, 2-5% CPU overhead
- **ISP FastNetMon:** 1-second detection, 10-second BGP blackhole mitigation

## Conclusion

Defense against modern DDoS attacks requires architecting multiple protection layers that filter traffic at progressively deeper inspection levels. Start with kernel hardening through sysctl tuning and SYN cookies to establish baseline resilience—a 30-minute investment providing immediate protection against protocol attacks. Layer iptables rules in mangle/PREROUTING chains for 3-5 million packets per second filtering capacity, adding per-IP connection limits and rate controls. Deploy application-layer defenses through mod_reqtimeout, connection limiting, and request validation to stop Slowloris and HTTP floods. For high-traffic environments exceeding 10 million packets per second, implement XDP programs achieving 10-40x iptables performance through driver-level packet filtering.

Organizations should phase deployment over 3-4 weeks, beginning with low-risk sysctl hardening and progressively adding iptables, application controls, XDP, and behavioral detection. Testing at each phase validates legitimate traffic flows normally while attack simulations trigger mitigation. Continuous monitoring through Prometheus, FastNetMon, or Suricata provides visibility into attack patterns and mitigation effectiveness.

The combination of kernel optimizations (10-40% CPU reduction under attack), XDP filtering (10-26M pps capacity), connection management (90%+ slow attack blocking), and behavioral analysis (96-100% detection accuracy) creates defense-in-depth capable of withstanding contemporary multi-vector campaigns while maintaining service availability. Regular threshold tuning based on traffic baselines, quarterly configuration reviews, and integration with BGP blackholing or cloud scrubbing services ensure defenses evolve with the threat landscape.
