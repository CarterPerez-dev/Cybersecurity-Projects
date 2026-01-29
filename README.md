<div align="center">
  <img width="260" height="260" alt="Kali-dragon-icon svg" src="https://github.com/user-attachments/assets/d911b71f-6ad9-45b7-9513-237f83377023" alt="Kali Linux Icon"/>
  <h1 align="center">Cybersecurity Projects 🐉</h1>
  <p align="center">60 Cybersecurity Projects, Certification Roadmaps & Resources</p>
</div>

<div align="center">
  <img src="https://img.shields.io/github/stars/CarterPerez-dev/Cybersecurity-Projects" alt="stars"/>
  <img src="https://img.shields.io/github/forks/CarterPerez-dev/Cybersecurity-Projects" alt="forks"/>
  <img src="https://img.shields.io/github/issues/CarterPerez-dev/Cybersecurity-Projects" alt="issues"/>
  <img src="https://img.shields.io/github/license/CarterPerez-dev/Cybersecurity-Projects" alt="license"/>
  <br/>
  <img src="https://img.shields.io/badge/Cybersecurity-60_Projects-darkblue" alt="projects"/>
  <img src="https://img.shields.io/badge/Security-Learning_Resources-darkred" alt="resources"/>
</div>

<div align="center">
  <a href="https://github.com/sponsors/CarterPerez-dev">
    <img src="https://img.shields.io/static/v1?label=Contribute&message=%E2%9D%A4&logo=GitHub&color=darkgreen" alt="contribute"/>
  </a>
</div>

<h2 align="center"><strong>View Complete Projects:</strong></h2>
<div align="center">
  <a href="https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS">
    <img src="https://img.shields.io/badge/Full_Source_Code-10/60-blue?style=for-the-badge&logo=github" alt="Projects"/>
  </a>
</div>

---

## Table of Contents
- [Projects](#projects)
  - [Beginner Projects](#beginner-projects)
  - [Intermediate Projects](#intermediate-projects)
  - [Advanced Projects](#advanced-projects)
- [Certification Roadmaps](#certification-roadmaps)
- [Learning Resources](#learning-resources)


Big thanks to the current contributors! ❤️
- [@deniskhud](https://github.com/deniskhud):  [Simple Port Scanner](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/beginner/simple-port-scanner)
- [@Heritage-XioN](https://github.com/Heritage-XioN): [Metadata Scrubber Tool](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/beginner/metadata-scrubber-tool)
---

# Projects
### *Each link to their brief instructions or source code*
---
## Beginner Projects

### *SOURCE CODE:* *[Simple Port Scanner](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/beginner/simple-port-scanner)*
Asynchronous TCP port scanner in C++ using boost::asio for concurrent port scanning with configurable ranges and timeouts. Implements service detection through banner grabbing and demonstrates async I/O patterns with TCP socket programming.

### *SOURCE CODE:* *[Keylogger](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/beginner/keylogger)*
Use Python's `pynput` library to capture keyboard events and log them to a local file with timestamps. Include a toggle key (like F12) to start/stop logging. **Important**: Add clear disclaimers and only test on systems you own.

### *SOURCE CODE:* *[Caesar Cipher](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/beginner/caesar-cipher)*
Create a CLI tool that shifts characters by a specified number (the "key") to encrypt/decrypt text. Implement both encryption and brute-force decryption (try all 26 possible shifts). Bonus: Add support for preserving spaces and punctuation.

### *SOURCE CODE:* *[DNS Lookup CLI Tool](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/beginner/dns-lookup)*
Use Python's `dnspython` library to query different DNS record types (A, AAAA, MX, TXT, NS, CNAME). Display results in a clean table format with color coding using `rich` and `typer` libraries. Add reverse DNS lookup functionality and WHOIS.

### [Simple Vulnerability Scanner](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/beginner/Simple.Vulnerability.Scanner.md)
Build a script that checks installed software versions against a CVE database or uses `pip-audit` for Python packages. Parse system package managers (apt, yum, brew) to list installed software. Flag packages with known vulnerabilities and suggest updates.

### *SOURCE CODE:* *[Metadata Scrubber Tool](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/beginner/metadata-scrubber-tool)*
CLI tool that removes privacy sensitive metadata (EXIF, GPS, author info) from images, PDFs, and Office documents using concurrent batch processing. Features read/scrub/verify commands with rich terminal output, supports dry-run previews, and generates detailed comparison reports showing exactly what metadata was removed.

### [Network Traffic Analyzer](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/beginner/Network.Traffic.Analyzer.md)
Use `scapy` to capture packets on local network and display protocol distribution, top talkers, and bandwidth usage. Filter by protocol (HTTP, DNS, TCP, UDP) and visualize data with simple bar charts. Add export to CSV functionality.

### [Hash Cracker](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/beginner/Hash.Cracker.md)
Build a basic hash cracking tool that attempts to match MD5/SHA1/SHA256 hashes against wordlists. Implement both dictionary and brute-force modes. Add salted hash support and performance metrics (hashes per second).

### [Steganography Tool](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/beginner/Steganography.Tool.md)
Hide secret messages inside image files using LSB (Least Significant Bit) steganography. Support PNG and BMP formats. Include both encoding and decoding functionality with password protection option.

### [MAC Address Spoofer](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/beginner/MAC.Address.Spoofer.md)
Create a script to change network interface MAC addresses on Linux/Windows. Include validation, backup of original MAC, and automatic restoration. Add vendor lookup to generate realistic MAC addresses.

### [File Integrity Monitor](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/beginner/File.Integrity.Monitor.md)
Monitor specified directories for file changes using checksums (MD5/SHA256). Log all modifications, additions, and deletions with timestamps. Send alerts when critical system files are modified.

### [Security News Scraper](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/beginner/Security.News.Scraper.md)
Scrape cybersecurity news from sites like Krebs on Security, The Hacker News, and Bleeping Computer. Parse articles, extract CVEs, and store in a database. Create a simple dashboard to view latest threats.

### [Phishing URL Detector](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/beginner/Phishing.URL.Detector.md)
Analyze URLs for common phishing indicators (suspicious TLDs, typosquatting, URL shorteners). Check against safe browsing APIs (Google Safe Browsing). Display risk score with detailed analysis.

### [SSH Brute Force Detector](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/beginner/SSH.Brute.Force.Detector.md)
Monitor auth.log or secure log files for failed SSH login attempts. Detect brute force patterns and automatically add offending IPs to firewall rules. Send email alerts when attacks detected.

### [WiFi Network Scanner](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/beginner/WiFi.Network.Scanner.md)
Scan for nearby wireless networks and display SSIDs, signal strength, encryption types, and connected clients. Identify potentially rogue access points and weak encryption (WEP, WPA).

### [Base64 Encoder/Decoder](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/beginner/Base64.Encoder.Decoder.md)
Create a tool that encodes/decodes Base64, Base32, and hex. Automatically detect encoding type. Add support for URL encoding and HTML entity encoding.

### [Firewall Log Parser](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/beginner/Firewall.Log.Parser.md)
Parse firewall logs (iptables, UFW, pfSense) and generate reports on blocked connections. Identify top attacking IPs, most targeted ports, and attack patterns. Visualize with graphs.

### [ARP Spoofing Detector](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/beginner/ARP.Spoofing.Detector.md)
Monitor network for ARP spoofing attacks by tracking MAC-to-IP mappings. Alert when duplicate IP addresses or MAC address changes detected. Log all ARP traffic for analysis.

### [Windows Registry Monitor](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/beginner/Windows.Registry.Monitor.md)
Track changes to Windows registry keys and values. Focus on common persistence locations (Run keys, Services, Scheduled Tasks). Alert on suspicious modifications.

### [Ransomware Simulator](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/beginner/Ransomware.Simulator.md)
Educational tool that demonstrates file encryption without actual harm. Encrypt test files in isolated directory with strong encryption. Include decryption capability and educational warnings.

---

## Intermediate Projects

### [Reverse Shell Handler](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/intermediate/Reverse.Shell.Handler.md)
Create a server that listens for incoming reverse shell connections using Python sockets. Implement command execution, file upload/download, and session management for multiple clients. Use `cmd2` or similar library for a clean CLI interface.

### [SIEM Dashboard](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/intermediate/SIEM.Dashboard.md)
Build a Flask/FastAPI backend that ingests logs via syslog or file parsing, then visualize with a React frontend using Chart.js or Recharts. Store events in SQLite/PostgreSQL and implement basic correlation rules (e.g., "5 failed logins in 1 minute"). Add filtering by severity, source IP, and time range.

### [Threat Intelligence Aggregator](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/intermediate/Threat.Intelligence.Aggregator.md)
Use APIs from threat feeds (AbuseIPDB, VirusTotal, AlienVault OTX) to collect IOCs (IPs, domains, file hashes). Store in a database with deduplication and enrich with WHOIS/geolocation data. Create a simple UI to search IOCs and view threat scores.

### [OAuth Token Analyzer](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/intermediate/OAuth.Token.Analyzer.md)
Build a tool that decodes JWT tokens, validates signatures, and checks for common vulnerabilities (weak secrets, algorithm confusion, expired claims). Use PyJWT or similar library and add support for multiple signature algorithms (HS256, RS256). Display token payload in formatted JSON with security warnings.

### [Web Vulnerability Scanner](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/intermediate/Web.Vulnerability.Scanner.md)
Create an async Python scanner using `httpx` that crawls a target website and tests for XSS (reflected/stored), SQLi (error-based), and CSRF (missing tokens). Implement a plugin architecture so tests are modular and easy to add. Generate HTML reports with vulnerability details and remediation advice.

### [DDoS Mitigation Tool](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/intermediate/DDoS.Mitigation.Tool.md)
Create a network monitor that detects traffic spikes using packet sniffing (Scapy) and implements rate limiting with iptables or similar. Add anomaly detection by establishing baseline traffic patterns. Include alerts via email/webhook when attacks detected.

### [Container Security Scanner](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/intermediate/Container.Security.Scanner.md)
Scan Docker images by parsing Dockerfiles for insecure practices (running as root, hardcoded secrets) and checking base image versions against vulnerability databases. Use Docker API to inspect running containers for exposed ports and mounted volumes. Output findings in JSON with severity ratings.

### *SOURCE CODE:* *[Full Stack API Security Scanner](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/intermediate/api-security-scanner)*
Build an enterprise-grade automated API security scanner that performs deep vulnerability assessment across REST, GraphQL, and SOAP endpoints, detecting OWASP API Top 10 flaws through intelligent fuzzing, authentication bypass testing, broken object level authorization, mass assignment exploitation, and rate limiting analysis with ML-enhanced payload generation and comprehensive reporting dashboards. (FastAPI - React-Typescript - Vite - Nginx - Docker - CSS)

### [Wireless Deauth Detector](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/intermediate/Wireless.Deauth.Detector.md)
Monitor WiFi networks for deauthentication attacks using packet sniffing. Alert when abnormal deauth frames detected. Track affected clients and potential attacker locations.

### [Active Directory Enumeration](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/intermediate/Active.Directory.Enumeration.md)
Enumerate AD users, groups, computers, and permissions using LDAP queries. Identify privileged accounts, stale accounts, and misconfigurations. Generate visual diagrams of AD structure.

### [Binary Analysis Tool](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/intermediate/Binary.Analysis.Tool.md)
Disassemble executables and analyze for suspicious patterns. Extract strings, identify imported functions, and detect packing/obfuscation. Support PE, ELF, and Mach-O formats.

### [Network Intrusion Prevention](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/intermediate/Network.Intrusion.Prevention.md)
Real-time packet inspection using Snort rules or custom signatures. Automatically block malicious traffic using firewall integration. Dashboard for viewing blocked threats and rule management.

### [Password Policy Auditor](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/intermediate/Password.Policy.Auditor.md)
Audit Active Directory or local password policies against security best practices. Test for weak passwords using common patterns. Generate compliance reports and recommendations.

### [Cloud Asset Inventory](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/intermediate/Cloud.Asset.Inventory.md)
Automatically discover and catalog all resources across AWS, Azure, and GCP. Track changes over time, identify untagged resources, and calculate costs. Export to CSV/JSON.

### [OSINT Reconnaissance Framework](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/intermediate/OSINT.Reconnaissance.Framework.md)
Aggregate data from public sources (WHOIS, DNS, social media, breached databases). Automate information gathering for penetration testing. Generate comprehensive target profiles.

### [SSL/TLS Certificate Scanner](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/intermediate/SSL.TLS.Certificate.Scanner.md)
Scan domains for SSL/TLS misconfigurations (expired certs, weak ciphers, missing HSTS). Check against best practices (Mozilla SSL Config). Alert on vulnerabilities like Heartbleed.

### [Mobile App Security Analyzer](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/intermediate/Mobile.App.Security.Analyzer.md)
Decompile Android APKs and iOS IPAs to analyze security. Detect hardcoded secrets, insecure data storage, and vulnerable libraries. Generate OWASP Mobile Top 10 compliance reports.

### [Backup Integrity Checker](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/intermediate/Backup.Integrity.Checker.md)
Verify backup files aren't corrupted using checksums. Test restoration process automatically. Alert if backups fail validation or haven't run recently.

### [Web Application Firewall](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/intermediate/Web.Application.Firewall.md)
Build a reverse proxy that filters HTTP requests for malicious patterns. Block SQL injection, XSS, and path traversal attempts. Include whitelist/blacklist rules and logging.

### [Privilege Escalation Finder](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/intermediate/Privilege.Escalation.Finder.md)
Analyze Linux/Windows systems for potential privilege escalation vectors. Check for SUID binaries, weak permissions, and kernel exploits. Generate attack path diagrams.

### [Network Baseline Monitor](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/intermediate/Network.Baseline.Monitor.md)
Establish normal network behavior patterns (traffic volume, protocol distribution, top talkers). Alert on deviations that could indicate compromises or attacks.

### *SOURCE CODE:* *[Docker Security Audit](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/intermediate/docker-security-audit)*
Go CLI tool that scans Docker containers, images, Dockerfiles, and compose files for security misconfigurations. Checks against CIS Docker Benchmark v1.6.0 controls (privileged mode, dangerous capabilities, sensitive mounts, secrets in images, missing security profiles). Outputs findings with remediation guidance in terminal, JSON, SARIF, or JUnit formats.

---

## Advanced Projects

### *SOURCE CODE:* *[API Rate Limiter](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/advanced/api-rate-limiter)*
Build middleware that implements token bucket or sliding window rate limiting for APIs. Support per-user, per-IP, and global limits. Include Redis backend for distributed rate limiting across multiple servers.

### *SOURCE CODE:* *[Encrypted Chat Application](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/advanced/encrypted-p2p-chat)*
Build a real time encrypted chat using WebSockets with Signal Protocol encryption (X3DH key exchange + Double Ratchet) for forward secrecy and break-in recovery. Implement passwordless authentication via WebAuthn/Passkeys. Backend uses FastAPI with PostgreSQL, SurrealDB live queries, and Redis. SolidJS TypeScript frontend with nanostores and 8-bit retro design using TailwindCSS.

### [Exploit Development Framework](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/advanced/Exploit.Development.Framework.md)
Build a modular framework in Python where exploits are plugins (one file per vulnerability). Include payload generators, shellcode encoders, and target validation. Implement a Metasploit-like interface with search, configure, and execute commands.

### [AI Threat Detection](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/advanced/AI.Threat.Detection.md)
Train a machine learning model (Random Forest or LSTM) on network traffic data (CICIDS2017 dataset) to classify normal vs. malicious behavior. Use feature engineering on packet metadata (packet size, timing, protocols). Deploy model with FastAPI for real-time inference on live traffic.

### *SOURCE CODE:* *[Bug Bounty Platform](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/advanced/bug-bounty-platform)*
Create a web app with user roles (researchers, companies), vulnerability submission workflow, and reward management. Implement severity scoring (CVSS), status tracking, and encrypted communications. Use React frontend, FastAPI/Django backend, PostgreSQL database, and S3 for file uploads.

### [Cloud Security Posture Management](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/advanced/Cloud.Security.Posture.Management.md)
Build a tool using boto3 (AWS), Azure SDK, and Google Cloud SDK to scan for misconfigurations (public S3 buckets, overly permissive IAM roles, unencrypted storage). Implement compliance checks against CIS benchmarks. Generate executive dashboards showing risk scores and remediation priorities.

### [Malware Analysis Platform](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/advanced/Malware.Analysis.Platform.md)
Create a sandbox using Docker or VMs where suspicious files are executed in isolation while monitoring API calls, network traffic, and file system changes. Implement static analysis (strings, PE headers, YARA rules) and dynamic analysis (behavior tracking). Generate detailed reports with IOCs extracted.

### [Quantum Resistant Encryption](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/advanced/Quantum.Resistant.Encryption.md)
Implement post-quantum algorithms like Kyber (key exchange) or Dilithium (digital signatures) using existing libraries (liboqs-python). Build a file encryption tool that uses hybrid encryption (classical + quantum-resistant). Benchmark performance against traditional RSA/AES and document the security rationale.

### [Zero Day Vulnerability Scanner](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/advanced/Zero.Day.Vulnerability.Scanner.md)
Fuzzing framework that automatically discovers bugs in applications. Implement coverage-guided fuzzing using AFL or LibFuzzer. Triage crashes and generate proof-of-concept exploits.

### [Distributed Password Cracker](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/advanced/Distributed.Password.Cracker.md)
Coordinate password cracking across multiple machines using GPU acceleration. Support distributed workloads with job queuing. Dashboard for monitoring progress and performance.

### [Kernel Rootkit Detection](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/advanced/Kernel.Rootkit.Detection.md)
Detect kernel-level rootkits by comparing system calls, loaded modules, and memory structures. Use volatility framework for memory analysis. Alert on hidden processes or drivers.

### [Blockchain Smart Contract Auditor](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/advanced/Blockchain.Smart.Contract.Auditor.md)
Static analysis tool for Solidity smart contracts detecting vulnerabilities (reentrancy, integer overflow, access control). Integrate with Mythril and Slither. Generate security reports.

### [Adversarial ML Attacker](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/advanced/Adversarial.ML.Attacker.md)
Generate adversarial examples to fool ML-based security systems. Implement attacks like FGSM, DeepFool, and C&W. Test robustness of image classifiers and malware detectors.

### [Advanced Persistent Threat Simulator](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/advanced/Advanced.Persistent.Threat.Simulator.md)
Simulate multi-stage APT attacks with C2 infrastructure, lateral movement, and data exfiltration. Support various persistence mechanisms and evasion techniques. Generate attack reports.

### [Hardware Security Module Emulator](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/advanced/Hardware.Security.Module.Emulator.md)
Software emulation of HSM for cryptographic operations. Implement secure key storage, signing, and encryption. Support PKCS#11 interface for application integration.

### [Network Covert Channel](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/advanced/Network.Covert.Channel.md)
Exfiltrate data using DNS queries, ICMP packets, or HTTP headers. Implement encoding schemes to hide data in legitimate traffic. Measure detection rates against common DLP solutions.

### [Automated Penetration Testing](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/advanced/Automated.Penetration.Testing.md)
Orchestrate full penetration tests including reconnaissance, vulnerability scanning, exploitation, and post-exploitation. Generate executive and technical reports. Support multiple target types.

### [Supply Chain Security Analyzer](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/advanced/Supply.Chain.Security.Analyzer.md)
Analyze software dependencies for vulnerabilities and malicious packages. Detect typosquatting, dependency confusion, and compromised packages. Monitor for suspicious updates in CI/CD pipelines.

---

## Certification Roadmaps

Structured certification paths for 10 cybersecurity career tracks, from entry-level to senior positions.

**[View All Certification Roadmaps](./ROADMAPS/README.md)**

**Available Paths:**
- [SOC Analyst](./ROADMAPS/SOC-ANALYST.md)
- [Penetration Tester](./ROADMAPS/PENTESTER.md)
- [Security Engineer](./ROADMAPS/SECURITY-ENGINEER.md)
- [Incident Responder](./ROADMAPS/INCIDENT-RESPONDER.md)
- [Security Architect](./ROADMAPS/SECURITY-ARCHITECT.md)
- [Cloud Security Engineer](./ROADMAPS/CLOUD-SECURITY-ENGINEER.md)
- [GRC Analyst/Consultant](./ROADMAPS/GRC-ANALYST.md)
- [Threat Intelligence Analyst](./ROADMAPS/THREAT-INTELLIGENCE-ANALYST.md)
- [Application Security](./ROADMAPS/APPLICATION-SECURITY.md)
- [Network Engineer](./ROADMAPS/NETWORK-ENGINEER.md)

---

# Cybersecurity Learning Resources

A  collection of tools, courses, frameworks, and educational resources for cybersecurity professionals and learners at all levels.

---

## Table of Contents

- [Cybersecurity Tools](#cybersecurity-tools)
- [Study Platforms & Courses](#study-platforms--courses)
- [Certifications & Exam Prep](#certifications--exam-prep)
- [YouTube Channels & Videos](#youtube-channels--videos)
- [Reddit Communities](#reddit-communities)
- [Security Frameworks](#security-frameworks)
- [Industry Resources](#industry-resources)
- [Cloud Certifications](#cloud-certifications)

---

## Learning Resources

Comprehensive collection of cybersecurity tools, training courses, certifications, communities, and frameworks.

**[View All Learning Resources](./RESOURCES/README.md)**

**Quick Access:**
- **[Tools](./RESOURCES/TOOLS.md)** - Network analysis, vulnerability scanners, pentesting tools, SIEM platforms, and more
- **[Courses & Training](./RESOURCES/COURSES.md)** - Free and premium platforms, Udemy courses, hands-on labs
- **[Certifications](./RESOURCES/CERTIFICATIONS.md)** - Exam objectives, practice tests, study guides, vouchers
- **[Communities](./RESOURCES/COMMUNITIES.md)** - YouTube channels, Reddit communities, LinkedIn professionals
- **[Frameworks & Standards](./RESOURCES/FRAMEWORKS.md)** - NIST, ISO, MITRE, compliance regulations

---
