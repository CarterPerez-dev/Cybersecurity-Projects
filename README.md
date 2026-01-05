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
    <img src="https://img.shields.io/badge/Full_Source_Code-7/60-blue?style=for-the-badge&logo=github" alt="Projects"/>
  </a>
</div>

---

## Table of Contents
- [Projects](#projects)
  - [Beginner Projects](#beginner-projects)
  - [Intermediate Projects](#intermediate-projects)
  - [Advanced Projects](#advanced-projects)
- [Certification Roadmaps by Role](#certification-roadmaps-by-role)
- [Cybersecurity Tools](#cybersecurity-tools)
- [Study Platforms & Courses](#study-platforms--courses)
- [Certifications & Exam Prep](#certifications--exam-prep)
- [YouTube Channels & Videos](#youtube-channels--videos)
- [Reddit Communities](#reddit-communities)
- [Security Frameworks](#security-frameworks)
- [Industry Resources](#industry-resources)
- [Cloud Certifications](#cloud-certifications)
- [CISSP Resources](#cissp-resources)
- [LinkedIn Professionals](#linkedin-professionals-to-follow)
- [Additional Learning Resources](#additional-learning-resources)

---

# Projects 
### *Each link to their brief instructions or source code*

## Beginner Projects

### *SOURCE CODE:* *[Simple Port Scanner](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/simple-port-scanner)*
Asynchronous TCP port scanner in C++ using boost::asio for concurrent port scanning with configurable ranges and timeouts. Implements service detection through banner grabbing and demonstrates async I/O patterns with TCP socket programming.

### *SOURCE CODE:* *[Keylogger](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/keylogger)*
Use Python's `pynput` library to capture keyboard events and log them to a local file with timestamps. Include a toggle key (like F12) to start/stop logging. **Important**: Add clear disclaimers and only test on systems you own.

### [Caesar Cipher](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/beginner/Caesar.Cipher.md)
Create a CLI tool that shifts characters by a specified number (the "key") to encrypt/decrypt text. Implement both encryption and brute-force decryption (try all 26 possible shifts). Bonus: Add support for preserving spaces and punctuation.

### *SOURCE CODE:* *[DNS Lookup CLI Tool](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/dns-lookup)*
Use Python's `dnspython` library to query different DNS record types (A, AAAA, MX, TXT, NS, CNAME). Display results in a clean table format with color coding using `rich` and `typer` libraries. Add reverse DNS lookup functionality and WHOIS.

### [Simple Vulnerability Scanner](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/beginner/Simple.Vulnerability.Scanner.md)
Build a script that checks installed software versions against a CVE database or uses `pip-audit` for Python packages. Parse system package managers (apt, yum, brew) to list installed software. Flag packages with known vulnerabilities and suggest updates.

### [Metadata Scrubber Tool](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/beginner/Metadata.Scrubber.Tool.md)
Build a tool that removes metadata from files (images, PDFs, Office docs) to protect privacy. Extract and display EXIF data, GPS coordinates, author info, and edit history. Support batch processing and create sanitized copies. Add detection for hidden data in file headers and warn users about information leakage risks.

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

### *SOURCE CODE:* *[Full Stack API Security Scanner](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/api-security-scanner)*
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

### *SOURCE CODE:* *[Docker Security Audit](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/docker-security-audit)*
Go CLI tool that scans Docker containers, images, Dockerfiles, and compose files for security misconfigurations. Checks against CIS Docker Benchmark v1.6.0 controls (privileged mode, dangerous capabilities, sensitive mounts, secrets in images, missing security profiles). Outputs findings with remediation guidance in terminal, JSON, SARIF, or JUnit formats.

---

## Advanced Projects

### *SOURCE CODE:* *[API Rate Limiter](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/api-rate-limiter)*
Build middleware that implements token bucket or sliding window rate limiting for APIs. Support per-user, per-IP, and global limits. Include Redis backend for distributed rate limiting across multiple servers.

### *SOURCE CODE:* *[Encrypted Chat Application](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/encrypted-p2p-chat)*
Build a real time encrypted chat using WebSockets with Signal Protocol encryption (X3DH key exchange + Double Ratchet) for forward secrecy and break-in recovery. Implement passwordless authentication via WebAuthn/Passkeys. Backend uses FastAPI with PostgreSQL, SurrealDB live queries, and Redis. SolidJS TypeScript frontend with nanostores and 8-bit retro design using TailwindCSS.

### [Exploit Development Framework](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/advanced/Exploit.Development.Framework.md)
Build a modular framework in Python where exploits are plugins (one file per vulnerability). Include payload generators, shellcode encoders, and target validation. Implement a Metasploit-like interface with search, configure, and execute commands.

### [AI Threat Detection](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/advanced/AI.Threat.Detection.md)
Train a machine learning model (Random Forest or LSTM) on network traffic data (CICIDS2017 dataset) to classify normal vs. malicious behavior. Use feature engineering on packet metadata (packet size, timing, protocols). Deploy model with FastAPI for real-time inference on live traffic.

### [Bug Bounty Platform](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/SYNOPSES/advanced/Bug.Bounty.Platform.md)
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

## <img src="https://media2.giphy.com/media/QssGEmpkyEOhBCb7e1/giphy.gif?cid=ecf05e47a0n3gi1bfqntqmob8g9aid1oyj2wr3ds3mg700bl&rid=giphy.gif" width ="30">   **Certification Roadmap by Role**   <img src="https://media2.giphy.com/media/QssGEmpkyEOhBCb7e1/giphy.gif?cid=ecf05e47a0n3gi1bfqntqmob8g9aid1oyj2wr3ds3mg700bl&rid=giphy.gif" width ="30">

# Certification Roadmaps By Role

### 1. SOC Analyst
[![Role](https://skillicons.dev/icons?i=debian)](https://skillicons.dev)

| Level | Certification | Organization | Link |
|-------|--------------|--------------|------|
| **Entry** | **Security+** | CompTIA | [Website](https://www.comptia.org/certifications/security) |
| **Core** | **CySA+** | CompTIA | [Website](https://www.comptia.org/certifications/cybersecurity-analyst) |
| **Intermediate** | **GCIH** (Certified Incident Handler) | GIAC | [Website](https://www.giac.org/certifications/certified-incident-handler-gcih/) |
| **Intermediate** | **CEH** (Certified Ethical Hacker) | EC-Council | [Website](https://www.eccouncil.org/train-certify/certified-ethical-hacker-ceh/) |
| **Advanced** | **GCIA** (Certified Intrusion Analyst) | GIAC | [Website](https://www.giac.org/certifications/certified-intrusion-analyst-gcia/) |
| **Senior/Management** | **CISSP** | (ISC)² | [Website](https://www.isc2.org/Certifications/CISSP) |

---

### 2. Penetration Tester
[![Role](https://skillicons.dev/icons?i=kali)](https://skillicons.dev)

| Level | Certification | Organization | Link |
|-------|--------------|--------------|------|
| **Foundation** | **Security+** | CompTIA | [Website](https://www.comptia.org/certifications/security) |
| **Entry-Level Pentest** | **PenTest+** | CompTIA | [Website](https://www.comptia.org/certifications/pentest) |
| **Intermediate** | **CEH** (Certified Ethical Hacker) | EC-Council | [Website](https://www.eccouncil.org/train-certify/certified-ethical-hacker-ceh-v12/) |
| **Advanced** | **OSCP** (Gold Standard) | Offensive Security | [Website](https://www.offsec.com/courses-and-certifications/oscp-certification) |
| **Expert** | **OSEP** | Offensive Security | [Website](https://www.offsec.com/courses-and-certifications/osep-certification) |
| **Expert** | **GXPN** (Exploit Researcher) | GIAC | [Website](https://www.giac.org/certification/exploit-researcher-advanced-penetration-tester-gxpn/) |

---

### 3. Security Engineer
[![Role](https://skillicons.dev/icons?i=linux)](https://skillicons.dev)

| Level | Certification | Organization | Link |
|-------|--------------|--------------|------|
| **Foundation** | **Security+** | CompTIA | [Website](https://www.comptia.org/certifications/security) |
| **Intermediate** | **CySA+** | CompTIA | [Website](https://www.comptia.org/certifications/cysa) |
| **Advanced** | **SecurityX** (formerly CASP+) | CompTIA | [Website](https://www.comptia.org/certifications/securityx) |
| **Advanced/Expert** | **CISSP** | (ISC)² | [Website](https://www.isc2.org/Certifications/CISSP) |
| **Expert (Cloud-focused)** | **CCSP** | (ISC)² | [Website](https://www.isc2.org/Certifications/CCSP) |

---

### 4. Incident Responder
[![Role](https://skillicons.dev/icons?i=redhat)](https://skillicons.dev)

| Level | Certification | Organization | Link |
|-------|--------------|--------------|------|
| **Entry** | **Security+** | CompTIA | [Website](https://www.comptia.org/certifications/security) |
| **Core** | **CySA+** | CompTIA | [Website](https://www.comptia.org/certifications/cybersecurity-analyst) |
| **Core IR Cert** | **GCIH** (Certified Incident Handler) | GIAC | [Website](https://www.giac.org/certifications/certified-incident-handler-gcih/) |
| **Forensics/Advanced** | **GCFA** (Certified Forensic Analyst) | GIAC | [Website](https://www.giac.org/certifications/certified-forensic-analyst-gcfa/) |
| **Malware Analysis/Expert** | **GREM** (Reverse Engineering Malware) | GIAC | [Website](https://www.giac.org/certifications/reverse-engineering-malware-grem/) |

---

### 5. Security Architect
[![Role](https://skillicons.dev/icons?i=laravel)](https://skillicons.dev)

| Level | Certification | Organization | Link |
|-------|--------------|--------------|------|
| **Foundation** | **Security+** | CompTIA | [Website](https://www.comptia.org/certifications/security) |
| **Advanced** | **SecurityX** (formerly CASP+) | CompTIA | [Website](https://www.comptia.org/certifications/securityx) |
| **Architect/Management** | **CISSP** (Required) | (ISC)² | [Website](https://www.isc2.org/Certifications/CISSP) |
| **Cloud Architecture** | **CCSP** | (ISC)² | [Website](https://www.isc2.org/Certifications/CCSP) |
| **Security Architecture Framework** | **SABSA** | SABSA Institute | [Website](https://sabsa.org/sabsa-chartered-architect-programme/) |
| **Enterprise Architecture** | **TOGAF** | The Open Group | [Website](https://www.opengroup.org/certifications/togaf-certifications) |

---

### 6. Cloud Security Engineer
[![Role](https://skillicons.dev/icons?i=aws)](https://skillicons.dev)

| Level | Certification | Organization | Link |
|-------|--------------|--------------|------|
| **Foundation** | **Security+** | CompTIA | [Website](https://www.comptia.org/certifications/security) |
| **AWS Cloud Security** | **AWS Security Specialty** | AWS | [Website](https://aws.amazon.com/certification/certified-security-specialty/) |
| **Azure Cloud Security** | **Azure Security Engineer** | Microsoft | [Website](https://learn.microsoft.com/en-us/certifications/azure-security-engineer/) |
| **Vendor-Neutral** | **CCSK** | Cloud Security Alliance | [Website](https://cloudsecurityalliance.org/education/ccsk) |
| **Advanced** | **CCSP** | (ISC)² | [Website](https://www.isc2.org/Certifications/CCSP) |
| **Advanced Practice** | **SecurityX** (formerly CASP+) | CompTIA | [Website](https://www.comptia.org/certifications/securityx) |
| **Expert/Management** | **CISSP** | (ISC)² | [Website](https://www.isc2.org/Certifications/CISSP) |

---

### 7. GRC Analyst/Consultant
[![Role](https://skillicons.dev/icons?i=notion)](https://skillicons.dev)

| Level | Certification | Organization | Link |
|-------|--------------|--------------|------|
| **Foundation** | **Security+** | CompTIA | [Website](https://www.comptia.org/certifications/security) |
| **Audit Focused** | **CISA** (Certified Information Systems Auditor) | ISACA | [Website](https://www.isaca.org/credentialing/cisa) |
| **Risk Management** | **CRISC** (Risk and Information Systems Control) | ISACA | [Website](https://www.isaca.org/credentialing/crisc) |
| **Advanced** | **CISSP** | (ISC)² | [Website](https://www.isc2.org/Certifications/CISSP) |
| **Compliance-Heavy** | **ISO 27001 Lead Auditor** | PECB (and others) | [Website](https://pecb.com/en/education-and-certification/iso-iec-27001-lead-auditor) |

---

### 8. Threat Intelligence Analyst
[![Role](https://skillicons.dev/icons?i=bash)](https://skillicons.dev)

| Level | Certification | Organization | Link |
|-------|--------------|--------------|------|
| **Foundation** | **Security+** | CompTIA | [Website](https://www.comptia.org/certifications/security) |
| **Core** | **CySA+** | CompTIA | [Website](https://www.comptia.org/certifications/cysa) |
| **Cyber Threat Intelligence** | **GCTI** | GIAC | [Website](https://www.giac.org/certification/cyber-threat-intelligence-gcti/) |
| **Intrusion Analysis** | **GCIA** | GIAC | [Website](https://www.giac.org/certification/certified-intrusion-analyst-gcia/) |
| **OSINT (Optional)** | **GOSI** | GIAC | [Website](https://www.giac.org/certification/open-source-intelligence-gosi/) |
| **OSINT (Optional)** | **C\|OSINT** | McAfee Institute | [Website](https://www.mcafeeinstitute.com/products/certified-osint) |

---

### 9. Application Security
[![Role](https://skillicons.dev/icons?i=flask)](https://skillicons.dev)

| Level | Certification | Organization | Link |
|-------|--------------|--------------|------|
| **Foundation** | **Security+** | CompTIA | [Website](https://www.comptia.org/certifications/security) |
| **Foundation/Core** | **CEH** (Certified Ethical Hacker) | EC-Council | [Website](https://www.eccouncil.org/train-certify/certified-ethical-hacker-ceh/) |
| **Foundation/Core** | **CySA+** | CompTIA | [Website](https://www.comptia.org/certifications/cybersecurity-analyst) |
| **Secure Software Lifecycle** | **CSSLP** | (ISC)² | [Website](https://www.isc2.org/Certifications/CSSLP) |
| **Web App Exploitation** | **OSWE** | Offensive Security | [Website](https://www.offensive-security.com/web-expert-oswe/) |
| **Web App Pentest** | **GWAPT** | GIAC | [Website](https://www.giac.org/certifications/web-application-penetration-tester-gwapt/) |

---

### 10. Network Engineer (Security-Focused)
[![Role](https://skillicons.dev/icons?i=cloudflare)](https://skillicons.dev)

| Level | Certification | Organization | Link |
|-------|--------------|--------------|------|
| **Foundation** | **Network+** | CompTIA | [Website](https://www.comptia.org/certifications/network) |
| **Foundation** | **Security+** | CompTIA | [Website](https://www.comptia.org/certifications/security) |
| **Associate** | **CCNA** (Cisco Certified Network Associate) | Cisco | [Website](https://www.cisco.com/c/en/us/training-events/training-certifications/certifications/associate/ccna.html) |
| **Advanced** | **CCNP Security** | Cisco | [Website](https://www.cisco.com/c/en/us/training-events/training-certifications/certifications/professional/ccnp-security.html) |
| **Architect/Management** | **CISSP** | (ISC)² | [Website](https://www.isc2.org/Certifications/CISSP) |

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

## Cybersecurity Tools

### Reconnaissance & Scanning
- [Nmap](https://nmap.org/) - Network mapper and port scanner
- [Nessus](https://www.tenable.com/products/nessus) - Vulnerability scanner
- [Nikto](https://cirt.net/Nikto2) - Web server scanner
- [Searchsploit](https://github.com/dev-angelist/Ethical-Hacking-Tools/blob/main/practical-ethical-hacker-notes/tools/searchsploit.md) - Exploit database CLI
- [theHarvester](https://github.com/laramies/theHarvester) - Information gathering tool
- [Amass](https://github.com/owasp-amass/amass) - Subdomain enumeration
- [Sublist3r](https://github.com/aboul3la/Sublist3r) - Subdomain finder
- [Recon-ng](https://github.com/lanmaster53/recon-ng) - Web reconnaissance framework
- [Fierce](https://github.com/mschwager/fierce) - DNS scanner

### Web Application Testing
- [Burp Suite](https://portswigger.net/burp) - Web vulnerability scanner
- [OWASP ZAP](https://www.zaproxy.org/) - Web application security scanner
- [Nikto](https://cirt.net/Nikto2) - Web server scanner
- [SQLmap](https://sqlmap.org/) - SQL injection testing
- [Wfuzz](https://github.com/xmendez/wfuzz) - Web fuzzer
- [Gobuster](https://github.com/OJ/gobuster) - URI/DNS/Vhost brute forcing
- [SkipFish](https://github.com/spinkham/skipfish) - Active web application scanner
- [Wapiti](https://github.com/wapiti-scanner/wapiti) - Web vulnerability scanner
- [Arachni](https://github.com/Arachni/arachni) - Web application security scanner
- [Nuclei](https://github.com/projectdiscovery/nuclei) - Template-based scanning
- [Maltego](https://www.maltego.com/) - OSINT & data mining

### Network & Wireless
- [Wireshark](https://www.wireshark.org/) - Network protocol analyzer
- [Bettercap](https://github.com/bettercap/bettercap) - Network attack framework
- [Responder](https://github.com/SpiderLabs/Responder) - LLMNR/NBT-NS poisoner
- [Ettercap](https://github.com/Ettercap/ettercap) - Man-in-the-middle framework
- [SSLstrip](https://github.com/moxie0/sslstrip) - SSL stripping attack
- [Aircrack-ng](https://www.aircrack-ng.org/) - Wireless network auditing
- [Kismet](https://github.com/kismetwireless/kismet) - Wireless network detector
- [mitmproxy](https://github.com/mitmproxy/mitmproxy) - HTTP/HTTPS proxy
- [Fiddler](https://www.telerik.com/fiddler) - Web debugging proxy
- [Yersinia](https://github.com/tomac/yersinia) - Layer 2 attacks

### Exploitation & Post-Exploitation
- [Metasploit](https://www.metasploit.com/) - Penetration testing framework
- [Hydra](https://github.com/vanhauser-thc/thc-hydra) - Password cracking
- [Ncrack](https://github.com/nmap/ncrack) - Network authentication cracker
- [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec) - Post-exploitation framework
- [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) - WinRM shell
- [Empire](https://github.com/EmpireProject/Empire) - PowerShell post-exploitation
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) - Credential extraction
- [Shellter](https://www.shellterproject.com/) - Dynamic shellcode injection
- [BeEF](https://github.com/beefproject/beef) - Browser exploitation framework
- [RouterSploit](https://github.com/threat9/routersploit) - Router exploitation framework
- [Legion](https://github.com/Abacus-Group-RTO/legion) - Automated pentest tool
- [Social-Engineer Toolkit (SET)](https://github.com/trustedsec/social-engineer-toolkit) - Social engineering attacks

### Cryptography & Analysis
- [John the Ripper](https://www.openwall.com/john/) - Password cracker
- [Hashcat](https://hashcat.net/hashcat/) - GPU-accelerated hash cracking
- [Ghidra](https://ghidra-sre.org/) - Reverse engineering
- [Radare2](https://github.com/radareorg/radare2) - Binary analysis framework
- [Binwalk](https://github.com/ReFirmLabs/binwalk) - Binary file analysis

### Forensics & Malware Analysis
- [Volatility](https://www.volatilityfoundation.org/) - Memory forensics
- [Cuckoo Sandbox](https://cuckoosandbox.org/) - Malware analysis sandbox
- [Impacket](https://github.com/fortra/impacket) - Network protocol library

### Monitoring & Defense
- [Suricata](https://suricata.io/) - Network IDS/IPS
- [OSSEC](https://www.ossec.net/) - Host-based intrusion detection
- [Greenbone Vulnerability Manager](https://www.greenbone.net/en/) - Vulnerability scanning

### Code Security
- [Snyk](https://snyk.io/) - Dependency vulnerability scanner
- [OWASP Dependency-Check](https://github.com/jeremylong/DependencyCheck) - Dependency checker
- [Semgrep](https://semgrep.dev/) - Static analysis tool
- [Detectify](https://detectify.com/) - Web security platform

### Intelligence & Recon
- [Shodan](https://www.shodan.io/) - Internet search engine
- [Offensive Security Exploit Database](https://www.exploit-db.com/) - Exploit database
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) - Active Directory analysis
- [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness) - Screenshot capture tool

---

## Study Platforms & Courses

### Udemy CompTIA Courses
- [CompTIA Security+ (SY0-701) Complete Course & Exam](https://www.udemy.com/course/securityplus)
- [CompTIA Security+ (SY0-701) Practice Exams Set 1](https://www.udemy.com/course/comptia-security-sy0-701-practice-exams/)
- [CompTIA Security+ (SY0-701) Practice Exams Set 2](https://www.udemy.com/course/comptia-security-sy0-701-practice-exams-2nd-edition/)
- [TOTAL: CompTIA Security+ Certification Course + Exam SY0-701](https://www.udemy.com/course/total-comptia-security-plus/)
- [CompTIA A+ Core 1 (220-1101) Complete Course & Practice Exam](https://www.udemy.com/course/comptia-a-core-1/)
- [CompTIA A+ Core 2 (220-1102) Complete Course & Practice Exam](https://www.udemy.com/course/comptia-a-core-2/)
- [CompTIA A+ (220-1101) Core 1 Practice Exams](https://www.udemy.com/course/comptia-a-220-1101-core-1-practice-exams-new-for-2022/)
- [CompTIA A+ (220-1102) Core 2 Practice Exams](https://www.udemy.com/course/comptia-a-220-1102-core-2-practice-exams-new-for-2022/)
- [CompTIA A+ Core 1 & Core 2 - IT Cert Doctor - 2024](https://www.udemy.com/course/it-cert-doctor-comptia-a-220-1101-1102/)
- [CompTIA Network+ (N10-009) Full Course & Practice Exam](https://www.udemy.com/course/comptia-network-009/)
- [CompTIA Network+ (N10-009) 6 Full Practice Exams Set 1](https://www.udemy.com/course/comptia-network-n10-009-6-practice-exams-and-pbqs-set-1/)
- [CompTIA Network+ (N10-009) 6 Full Practice Exams Set 2](https://www.udemy.com/course/comptia-network-n10-009-6-practice-exams-and-pbqs-set-2/)
- [CompTIA CySA+ (CS0-003) Complete Course & Practice Exam](https://www.udemy.com/course/comptia-cysa-003/)
- [CompTIA CySA+ (CS0-003) Practice Exams](https://www.udemy.com/course/comptia-cysa-cs0-003-practice-exams/)
- [CompTIA PenTest+ (PT0-003) Full Course & Practice Exam](https://www.udemy.com/course/pentestplus/)
- [CompTIA PenTest+ (PT0-003) 6 Practice Exams](https://www.udemy.com/course/comptia-pentest-pt0-003-6-practice-exams/)
- [CompTIA SecurityX (CAS-005) Complete Course & Practice Exam](https://www.udemy.com/course/casp-plus/)
- [CompTIA SecurityX (CAS-005) Practice Exam Prep](https://www.udemy.com/course/comptia-securityx-practice-exam-prep-new/)
- [CompTIA Linux+ (XK0-005) Complete Course & Exam](https://www.udemy.com/course/comptia-linux/)
- [CompTIA Linux+ (XK0-005) Practice Exams & Simulated PBQs](https://www.udemy.com/course/comptia-linux-exams/)

### Udemy Other Security Courses
- [The Complete Cyber Security Course : Hackers Exposed!](https://www.udemy.com/course/the-complete-internet-security-privacy-course-volume-1/)
- [The Complete Cyber Security Course : Network Security!](https://www.udemy.com/course/network-security-course/)
- [The Complete Cyber Security Course : End Point Protection!](https://www.udemy.com/course/the-complete-cyber-security-course-end-point-protection/)
- [Complete Ethical Hacking & Cyber Security Masterclass Course](https://www.udemy.com/course/ethicalhackingcourse/)
- [Implementing the NIST Cybersecurity Framework (CSF)](https://www.udemy.com/course/nist-cybersecurity-framework/)
- [ISC2 CISSP Full Course & Practice Exam](https://www.udemy.com/course/isc2-cissp-full-course-practice-exam/)
- [ISC2 CISSP 6 Practice Exams](https://www.udemy.com/course/isc2-cissp-6-practice-exams/)
- [The Complete Certified in Cybersecurity CC course ISC2 2024](https://www.udemy.com/course/certifiedincybersecurity/)

### Free Learning Platforms
- [Cybrary](https://www.cybrary.it) - Free cybersecurity courses
- [TryHackMe](https://tryhackme.com/) - Interactive hacking challenges
- [Hack The Box](https://www.hackthebox.com/) - Penetration testing labs
- [HackTheBox Academy](https://academy.hackthebox.com/) - Structured learning paths
- [SANS Cyber Aces Online](https://www.cyberaces.org/) - Free tutorials
- [Coursera](https://www.coursera.org/) - University-level courses
- [edX Cybersecurity Programs](https://www.edx.org/professional-certificate/cybersecurity) - Professional certificates
- [freeCodeCamp](https://www.youtube.com/freecodecamp) - Free comprehensive courses
- [Codecademy Cybersecurity](https://www.codecademy.com/catalog/subject/cybersecurity) - Interactive coding

### Premium Platforms
- [Pluralsight](https://www.pluralsight.com/) - Tech skill development
- [CBT Nuggets](https://www.cbtnuggets.com/) - Video training
- [LinkedIn Learning](https://www.linkedin.com/learning/) - Professional development
- [INE Security Courses](https://ine.com/learning/areas/security) - Cybersecurity specialization
- [Infosec Skills](https://www.infosecinstitute.com/skills/) - Hands-on labs
- [Offensive Security (OffSec)](https://www.offensive-security.com/) - Advanced training
- [TestOut](https://testoutce.com/) - Certification prep

---

## Certifications & Exam Prep

### CompTIA Exam Objectives
- [A+ Core 1 (220-1101)](https://partners.comptia.org/docs/default-source/resources/comptia-a-220-1101-exam-objectives-(3-0))
- [A+ Core 2 (220-1102)](https://partners.comptia.org/docs/default-source/resources/comptia-a-220-1102-exam-objectives-(3-0))
- [Network+ (N10-009)](https://partners.comptia.org/docs/default-source/resources/comptia-network-n10-009-exam-objectives-(4-0))
- [Security+ (SY0-701)](https://assets.ctfassets.net/82ripq7fjls2/6TYWUym0Nudqa8nGEnegjG/0f9b974d3b1837fe85ab8e6553f4d623/CompTIA-Security-Plus-SY0-701-Exam-Objectives.pdf)
- [CySA+ (CS0-003)](https://partners.comptia.org/docs/default-source/resources/comptia-cysa-cs0-003-exam-objectives-(2-0))
- [PenTest+ (PT0-003)](https://partners.comptia.org/docs/default-source/resources/comptia-pentest-pt0-003-exam-objectives-(1-0))
- [SecurityX (CAS-005)](https://partners.comptia.org/docs/default-source/resources/comptia-securityx-cas-005-exam-objectives-(3-0))
- [Linux+ (XK0-005)](https://partners.comptia.org/docs/default-source/resources/comptia-linux-xk0-005-exam-objectives-(1-0))
- [Cloud+ (CV0-003)](https://partners.comptia.org/docs/default-source/resources/comptia-cloud-cv0-003-exam-objectives-(1-0))
- [Data+ (DA0-001)](https://partners.comptia.org/docs/default-source/resources/comptia-data-da0-001-exam-objectives-(2-0))
- [Server+ (SK0-005)](https://partners.comptia.org/docs/default-source/resources/comptia-server-sk0-005-exam-objectives-(1-0))

### Practice Test Resources
- [CertNova](https://www.certnova.com/) - Free practice tests
- [ExamCompass](https://www.examcompass.com/) - Practice exams
- [ExamDigest](https://examsdigest.com/) - Exam resources
- [Mike Meyers Practice Tests](https://www.totalsem.com/total-tester-practice-tests/) - Total Tester
- [Quizlet](https://quizlet.com/) - Flashcards & quizzes

### Exam Vouchers & Official Resources
- [CompTIA Student Discount](https://academic-store.comptia.org/) - 50% vouchers for students
- [Official CompTIA Resources](https://www.comptia.org/resources) - Study materials
- [CompTIA.org](https://www.comptia.org/) - Main website

### Study Guides & Books
- [SYBEX CompTIA Books](https://www.amazon.com/s?k=wiley+sybex+comptia) - Official study guides
- [Notes: CompTIA A+, Network+ and Security+](https://www.udemy.com/course/comptia-a-1001-1002-study-notes/) - Study notes collection

---

## YouTube Channels & Videos

### Top Cybersecurity Channels
- [Professor Messer](https://www.youtube.com/@professormesser) - CompTIA certification prep
- [NetworkChuck](https://www.youtube.com/@NetworkChuck) - Networking & security
- [PowerCert Animated Videos](https://www.youtube.com/@PowerCertAnimatedVideos) - Educational animations
- [HackerSploit](https://www.youtube.com/@HackerSploit) - Ethical hacking tutorials
- [Cyberkraft](https://www.youtube.com/@cyberkraft) - Cybersecurity education
- [howtonetwork](https://www.youtube.com/@howtonetworkcom) - Network fundamentals
- [CBT Nuggets](https://www.youtube.com/user/cbtnuggets) - Professional training
- [Eli the Computer Guy](https://www.youtube.com/user/elithecomputerguy) - IT & networking
- [The Cyber Mentor](https://www.youtube.com/channel/UC0ArlFuFYMpEewyRBzdLHiw) - Ethical hacking
- [ITProTV](https://www.youtube.com/user/ITProTV) - IT certifications
- [freeCodeCamp.org](https://www.youtube.com/freecodecamp) - Free comprehensive courses
- [With Sandra](https://www.youtube.com/@WithSandra) - Career & tech
- [Andrew Huberman](https://www.youtube.com/@hubermanlab) - Learning & productivity science
- [Tech with Jono](https://www.youtube.com/@TechwithJono) - Tech tutorials
- [Practical Networking](https://www.youtube.com/@PracticalNetworking) - Networking fundamentals
- [David Bombal](https://www.youtube.com/@davidbombal) - Cisco & networking
- [John Hammond](https://www.youtube.com/@_JohnHammond) - Hacking & security
- [LiveOverflow](https://www.youtube.com/@LiveOverflow) - CTF & binary exploitation
- [PwnFunction](https://www.youtube.com/@PwnFunction) - Security concepts
- [SecurityWeekly](https://www.youtube.com/@SecurityWeekly) - Security news & updates
- [BlackHat Official](https://www.youtube.com/@BlackHatOfficialYT) - Security conferences
- [DEFCONConference](https://www.youtube.com/@DEFCONConference) - Hacker conference talks

### Featured Video Playlists & Courses
- [CompTIA A+ Full Course (31+ Hours)](https://www.youtube.com/watch?v=1CZXXNKAY5o&list=PLejqXniG-4qmFqpxbWd7Oo235uH1ffG2x&index=5)
- [CompTIA Network+ Full Course](https://www.youtube.com/watch?v=qiQR5rTSshw&list=PLejqXniG-4qmFqpxbWd7Oo235uH1ffG2x&index=6)
- [CompTIA Security+ SY0-701 Full Course](https://www.youtube.com/watch?v=KiEptGbnEBc&list=PLG49S3nxzAnl4QDVqK-hOnoqcSKEIDDuv)
- [CompTIA CySA+ 2024 Crash Course (10+ Hours)](https://www.youtube.com/watch?v=qP9x0mucwVc&list=PLejqXniG-4qmFqpxbWd7Oo235uH1ffG2x&index=9)
- [CASP+ Course](https://www.youtube.com/watch?v=vwNjLVpXNzk&list=PLCNmoXT8zexnJtDOdd8Owa8TAdSVVWF-J)
- [Ethical Hacking 15 Hours Course](https://www.youtube.com/watch?v=3FNYvj2U0HM&list=PLejqXniG-4qmFqpxbWd7Oo235uH1ffG2x&index=13)
- [Complete Ethical Hacking 16 Hours](https://www.youtube.com/watch?v=w_oxcjPOWos&list=PLejqXniG-4qmFqpxbWd7Oo235uH1ffG2x&index=4)
- [Python Full Course for Free](https://www.youtube.com/watch?v=ix9cRaBkVe0)
- [Subnetting Mastery](https://www.youtube.com/watch?v=BWZ-MHIhqjM&list=PLIFyRwBY_4bQUE4IB5c4VPRyDoLgOdExE)
- [NMAP Full Guide](https://www.youtube.com/watch?v=JHAMj2vN2oU&t=33s)

### Learning Science & Study Techniques
- [Optimal Protocols for Studying & Learning](https://youtu.be/ddq8JIMhz7c?si=qT00KFkFBAwm7LP7)
- [How to Study Using Active Recall](https://youtu.be/mzexJPoXBCM?si=sv-yeuIoLF9pwDRG)
- [Learning with Failures, Movement & Balance](https://youtu.be/jwChiek_aRY?si=3kyPbIAVwJWMPfnG)

### Practice Exam Videos
- [CompTIA Security+ PBQ](https://youtu.be/zfwxSmL4n6w?si=q5lXlvmViTK6TnSI)
- [CompTIA Network+ PBQ](https://www.youtube.com/live/9cdL214y-u0?si=lCSxriFy636PbOnR)
- [CompTIA CySA+ PBQ](https://www.youtube.com/live/0NMffWaxlmA?si=Rm9IBkZ04OAxFJtp)
- [CompTIA CASP+ PBQ](https://www.youtube.com/live/eInvTuYBF3Q?si=Hbe4mWLd3X31AUkA)

---

## Reddit Communities

### Main Subreddits
- [r/CompTIA](https://www.reddit.com/r/CompTIA/) - CompTIA certifications
- [r/CyberSecurity](https://www.reddit.com/r/cybersecurity/) - Cybersecurity discussions
- [r/AskNetsec](https://www.reddit.com/r/AskNetsec/) - Network security Q&A
- [r/ITCareerQuestions](https://www.reddit.com/r/ITCareerQuestions/) - Career advice
- [r/InformationSecurity](https://www.reddit.com/r/InformationSecurity/) - InfoSec discussions
- [r/netsec](https://www.reddit.com/r/netsec/) - Network security news
- [r/ethicalhacking](https://www.reddit.com/r/ethicalhacking/) - Ethical hacking
- [r/BlueTeamSec](https://www.reddit.com/r/BlueTeamSec/) - Defensive security
- [r/RedTeam](https://www.reddit.com/r/RedTeam/) - Offensive security
- [r/netsecstudents](https://www.reddit.com/r/netsecstudents/) - Students learning security

### Certification-Specific Communities
- [r/Casp](https://www.reddit.com/r/casp/) - CASP+ certification
- [r/CCNA](https://www.reddit.com/r/ccna/) - CCNA certification
- [r/WGU](https://www.reddit.com/r/WGU/) - Western Governors University
- [r/sysadmin](https://www.reddit.com/r/sysadmin/) - System administration
- [r/linuxquestions](https://www.reddit.com/r/linuxquestions/) - Linux help
- [r/ReverseEngineering](https://www.reddit.com/r/ReverseEngineering/) - Reverse engineering
- [r/ITsecurity](https://www.reddit.com/r/ITsecurity/) - IT security

### Popular Reddit Posts
- [Master List: Study Resources for A+, Network+, Security+](https://www.reddit.com/r/CompTIA/comments/i7hx4t/master_list_i_compiled_and_ranked_every_major/)
- [How I Passed Sec+](https://www.reddit.com/r/CompTIA/comments/zkjs1d/how_a_dumdum_like_me_passed_sec/)
- [How I Passed CompTIA A+, N+, S+](https://www.reddit.com/r/CompTIA/comments/1cra3cg/how_i_passed_comptia_a_n_s/)
- [Passed Sec+, PenTest+, CySA+ in 2 Months 22 Days](https://www.reddit.com/r/CompTIA/comments/1f5cofp/passed_sec_pentest_cysa_in_2_months_22_days/)
- [34 Year Old, No IT Experience, Got Hired After A+ Cert](https://www.reddit.com/r/CompTIA/comments/m38lb8/update_34_years_old_posted_a_month_ago_about/)
- [Hiring Manager Advice to Newbies](https://www.reddit.com/r/ITCareerQuestions/comments/ni4vnm/general_advice_from_a_hiring_manager_and_23_year/)
- [CompTIA Trifecta in 6 Months](https://www.reddit.com/r/CompTIA/comments/1fmjb2p/just_passed_network_got_the_trifecta_in_about_6/)
- [I Passed CASP+ Study Guide](https://www.reddit.com/r/casp/comments/1ft2qjr/i_passed_casp_this_is_what_i_did_to_prepare/)

---

## Security Frameworks

### NIST Framework Suite
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [NIST Privacy Framework](https://www.nist.gov/privacy-framework)
- [NIST 800-53 Security Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [NIST 800-171](https://csrc.nist.gov/publications/detail/sp/800-171/rev-2/final)
- [NIST 800-37 Risk Management Framework](https://csrc.nist.gov/publications/detail/sp/800-37/rev-2/final)
- [NIST 800-39 Managing Information Security Risk](https://csrc.nist.gov/publications/detail/sp/800-39/final)
- [NIST 800-61 Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [NIST 800-63 Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)
- [NIST 800-207 Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [NIST 800-218 Secure Software Development Framework](https://csrc.nist.gov/publications/detail/sp/800-218/final)

### ISO/IEC Standards
- [ISO/IEC 27001](https://www.iso.org/isoiec-27001-information-security.html) - Information security management
- [ISO/IEC 27002](https://www.iso.org/standard/73906.html) - Security controls code of practice
- [ISO/IEC 27032](https://www.iso.org/standard/44375.html) - Cybersecurity guidelines
- [ISO/IEC 27033](https://www.iso.org/standard/63411.html) - Network security
- [ISO/IEC 27034](https://www.iso.org/standard/44379.html) - Application security
- [ISO 22301](https://www.iso.org/iso-22301-business-continuity.html) - Business continuity

### Industry Frameworks
- [MITRE ATT&CK Framework](https://attack.mitre.org/) - Adversary tactics & techniques
- [Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Web application risks
- [CIS Controls](https://www.cisecurity.org/controls) - Critical security controls
- [Cybersecurity Maturity Model Certification (CMMC)](https://www.acq.osd.mil/cmmc/)
- [Cloud Security Alliance CCSK](https://cloudsecurityalliance.org/education/ccsk/)

### Compliance & Regulatory
- [PCI-DSS](https://www.pcisecuritystandards.org/) - Payment card security
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [GDPR](https://gdpr.eu/) - European data protection
- [FedRAMP](https://www.fedramp.gov/) - Federal cloud security
- [SOC 2](https://www.vanta.com/products/soc-2) - Service organization controls
- [SOX IT Controls](https://www.sarbanes-oxley-101.com/sarbanes-oxley-compliance.htm)

### Analysis & Modeling
- [Diamond Model of Intrusion Analysis](https://www.threatintel.academy/wp-content/uploads/2020/07/diamond-model.pdf)
- [Unified Kill Chain](https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf)
- [MITRE Shield](https://shield.mitre.org/) - Defense techniques
- [MITRE Engage](https://engage.mitre.org/) - Adversary engagement
- [VERIS](http://veriscommunity.net/) - Data breach framework

---

## Industry Resources

### Security News & Blogs
- [Krebs on Security](https://krebsonsecurity.com/)
- [Dark Reading](https://www.darkreading.com/)
- [Rapid7 Blog](https://www.rapid7.com/blog/)
- [Malwarebytes Labs](https://blog.malwarebytes.com/)

### Training & Education Organizations
- [SANS Institute](https://www.sans.org/)
- [InfoSec Institute](https://www.infosecinstitute.com/)
- [OWASP](https://owasp.org)
- [SANS Cyber Aces](https://www.cyberaces.org/)

### Professional Organizations
- [CompTIA](https://www.comptia.org/)
- [ISC2](https://www.isc2.org/)
- [ISACA](https://www.isaca.org/)

### Development & Tools
- [GitHub](https://github.com/) - Version control & collaboration
- [Kali Linux](https://www.kali.org/) - Penetration testing distro
- [Ubuntu](https://ubuntu.com/) - Linux distribution
- [Oracle VirtualBox](https://www.oracle.com/virtualization/technologies/vm/downloads/virtualbox-downloads.html) - Virtual machines
- [Red Hat](https://www.redhat.com/en) - Enterprise Linux

---

## Cloud Certifications

### AWS Cloud
- [AWS Certified Cloud Practitioner Exam Guide](https://d1.awsstatic.com/training-and-certification/docs-cloud-practitioner/AWS-Certified-Cloud-Practitioner_Exam-Guide.pdf)
- [AWS Cloud Practitioner Essentials (Free)](https://aws.amazon.com/training/learn-about/cloud-practitioner/)
- [AWS Cloud Quest: Cloud Practitioner](https://aws.amazon.com/training/digital/aws-cloud-quest/)
- [AWS Skill Builder - Free Learning Path](https://explore.skillbuilder.aws/learn/public/learning_plan/view/1/cloud-foundations-learning-plan)
- [Ultimate AWS Certified Cloud Practitioner CLF-C02 2025](https://www.udemy.com/course/aws-certified-cloud-practitioner-new/)
- [AWS Certified Cloud Practitioner YouTube Course](https://www.youtube.com/watch?v=SOTamWNgDKc)
- [AWS Certified Cloud Practitioner 15 Hour FreeCodeCamp](https://www.youtube.com/watch?v=NhDYbskXRgc)
- [AWS Security Specialty](https://aws.amazon.com/certification/certified-security-specialty/)

### Microsoft Azure
- [Azure Fundamentals (AZ-900)](https://learn.microsoft.com/en-us/training/paths/az-900-describe-cloud-concepts/)
- [Azure Security Engineer Associate](https://learn.microsoft.com/en-us/certifications/azure-security-engineer/)

### Google Cloud
- [Google Cloud Digital Leader](https://cloud.google.com/certification/cloud-digital-leader)
- [Google Professional Cloud Security Engineer](https://cloud.google.com/certification/cloud-security-engineer)

### Other Cloud Platforms
- [Oracle Cloud Infrastructure Foundations](https://education.oracle.com/oracle-cloud-infrastructure-foundations-2023-associate/pexam_1Z0-1085-23)
- [IBM Cloud Essentials](https://www.ibm.com/training/badge/cloud-essentials)

---

## CISSP Resources

### Official Materials
- [CISSP Exam Outline](https://www.isc2.org/-/media/ISC2/Certifications/Exam-Outlines/CISSP-Exam-Outline-English-April-2021.ashx)
- [ISC2 CISSP Certification Details](https://www.isc2.org/Certifications/CISSP)
- [ISC2 Official Training](https://www.isc2.org/Training/Self-Study-Resources)
- [Official ISC2 CISSP Study Guide (9th Edition)](https://www.amazon.com/Certified-Information-Security-Professional-Official/dp/1119786231/)
- [CISSP Study Guide 2025-2026](https://www.amazon.com/CISSP-Study-Guide-2025-2026-Certification/dp/B0DRHZG41M)
- [CISSP For Dummies (7th Edition)](https://www.amazon.com/CISSP-Dummies-Computer-Tech/dp/1119806836/)

### Practice Tests & Prep
- [CISSP Official Practice Tests (3rd Edition)](https://www.amazon.com/CISSP-Official-ISC-Practice-Tests/dp/1119787637/)
- [Boson CISSP Practice Exams](https://www.boson.com/practice-exam/cissp-isc2-practice-exam)
- [TotalTester CISSP Practice Exams](https://www.totalsem.com/cissp-practice-tests/)
- [CISSP Pocket Prep Mobile App](https://pocketprep.com/exam-bank/isc2-cissp/)
- [CISSP Certification Complete Training 2025](https://www.udemy.com/course/cissp-certification-cissp-training/)
- [CISSP Practice Exams 2025](https://www.udemy.com/course/cissp-practice-exams-2020/)

### YouTube Courses
- [CISSP Course 2024](https://www.youtube.com/watch?v=M1_v5HBVHWo)
- [CISSP MasterClass - Mike Chapple](https://www.youtube.com/watch?v=v8furUCfuaY)
- [Inside CISSP - Kelly Handerhan](https://www.youtube.com/playlist?list=PL7XJSuT7Dq_XPLpbZOrNXA-lsQbvx3YeQ)

### Study Resources
- [Study Notes and Theory CISSP Blog](https://www.studynotesandtheory.com/)
- [Cybrary CISSP Course (Free)](https://www.cybrary.it/course/cissp/)

---

## LinkedIn Professionals to Follow

### Industry Leaders
- [Mike Chapple](https://www.linkedin.com/in/mikechapple/) - Security educator
- [Brian Krebs](https://www.linkedin.com/in/bkrebs/) - Security journalist
- [Troy Hunt](https://www.linkedin.com/in/troyhunt/) - Web security expert
- [Heath Adams](https://www.linkedin.com/in/heathadams/) - Ethical hacking educator
- [Jason Dion](https://www.linkedin.com/in/jasondion/) - CompTIA instructor
- [Kevin Mitnick](https://www.linkedin.com/in/kevinmitnick/) - Security consultant
- [Chuck Brooks](https://www.linkedin.com/in/chuckbrooks/) - Security thought leader
- [Jane Frankland](https://www.linkedin.com/in/janefrankland/) - Cybersecurity strategist
- [Rinki Sethi](https://www.linkedin.com/in/rinkisethi/) - Security leader
- [Tyler Cohen Wood](https://www.linkedin.com/in/tylercohenwood/) - Threat intelligence

### Organizations
- [CompTIA](https://www.linkedin.com/company/comptia/posts/?feedView=all)
- [ISC2](https://www.linkedin.com/company/isc2/)
- [ISACA](https://www.linkedin.com/company/isaca/)
- [SANS Institute](https://www.linkedin.com/company/sans-institute/)
- [OWASP](https://www.linkedin.com/company/owasp/)

---

## Additional Learning Resources

### Specialized Platforms
- [Infosec Skills](https://www.infosecinstitute.com/skills/) - Hands-on labs
- [INE Security](https://ine.com/learning/areas/security) - Security specialization
- [Offensive Security](https://www.offensive-security.com/) - Advanced training
- [EC-Council CodeRed](https://codered.eccouncil.org/) - Interactive learning
- [ITPRO](https://www.acilearning.com/itpro/) - IT Professional training
- [Professor Messer Website](https://www.professormesser.com/) - Free study materials

### Cheat Sheets & References
- [Digital Cloud Training AWS Cheat Sheets](https://digitalcloud.training/aws-cheat-sheets/)
- [Tutorials Dojo AWS Exam Guide](https://tutorialsdojo.com/aws-cloud-practitioner-clf-c02-exam-guide/)
- [wyzguys Cybersecurity Blog (CASP focused)](https://wyzguyscybersecurity.com/new-insights-for-the-casp-cas-004-exam/)

---

**Last Updated:** November 2025

**Tips for Success:**
- Start with free resources to test your interest
- Combine video courses with hands-on labs
- Use practice exams to measure progress
- Join communities for support and networking
- Stay current with security news and trends
