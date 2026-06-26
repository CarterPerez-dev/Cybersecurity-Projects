<div align="center">
  <img width="260" height="260" alt="Kali dragon icon" src="https://github.com/user-attachments/assets/d911b71f-6ad9-45b7-9513-237f83377023"/>
  <h1>Cybersecurity Projects</h1>
  <p>70 hands-on security tools — from first-time programmers to advanced engineers</p>
</div>

<div align="center">

[![Stars](https://img.shields.io/github/stars/CarterPerez-dev/Cybersecurity-Projects)](https://github.com/CarterPerez-dev/Cybersecurity-Projects)
[![Forks](https://img.shields.io/github/forks/CarterPerez-dev/Cybersecurity-Projects)](https://github.com/CarterPerez-dev/Cybersecurity-Projects)
[![Issues](https://img.shields.io/github/issues/CarterPerez-dev/Cybersecurity-Projects)](https://github.com/CarterPerez-dev/Cybersecurity-Projects)
[![License](https://img.shields.io/github/license/CarterPerez-dev/Cybersecurity-Projects)](LICENSE)
[![Source Code](https://img.shields.io/badge/Projects_with_source-36/70-blue)](./PROJECTS)
[![Sponsor](https://img.shields.io/static/v1?label=Sponsor&message=%E2%9D%A4&logo=GitHub&color=darkgreen)](https://github.com/sponsors/CarterPerez-dev)

</div>

<p align="center">Made possible by <a href="https://certgames.com"><strong>CertGames</strong></a></p>

A curated collection of cybersecurity projects organized by skill level. Each project includes full source code, documentation, and learning materials.

Browse the [certification roadmaps](./ROADMAPS/README.md) for career guidance or the [learning resources](./RESOURCES/README.md) for tools, courses, and communities.

> Currently building: **Self-Hosted Shodan Clone**

## Projects

<div align="center">
  <img src="https://img.shields.io/badge/Foundations-5DEFD0?style=for-the-badge&logo=bookstack&logoColor=black&labelColor=5DEFD0" alt="Foundations"/>
  <img src="https://img.shields.io/badge/Beginner-2EA44F?style=for-the-badge&logo=leaflet&logoColor=white" alt="Beginner"/>
  <img src="https://img.shields.io/badge/Intermediate-D4A017?style=for-the-badge&logo=target&logoColor=white" alt="Intermediate"/>
  <img src="https://img.shields.io/badge/Advanced-C73E3A?style=for-the-badge&logo=shield&logoColor=white" alt="Advanced"/>
</div>

### Foundations Projects

> **Start here if this is your first time coding.** The Foundations tier is *pre-beginner* — for someone who has never written Python, has barely used a terminal, and is new to cybersecurity. Source files are heavily commented as a teaching aid, and every `learn/` folder explains concepts from zero.
>
> **What makes Foundations different:**
> - **Single-file projects** — the entire tool lives in one readable Python file
> - **Heavy teaching comments** — every new concept is annotated inline
> - **Numpy-style docstrings** — every function documents what, why, and each parameter
> - **Extra-deep `learn/` folders** — Python features and security concepts explained from zero
> - **Production-quality code** — written to real standards, explained for beginners

| Project | Info | What You'll Learn |
|---------|------|-------------------|
| **[Hash Identifier](./PROJECTS/foundations/hash-identifier)**<br>Identify hash types by prefix, length, and charset | ![Step 1/3](https://img.shields.io/badge/Step-1%2F3_easiest-2EA44F?style=flat&logo=bookstack&logoColor=white) ![2-4h](https://img.shields.io/badge/⏱️_2--4h-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) | Hash families (MD5, SHA, bcrypt, Argon2) • PHC string format • Pattern matching • Pure-function design |
| **[HTTP Headers Scanner](./PROJECTS/foundations/http-headers-scanner)**<br>Audit a URL's response headers for missing or weak security controls | ![Step 2/3](https://img.shields.io/badge/Step-2%2F3_stepping_up-D4A017?style=flat&logo=bookstack&logoColor=white) ![3-5h](https://img.shields.io/badge/⏱️_3--5h-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) | HTTP fundamentals • Security headers (CSP, HSTS, X-Frame-Options) • httpx requests • Scored audits |
| **[Password Manager](./PROJECTS/foundations/password-manager)**<br>Encrypted local vault with master password unlock | ![Step 3/3](https://img.shields.io/badge/Step-3%2F3_hardest-C73E3A?style=flat&logo=bookstack&logoColor=white) ![6-8h](https://img.shields.io/badge/⏱️_6--8h-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) | Argon2id key derivation • AES-GCM authenticated encryption • Secure on-disk vaults • Master-password workflows |

### Beginner Projects

| Project | Info | What You'll Learn |
|---------|------|-------------------|
| **[Simple Port Scanner](./PROJECTS/beginner/simple-port-scanner)**<br>Async TCP port scanner in C++ [@deniskhud](https://github.com/deniskhud) | ![4-5h](https://img.shields.io/badge/⏱️_4--5h-blue) ![C++](https://img.shields.io/badge/C%2B%2B-00599C?logo=cplusplus) | TCP socket programming • Async I/O patterns • Service detection |
| **[Keylogger](./PROJECTS/beginner/keylogger)**<br>Capture keyboard events with timestamps | ![4-5h](https://img.shields.io/badge/⏱️_4--5h-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) | Event handling • File I/O • Ethical considerations |
| **[Caesar Cipher](./PROJECTS/beginner/caesar-cipher)**<br>CLI encryption/decryption tool | ![4-5h](https://img.shields.io/badge/⏱️_4--5h-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) | Classical cryptography • Brute force attacks • CLI design |
| **[DNS Lookup CLI Tool](./PROJECTS/beginner/dns-lookup)**<br>Query DNS records with WHOIS | ![6-7h](https://img.shields.io/badge/⏱️_6--7h-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) | DNS protocols • WHOIS queries • Reverse DNS lookup |
| **[Simple Vulnerability Scanner](./PROJECTS/beginner/simple-vulnerability-scanner)**<br>Check software against CVE databases | ![12-14h](https://img.shields.io/badge/⏱️_12--14h-blue) ![Go](https://img.shields.io/badge/Go-00ADD8?logo=go&logoColor=white) | CVE databases • Dependency scanning • Vulnerability assessment |
| **[Metadata Scrubber Tool](./PROJECTS/beginner/metadata-scrubber-tool)**<br>Remove EXIF and privacy metadata [@Heritage-XioN](https://github.com/Heritage-XioN) | ![10-12h](https://img.shields.io/badge/⏱️_10--12h-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) | EXIF data • Privacy protection • Batch processing |
| **[Network Traffic Analyzer](./PROJECTS/beginner/network-traffic-analyzer)**<br>Capture and analyze packets | ![10-12h](https://img.shields.io/badge/⏱️_10--12h-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) ![C++](https://img.shields.io/badge/C%2B%2B-00599C?logo=cplusplus) | Packet capture • Protocol analysis • Traffic visualization |
| **[Hash Cracker](./PROJECTS/beginner/hash-cracker)**<br>Dictionary and brute-force cracking | ![5-6h](https://img.shields.io/badge/⏱️_5--6h-blue) ![C++](https://img.shields.io/badge/C%2B%2B-00599C?logo=cplusplus) | Hash algorithms • Dictionary attacks • Password security |
| **[Steganography Multi-Tool](./SYNOPSES/beginner/Steganography.Multi.Tool.md)**<br>Hide data in images, audio, QR, PDFs, text | ![8-10h](https://img.shields.io/badge/⏱️_8--10h-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) | Multi-format steganography • Zero-width Unicode • Audio LSB • QR exploitation |
| **[Ghost on the Wire](./SYNOPSES/beginner/Ghost.On.The.Wire.md)**<br>L2 attack & defense: MAC spoofing + ARP detection | ![6-8h](https://img.shields.io/badge/⏱️_6--8h-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) | ARP protocol • MAC spoofing • MITM detection • L2 trust mapping |
| **[Canary Token Generator](./PROJECTS/beginner/canary-token-generator)**<br>Self-hosted honeytokens that alert on access | ![8-10h](https://img.shields.io/badge/⏱️_8--10h-blue) ![Go](https://img.shields.io/badge/Go-00ADD8?logo=go&logoColor=white) ![React](https://img.shields.io/badge/React-61DAFB?logo=react&logoColor=black) | Deception defense • Honeytokens • MySQL wire protocol • PDF/DOCX patching<br>[Live Demo](https://iglowinthedark.com/) |
| **[Security News Scraper](./SYNOPSES/beginner/Security.News.Scraper.md)**<br>Aggregate cybersecurity news | ![10-14h](https://img.shields.io/badge/⏱️_10--14h-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) | Web scraping • CVE parsing • Database storage |
| **[Phishing Domain Generator & Quishing Scanner](./SYNOPSES/beginner/Phishing.Domain.Generator.And.Quishing.Scanner.md)**<br>Typosquat generation + QR phishing detection | ![6-8h](https://img.shields.io/badge/⏱️_6--8h-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) | Homoglyph attacks • Typosquatting • QR code analysis • Domain intelligence |
| **[SSH Brute Force Detector](./SYNOPSES/beginner/SSH.Brute.Force.Detector.md)**<br>Monitor and block SSH attacks | ![2-4h](https://img.shields.io/badge/⏱️_2--4h-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) | Log parsing • Attack detection • Firewall automation |
| **[Simple C2 Beacon](./PROJECTS/beginner/c2-beacon)**<br>Command and Control beacon/server | ![10-12h](https://img.shields.io/badge/⏱️_10--12h-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) ![React](https://img.shields.io/badge/React-61DAFB?logo=react&logoColor=black) ![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white) | C2 architecture • MITRE ATT&CK • WebSocket protocol • XOR encoding |
| **[Base64 Encoder/Decoder](./SYNOPSES/beginner/Base64.Encoder.Decoder.md)**<br>Multi-format encoding tool | ![2h](https://img.shields.io/badge/⏱️_2h-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) | Base64/32 encoding • URL encoding • Auto-detection |
| **[Linux CIS Hardening Auditor](./PROJECTS/beginner/linux-cis-hardening-auditor)**<br>CIS benchmark compliance checker | ![6-8h](https://img.shields.io/badge/⏱️_6--8h-blue) ![Bash](https://img.shields.io/badge/Bash-4EAA25?logo=gnubash&logoColor=white) | CIS benchmarks • System hardening • Compliance scoring • Shell scripting |
| **[Systemd Persistence Scanner](./PROJECTS/beginner/systemd-persistence-scanner)**<br>Hunt Linux persistence mechanisms | ![6-8h](https://img.shields.io/badge/⏱️_6--8h-blue) ![Go](https://img.shields.io/badge/Go-00ADD8?logo=go&logoColor=white) | Persistence techniques • Systemd internals • Cron analysis • Threat hunting |
| **[Linux eBPF Security Tracer](./PROJECTS/beginner/linux-ebpf-security-tracer)**<br>Real-time syscall tracing with eBPF | ![10-12h](https://img.shields.io/badge/⏱️_10--12h-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) ![C](https://img.shields.io/badge/C-A8B9CC?logo=c&logoColor=black) | eBPF programs • Syscall tracing • BCC framework • Security observability |
| **[Trojan Application Builder](./SYNOPSES/beginner/Trojan.Application.Builder.md)**<br>Educational malware lifecycle demo | ![8-10h](https://img.shields.io/badge/⏱️_8--10h-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) | Trojan anatomy • Data exfiltration • File encryption • Attack lifecycle |
| **[DNS Sinkhole](./SYNOPSES/beginner/DNS.Sinkhole.md)**<br>Pi-hole-style malware domain blocker | ![10-12h](https://img.shields.io/badge/⏱️_10--12h-blue) ![Go](https://img.shields.io/badge/Go-00ADD8?logo=go&logoColor=white) | DNS protocol • Blocklist management • Query logging • Network defense |
| **[Firewall Rule Engine](./PROJECTS/beginner/firewall-rule-engine)**<br>Parse and validate iptables/nftables rules | ![6-8h](https://img.shields.io/badge/⏱️_6--8h-blue) ![V](https://img.shields.io/badge/V-5D87BF?logo=v&logoColor=white) | Firewall internals • Rule parsing • iptables/nftables |
| **[LLM Prompt Injection Firewall](./SYNOPSES/beginner/LLM.Prompt.Injection.Firewall.md)**<br>Detect and block prompt injection attacks | ![8-10h](https://img.shields.io/badge/⏱️_8--10h-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) | AI security • Prompt injection • Input sanitization • LLM defense |

### Intermediate Projects

| Project | Info | What You'll Learn |
|---------|------|-------------------|
| **[Payload Obfuscation Engine](./SYNOPSES/intermediate/Payload.Obfuscation.Engine.md)**<br>Multi-layer payload obfuscation toolkit | ![3-5d](https://img.shields.io/badge/⏱️_3--5d-blue) ![Go](https://img.shields.io/badge/Go-00ADD8?logo=go&logoColor=white) | Obfuscation techniques • Polymorphism • AV evasion • Signature detection |
| **[SIEM Dashboard](./SYNOPSES/intermediate/SIEM.Dashboard.md)**<br>Log aggregation with correlation | ![3-5d](https://img.shields.io/badge/⏱️_3--5d-blue) ![React](https://img.shields.io/badge/React-61DAFB?logo=react&logoColor=black) ![Flask](https://img.shields.io/badge/Flask-000000?logo=flask) | SIEM concepts • Log correlation • Full-stack development<br>[Live Demo](https://siem.carterperez-dev.com/) |
| **[Token Abuse Playground](./SYNOPSES/intermediate/Token.Abuse.Playground.md)**<br>15+ token vulnerabilities to exploit and fix | ![3-5d](https://img.shields.io/badge/⏱️_3--5d-blue) ![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi) ![React](https://img.shields.io/badge/React-61DAFB?logo=react&logoColor=black) | JWT exploitation • OAuth attacks • Session security • Token forensics |
| **[Supply Chain Attack Simulator](./SYNOPSES/intermediate/Supply.Chain.Attack.Simulator.md)**<br>Fake PyPI package dependency confusion demo | ![2-4d](https://img.shields.io/badge/⏱️_2--4d-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) | Supply chain attacks • Dependency confusion • Package security • PyPI internals |
| **[DDoS Mitigation Tool](./SYNOPSES/intermediate/DDoS.Mitigation.Tool.md)**<br>Detect traffic spikes | ![2-4d](https://img.shields.io/badge/⏱️_2--4d-blue) ![Go](https://img.shields.io/badge/Go-00ADD8?logo=go&logoColor=white) | DDoS detection • Rate limiting • Anomaly detection |
| **[Secrets Scanner](./PROJECTS/intermediate/secrets-scanner)**<br>Scan codebases and git history for leaked secrets | ![1-2d](https://img.shields.io/badge/⏱️_1--2d-blue) ![Go](https://img.shields.io/badge/Go-00ADD8?logo=go&logoColor=white) | Secret detection • Shannon entropy • HIBP k-anonymity • SARIF output |
| **[API Security Scanner](./PROJECTS/intermediate/api-security-scanner)**<br>Enterprise API vulnerability scanner | ![3-5d](https://img.shields.io/badge/⏱️_3--5d-blue) ![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi) ![React](https://img.shields.io/badge/React-61DAFB?logo=react&logoColor=black) ![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white) | OWASP API Top 10 • ML fuzzing • GraphQL/SOAP testing |
| **[Wireless Deauth Detector](./SYNOPSES/intermediate/Wireless.Deauth.Detector.md)**<br>Monitor WiFi deauth attacks | ![2-4d](https://img.shields.io/badge/⏱️_2--4d-blue) ![Rust](https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white) | Wireless security • Packet sniffing • Attack detection |
| **[Credential Enumeration](./PROJECTS/intermediate/credential-enumeration)**<br>Post-exploitation credential collection | ![2-4d](https://img.shields.io/badge/⏱️_2--4d-blue) ![Nim](https://img.shields.io/badge/Nim-FFE953?logo=nim&logoColor=black) | Credential extraction • Browser forensics • Red team tooling |
| **[Binary Analysis Tool](./PROJECTS/intermediate/binary-analysis-tool)**<br>Disassemble and analyze executables | ![3-5d](https://img.shields.io/badge/⏱️_3--5d-blue) ![Rust](https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white) | Binary analysis • String extraction • Malware detection<br>[Live Demo](https://axumortem.carterperez-dev.com/) |
| **[Chaos Engineering Security Tool](./SYNOPSES/intermediate/Chaos.Engineering.Security.Tool.md)**<br>Inject security failures to test resilience | ![3-5d](https://img.shields.io/badge/⏱️_3--5d-blue) ![Go](https://img.shields.io/badge/Go-00ADD8?logo=go&logoColor=white) | Chaos engineering • Security resilience • Credential spraying • Auth testing |
| **[Credential Rotation Enforcer](./PROJECTS/intermediate/credential-rotation-enforcer)**<br>Track and enforce credential rotation policies | ![2-4d](https://img.shields.io/badge/⏱️_2--4d-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) | Credential hygiene • Secret rotation • Compliance dashboards • API integration |
| **[Race Condition Exploiter](./SYNOPSES/intermediate/Race.Condition.Exploiter.md)**<br>TOCTOU race condition attack & defense lab | ![3-5d](https://img.shields.io/badge/⏱️_3--5d-blue) ![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi) ![React](https://img.shields.io/badge/React-61DAFB?logo=react&logoColor=black) | TOCTOU attacks • Double-spend bugs • Concurrent exploitation • Race visualization |
| **[Self-Hosted Shodan Clone](./SYNOPSES/intermediate/Self.Hosted.Shodan.Clone.md)**<br>Internet-connected device search engine | ![3-5d](https://img.shields.io/badge/⏱️_3--5d-blue) ![Go](https://img.shields.io/badge/Go-00ADD8?logo=go&logoColor=white) ![React](https://img.shields.io/badge/React-61DAFB?logo=react&logoColor=black) | Service fingerprinting • Network scanning • OSINT • Search engine design |
| **[JA3/JA4 TLS Fingerprinting Tool](./PROJECTS/intermediate/ja3-ja4-tls-fingerprinting)**<br>Fingerprint TLS clients by handshake | ![2-4d](https://img.shields.io/badge/⏱️_2--4d-blue) ![Rust](https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white) | TLS handshake analysis • JA3/JA4 hashing • Bot detection • Malware C2 identification<br>[Live Demo](https://mkultraalumni.com/) |
| **[Mobile App Security Analyzer](./SYNOPSES/intermediate/Mobile.App.Security.Analyzer.md)**<br>Decompile and analyze mobile apps | ![3-5d](https://img.shields.io/badge/⏱️_3--5d-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) | APK/IPA analysis • Reverse engineering • OWASP Mobile |
| **[DLP Scanner](./PROJECTS/intermediate/dlp-scanner)**<br>Data Loss Prevention for files, DBs, and traffic | ![2-4d](https://img.shields.io/badge/⏱️_2--4d-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) | PII detection • GDPR/HIPAA compliance • Pattern matching • Data classification |
| **[Lua/Nginx Edge Backend](./SYNOPSES/intermediate/Lua.Nginx.Edge.Backend.md)**<br>Full CRUD backend via Lua in Nginx | ![3-5d](https://img.shields.io/badge/⏱️_3--5d-blue) ![Lua](https://img.shields.io/badge/Lua-2C2D72?logo=lua&logoColor=white) ![Nginx](https://img.shields.io/badge/Nginx-009639?logo=nginx&logoColor=white) | Edge computing • OpenResty • Lua scripting • WAF • JWT at the edge |
| **[Privesc Playground](./SYNOPSES/intermediate/Privesc.Playground.md)**<br>20+ privilege escalation paths to exploit | ![3-5d](https://img.shields.io/badge/⏱️_3--5d-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) | SUID exploitation • Sudo abuse • Cron hijacking • GTFOBins • Capability abuse |
| **[SBOM Generator & Vulnerability Matcher](./PROJECTS/intermediate/sbom-generator-vulnerability-matcher)**<br>Software Bill of Materials with CVE matching | ![2-4d](https://img.shields.io/badge/⏱️_2--4d-blue) ![Go](https://img.shields.io/badge/Go-00ADD8?logo=go&logoColor=white) | SPDX/CycloneDX formats • Dependency analysis • CVE databases • EO 14028 compliance |
| **[Subdomain Takeover Scanner](./SYNOPSES/intermediate/Subdomain.Takeover.Scanner.md)**<br>Detect dangling DNS records | ![2-4d](https://img.shields.io/badge/⏱️_2--4d-blue) ![Go](https://img.shields.io/badge/Go-00ADD8?logo=go&logoColor=white) | DNS enumeration • CNAME analysis • Cloud resource claiming • Bug bounty |
| **[GraphQL Security Tester](./SYNOPSES/intermediate/GraphQL.Security.Tester.md)**<br>Automated GraphQL vulnerability testing | ![2-4d](https://img.shields.io/badge/⏱️_2--4d-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) | Introspection attacks • Query depth DoS • Authorization bypass • Batching abuse |
| **[Docker Security Audit](./PROJECTS/intermediate/docker-security-audit)**<br>CIS Docker Benchmark scanner | ![1-2d](https://img.shields.io/badge/⏱️_1--2d-blue) ![Go](https://img.shields.io/badge/Go-00ADD8?logo=go&logoColor=white) | CIS benchmarks • Container security • Multiple output formats |

### Advanced Projects

| Project | Info | What You'll Learn |
|---------|------|-------------------|
| **[API Rate Limiter](./PROJECTS/advanced/api-rate-limiter)**<br>Distributed rate limiting middleware | ![1w](https://img.shields.io/badge/⏱️_1w-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) ![Redis](https://img.shields.io/badge/Redis-DC382D?logo=redis&logoColor=white) | Token bucket algorithm • Distributed systems • Redis backend |
| **[Encrypted Chat Application](./PROJECTS/advanced/encrypted-p2p-chat)**<br>Real-time E2EE messaging | ![1-2w](https://img.shields.io/badge/⏱️_1--2w-blue) ![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi) ![SolidJS](https://img.shields.io/badge/SolidJS-2C4F7C?logo=solid) ![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?logo=postgresql&logoColor=white) | Signal Protocol • Double Ratchet • WebAuthn • WebSockets |
| **[Exploit Development Framework](./SYNOPSES/advanced/Exploit.Development.Framework.md)**<br>Modular exploitation framework | ![3-4w](https://img.shields.io/badge/⏱️_3--4w-blue) ![C++](https://img.shields.io/badge/C%2B%2B-00599C?logo=cplusplus) | Exploit development • Payload generation • Plugin architecture |
| **[AI Threat Detection](./PROJECTS/advanced/ai-threat-detection)**<br>ML-powered nginx threat detection | ![3-4w](https://img.shields.io/badge/⏱️_3--4w-blue) ![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi) ![React](https://img.shields.io/badge/React-61DAFB?logo=react&logoColor=black) ![PyTorch](https://img.shields.io/badge/PyTorch-EE4C2C?logo=pytorch&logoColor=white) | ML ensemble (AE + RF + IF) • ONNX inference • Real-time detection |
| **[Bug Bounty Platform](./PROJECTS/advanced/bug-bounty-platform)**<br>Full vulnerability disclosure platform | ![2-3w](https://img.shields.io/badge/⏱️_2--3w-blue) ![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi) ![React](https://img.shields.io/badge/React-61DAFB?logo=react&logoColor=black) ![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?logo=postgresql&logoColor=white) | Full-stack development • CVSS scoring • Workflow automation<br>[Live Demo](https://bugbounty.carterperez-dev.com/) |
| **[Cloud Security Compliance Dashboard](./SYNOPSES/advanced/Cloud.Security.Compliance.Dashboard.md)**<br>Multi-cloud compliance with CIS, SOC2, HIPAA | ![2-3w](https://img.shields.io/badge/⏱️_2--3w-blue) ![Go](https://img.shields.io/badge/Go-00ADD8?logo=go&logoColor=white) ![React](https://img.shields.io/badge/React-61DAFB?logo=react&logoColor=black) | CIS benchmarks • SOC2/HIPAA compliance • Cost-security optimization • Drift detection |
| **[Malware Analysis Platform](./SYNOPSES/advanced/Malware.Analysis.Platform.md)**<br>Automated sandbox analysis | ![2-3w](https://img.shields.io/badge/⏱️_2--3w-blue) ![Rust](https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white) ![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white) | Malware analysis • Sandboxing • YARA rules • IOC extraction |
| **[Quantum Resistant Encryption](./SYNOPSES/advanced/Quantum.Resistant.Encryption.md)**<br>Post-quantum cryptography | ![3-4w](https://img.shields.io/badge/⏱️_3--4w-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) | Post-quantum algorithms • Hybrid encryption • Kyber/Dilithium |
| **[Zero Day Vulnerability Scanner](./SYNOPSES/advanced/Zero.Day.Vulnerability.Scanner.md)**<br>Coverage-guided fuzzing | ![2-3w](https://img.shields.io/badge/⏱️_2--3w-blue) ![Rust](https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white) ![C](https://img.shields.io/badge/C-A8B9CC?logo=c&logoColor=black) | Fuzzing • Vulnerability research • Crash triage |
| **[Distributed Password Cracker](./SYNOPSES/advanced/Distributed.Password.Cracker.md)**<br>GPU-accelerated cracking | ![3-4w](https://img.shields.io/badge/⏱️_3--4w-blue) ![C++](https://img.shields.io/badge/C%2B%2B-00599C?logo=cplusplus) ![CUDA](https://img.shields.io/badge/CUDA-76B900?logo=nvidia) | Distributed systems • GPU computing • Hash cracking |
| **[Kernel Rootkit Detection](./SYNOPSES/advanced/Kernel.Rootkit.Detection.md)**<br>Detect kernel-level rootkits | ![2-3w](https://img.shields.io/badge/⏱️_2--3w-blue) ![Rust](https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white) | Kernel internals • Memory forensics • Rootkit detection |
| **[Blockchain Smart Contract Auditor](./SYNOPSES/advanced/Blockchain.Smart.Contract.Auditor.md)**<br>Solidity vulnerability analysis | ![3-4w](https://img.shields.io/badge/⏱️_3--4w-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) ![Solidity](https://img.shields.io/badge/Solidity-363636?logo=solidity) | Smart contracts • Static analysis • Solidity security |
| **[Adversarial ML Attacker](./SYNOPSES/advanced/Adversarial.ML.Attacker.md)**<br>Generate adversarial examples | ![3-4w](https://img.shields.io/badge/⏱️_3--4w-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) ![TensorFlow](https://img.shields.io/badge/TensorFlow-FF6F00?logo=tensorflow&logoColor=white) | Adversarial ML • FGSM/DeepFool • Model robustness |
| **[Advanced Persistent Threat Simulator](./SYNOPSES/advanced/Advanced.Persistent.Threat.Simulator.md)**<br>Multi-stage APT simulation | ![3-4w](https://img.shields.io/badge/⏱️_3--4w-blue) ![Go](https://img.shields.io/badge/Go-00ADD8?logo=go&logoColor=white) | APT techniques • C2 infrastructure • Lateral movement |
| **[Hardware Security Module Emulator](./PROJECTS/advanced/hsm-emulator)**<br>Software HSM that compiles to a real PKCS#11 `.so` | ![2-3w](https://img.shields.io/badge/⏱️_2--3w-blue) ![Zig](https://img.shields.io/badge/Zig-F7A41D?logo=zig&logoColor=white) | PKCS#11/Cryptoki C ABI • AES-GCM/CBC • RSA/ECDSA/ECDH • Argon2id + encrypted-at-rest |
| **[Network Covert Channel](./SYNOPSES/advanced/Network.Covert.Channel.md)**<br>Data exfiltration techniques | ![3-4w](https://img.shields.io/badge/⏱️_3--4w-blue) ![Rust](https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white) | Covert channels • Data exfiltration • Steganography |
| **[Automated Penetration Testing](./SYNOPSES/advanced/Automated.Penetration.Testing.md)**<br>Full pentest automation | ![3-4w](https://img.shields.io/badge/⏱️_3--4w-blue) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) | Pentest automation • Recon to exploitation • Report generation |
| **[Haskell Reverse Proxy](./PROJECTS/advanced/haskell-reverse-proxy)**<br>Functional reverse proxy with security middleware | ![2-3w](https://img.shields.io/badge/⏱️_2--3w-blue) ![Haskell](https://img.shields.io/badge/Haskell-5D4F85?logo=haskell&logoColor=white) | Functional programming • Reverse proxy design • Security middleware |
| **["Monitor the Situation" Dashboard](./PROJECTS/advanced/monitor-the-situation-dashboard)**<br>Real-time cyber threat situational awareness | ![3-4w](https://img.shields.io/badge/⏱️_3--4w-blue) ![Go](https://img.shields.io/badge/Go-00ADD8?logo=go&logoColor=white) ![React](https://img.shields.io/badge/React-61DAFB?logo=react&logoColor=black) ![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?logo=postgresql&logoColor=white) | Threat intel feeds • EPSS/KEV/CVE velocity • BGP hijacks • WebSocket fan-out • 3D globe SOC view<br>[Live Demo](https://iminthewalls.com/) |
| **[Honeypot Network](./PROJECTS/advanced/honeypot-network)**<br>Multi-service honeypot deployment & analysis | ![2-3w](https://img.shields.io/badge/⏱️_2--3w-blue) ![Go](https://img.shields.io/badge/Go-00ADD8?logo=go&logoColor=white) ![React](https://img.shields.io/badge/React-61DAFB?logo=react&logoColor=black) ![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white) | Honeypot deployment • Attacker behavior analysis • IOC extraction • MITRE mapping<br>[Live Demo](https://honeypot-network.carterperez-dev.com/) |
| **[Supply Chain Security Analyzer](./SYNOPSES/advanced/Supply.Chain.Security.Analyzer.md)**<br>Dependency vulnerability analysis | ![2-3w](https://img.shields.io/badge/⏱️_2--3w-blue) ![Go](https://img.shields.io/badge/Go-00ADD8?logo=go&logoColor=white) | Supply chain security • Dependency analysis • Malicious packages |

## Getting Started

Each project lives in its own directory under [`PROJECTS/`](./PROJECTS) with its own README, source code, and `learn/` documentation. To explore a project:

```sh
cd PROJECTS/<tier>/<project-name>
# Then follow that project's README for setup and usage
```

Projects marked with a synopsis (under [`SYNOPSES/`](./SYNOPSES)) have detailed design documents available. Source-code-complete projects are indicated by the blue badge count above.

## Roadmaps & Resources

- **[Certification Roadmaps](./ROADMAPS/README.md)** — 10 career paths for SOC Analyst, Pentester, Security Engineer, GRC Analyst, and more
- **[Learning Resources](./RESOURCES/README.md)** — Curated tools, courses, certifications, YouTube channels, Reddit communities, and security frameworks

## Contributing

Contributions are welcome. If you want to add a project, improve existing code, or fix documentation:

1. Fork the repository
2. Create a feature branch
3. Open a pull request

See the [open issues](https://github.com/CarterPerez-dev/Cybersecurity-Projects/issues) for ideas on what to work on.

## License

[AGPL 3.0](./LICENSE)
