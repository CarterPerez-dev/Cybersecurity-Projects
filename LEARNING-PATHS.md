# Cybersecurity Learning Paths

These paths connect projects that are already listed in this repository. Work through them in order, using each project's README and `learn/` guides for setup and exercises. The prerequisites are starting points; you can skip material you already know.

Security tools in these paths are for your own systems and controlled labs. Use local fixtures or systems you have explicit permission to test. Do not point scanners or simulations at public or third-party systems.

## Web Application Security

**Prerequisites:** Basic command-line use and familiarity with HTTP requests, forms, and JSON. Start with the beginner projects if you have not written a small script before.

1. [HTTP Headers Scanner](./PROJECTS/foundations/http-headers-scanner/) — review HTTPS security headers and their effect on a local test endpoint or another endpoint you are authorized to assess.
2. [Deserialization Gadget Lab](./PROJECTS/beginner/deserialization-gadget-lab/) — study unsafe deserialization and the effect of strict allowlists in a self-contained lab.
3. [API Security Scanner](./PROJECTS/intermediate/api-security-scanner/) — practice assessing API security controls and interpreting scan results against a local test service.
4. [Secrets Scanner](./PROJECTS/intermediate/secrets-scanner/) — find exposed credentials in sample repositories and learn how to handle findings without disclosing secrets.
5. [Bug Bounty Platform](./PROJECTS/advanced/bug-bounty-platform/) — see how authorized reports move through triage, remediation, and disclosure workflows.

**Expected outcome:** Recognize common web and API weaknesses, distinguish useful findings from noise, and document a vulnerability for responsible remediation.

## Network Security

**Prerequisites:** Basic command-line use and an understanding of IP addresses, DNS, ports, and client/server connections.

1. [DNS Lookup](./PROJECTS/beginner/dns-lookup/) — inspect common DNS records and understand how names resolve.
2. [Simple Port Scanner](./PROJECTS/beginner/simple-port-scanner/) — map listening services on a local lab host and relate open ports to service exposure.
3. [Firewall Rule Engine](./PROJECTS/beginner/firewall-rule-engine/) — express allow and deny rules and reason about their order and effect.
4. [Network Traffic Analyzer](./PROJECTS/beginner/network-traffic-analyzer/python/) — inspect a packet capture generated inside your isolated lab; do not capture traffic from a network you do not control.
5. [JA3/JA4 TLS Fingerprinting](./PROJECTS/intermediate/ja3-ja4-tls-fingerprinting/) — examine TLS handshake fingerprints in a saved lab capture and understand their limits as detection signals.
6. [Honeypot Network](./PROJECTS/advanced/honeypot-network/) — study its simulated services and analyze interactions only inside an isolated lab.

**Expected outcome:** Explain how network services are exposed, how traffic can be observed, and how defensive controls and telemetry fit together.

## Cloud Security

**Prerequisites:** Basic Linux command-line skills and familiarity with containers, configuration files, and secrets. The implemented projects here focus on workload and host controls; they do not teach cloud-provider IAM or account setup.

1. [Linux CIS Hardening Auditor](./PROJECTS/beginner/linux-cis-hardening-auditor/) — compare a local Linux system or fixture with baseline hardening checks.
2. [Secrets Scanner](./PROJECTS/intermediate/secrets-scanner/) — identify credentials accidentally included in source and configuration files.
3. [Docker Security Audit](./PROJECTS/intermediate/docker-security-audit/) — review container images and Compose configuration for risky settings.
4. [SIEM Dashboard](./PROJECTS/intermediate/siem-dashboard/) — use generated events to practice correlation, alert handling, and investigation.
5. [Cloud Security Compliance Dashboard](./SYNOPSES/advanced/Cloud.Security.Compliance.Dashboard.md) — capstone design exercise for multi-cloud compliance and drift detection. This is a synopsis only; implementation is not present in the repository.

**Expected outcome:** Apply host, container, secret-management, and monitoring controls to cloud-hosted workloads, and identify where provider-specific controls need additional study.

## Offensive Security

**Prerequisites:** Basic command-line use, networking concepts, and comfort reading a small program. Keep all exercises inside local labs and use only sample data or binaries you are authorized to analyze.

1. [Caesar Cipher](./PROJECTS/beginner/caesar-cipher/) — learn basic encryption, decryption, brute force, and why classical ciphers are not secure.
2. [Hash Cracker](./PROJECTS/beginner/hash-cracker/) — compare dictionary and brute-force approaches using sample hashes you created for the exercise.
3. [Simple Port Scanner](./PROJECTS/beginner/simple-port-scanner/) — inspect service exposure on a local lab host.
4. [Deserialization Gadget Lab](./PROJECTS/beginner/deserialization-gadget-lab/) — understand a vulnerability class using the included isolated examples.
5. [Binary Analysis Tool](./PROJECTS/intermediate/binary-analysis-tool/) — inspect authorized sample binaries, file structure, strings, and disassembly.
6. [Zero-Day Vulnerability Scanner](./PROJECTS/advanced/zero-day-vulnerability-scanner/) — explore vulnerability discovery workflows only with synthetic targets and isolated test inputs; do not scan live systems.

**Expected outcome:** Understand foundational offensive techniques and use them to explain risk and improve defenses without testing systems outside an authorized lab.

---

[Back to the project catalog](./README.md) · [Certification roadmaps](./ROADMAPS/README.md)
