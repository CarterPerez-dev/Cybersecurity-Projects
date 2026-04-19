# Hive Honeypot Network

## What This Is

A multi-protocol honeypot network that simulates six real services (SSH, HTTP, FTP, SMB, MySQL, Redis), captures every attacker interaction, maps behavior to MITRE ATT&CK techniques, extracts threat intelligence (IOCs), and visualizes it all through a real-time web dashboard. Built entirely in Go with a React frontend.

## Why This Matters

Honeypots are one of the most effective ways to study real attacker behavior. Every connection to a honeypot is suspicious by definition since legitimate users have no reason to interact with fake services. Security teams at companies like Deutsche Telekom, Rapid7, and SANS use honeypot networks to detect compromised hosts, collect malware samples, and track attack campaigns.

The 2023 Cowrie SSH honeypot data from SANS showed over 2.3 million brute force attempts per month against a single sensor. Organizations running honeypots routinely discover compromised internal hosts attempting lateral movement, catching what firewall logs miss.

**Real world scenarios where this applies:**
- A SOC team deploys internal honeypots alongside production servers. When an attacker moves laterally after initial compromise, they hit the honeypot and trigger immediate alerting, catching what EDR missed
- A threat intelligence team runs public-facing honeypots to track botnet campaigns, collecting IoCs (IP addresses, malware hashes, credential lists) that feed into their SIEM and blocklists
- An incident responder uses honeypot session replays to understand exactly what commands an attacker ran, what tools they downloaded, and what persistence mechanisms they installed

## What You'll Learn

This project teaches you how honeypots work at the protocol level. By implementing each service from scratch, you understand both the attacker's perspective and the defender's tooling.

**Security Concepts:**
- Protocol emulation at depth levels: how much of SSH, HTTP, FTP, SMB, MySQL, and Redis you need to implement to fool automated tools vs. human attackers
- MITRE ATT&CK technique detection: mapping raw events (brute force attempts, discovery commands, tool transfers) to framework technique IDs
- Indicator of Compromise extraction: pulling IP addresses, URLs, domains, tool fingerprints, and credential pairs from protocol-level event data

**Technical Skills:**
- Building TCP servers that speak real wire protocols (SSH handshake, MySQL greeting packets, RESP commands, SMB negotiate)
- Event-driven architecture with fan-out pub/sub, worker pools, and non-blocking channels in Go
- Full-stack application development with Go backend, PostgreSQL persistence, Redis streaming, and React dashboard

**Tools and Techniques:**
- golang.org/x/crypto/ssh for building an SSH server with fake shell, filesystem, and session recording
- STIX 2.1 standard for threat intelligence sharing, generating bundles compatible with MISP and OpenCTI
- Asciicast v2 format for terminal session recording, replayable in the browser via xterm.js

## Prerequisites

**Required knowledge:**
- Go fundamentals: goroutines, channels, interfaces, error handling. You should be comfortable writing concurrent Go programs
- Basic networking: TCP/IP, how clients connect to servers, what a protocol handshake looks like
- SQL basics: CREATE TABLE, INSERT, SELECT with JOINs. The project uses PostgreSQL but nothing exotic

**Tools you'll need:**
- Go 1.25+ (the project uses modern Go features)
- Docker and Docker Compose (for PostgreSQL, Redis, and the full stack)
- Node.js 20+ and pnpm (for the React frontend)

**Helpful but not required:**
- Familiarity with any of the six protocols (SSH, HTTP, FTP, SMB, MySQL, Redis) at the wire level
- Experience with MITRE ATT&CK framework
- React and TypeScript knowledge (for the dashboard)

## Quick Start

```bash
cd PROJECTS/advanced/honeypot-network

# Check dependencies and build
./install.sh

# Start everything with Docker
just dev-up

# Or run just the backend locally (requires PostgreSQL and Redis)
just dev-serve
```

Expected output: Six honeypot services start listening, the API serves on port 8000, and the dashboard loads at http://localhost:5173. Connect to `ssh root@localhost -p 2222` with any password to see your first captured session.

## Project Structure

```
honeypot-network/
├── cmd/hive/              # CLI entry point
├── pkg/types/             # Shared domain types (Event, Session, IOC)
├── internal/
│   ├── sshd/              # SSH honeypot (shell, filesystem, commands)
│   ├── httpd/             # HTTP honeypot (WordPress, phpMyAdmin fakes)
│   ├── ftpd/              # FTP honeypot (auth capture, upload logging)
│   ├── smbd/              # SMB honeypot (negotiate-only)
│   ├── mysqld/            # MySQL honeypot (wire protocol, query logging)
│   ├── redisd/            # Redis honeypot (RESP commands)
│   ├── event/             # Event bus + processor pipeline
│   ├── store/             # PostgreSQL + Redis persistence
│   ├── mitre/             # ATT&CK technique detection engine
│   ├── intel/             # IOC extraction, STIX export, blocklists
│   ├── api/               # REST + WebSocket dashboard API
│   └── ...                # config, geo, ratelimit, session, ui
├── frontend/              # React 19 + TypeScript dashboard
├── migrations/            # PostgreSQL schema (goose format)
├── infra/                 # Docker, nginx, Redis configs
├── learn/                 # You are here
└── compose.yml            # Production Docker Compose
```

## Next Steps

1. **Understand the concepts** - Read [01-CONCEPTS.md](./01-CONCEPTS.md) to learn honeypot theory, protocol emulation, and how MITRE ATT&CK mapping works
2. **Study the architecture** - Read [02-ARCHITECTURE.md](./02-ARCHITECTURE.md) to see the event-driven design and data flow
3. **Walk through the code** - Read [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) for how each protocol is emulated
4. **Extend the project** - Read [04-CHALLENGES.md](./04-CHALLENGES.md) for ideas like adding Telnet, SMTP, or ML anomaly detection

## Common Issues

**SSH host key error on repeated starts**
```
ssh: handshake failed: ssh: no common algorithm for host key
```
Solution: Delete `data/hostkey_ed25519` and restart. A new key will be auto-generated.

**PostgreSQL connection refused**
Solution: Make sure the database is running. With Docker: `just dev-up postgres`. Locally: check that PostgreSQL is listening on port 5432.

**Frontend WebSocket not connecting**
Solution: The Vite dev server proxies `/ws/*` to the backend. Make sure the backend is running on port 8000 before starting the frontend.

## Related Projects

If you found this interesting, check out:
- **SIEM Dashboard** (intermediate) - Builds the monitoring side that consumes data from tools like this
- **DLP Scanner** (beginner) - Another detection tool, focused on data exfiltration patterns
- **AI Threat Detection** (advanced) - Adds machine learning to the analysis pipeline
