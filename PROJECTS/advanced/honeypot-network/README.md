```regex
██╗  ██╗██╗██╗   ██╗███████╗
██║  ██║██║██║   ██║██╔════╝
███████║██║██║   ██║█████╗
██╔══██║██║╚██╗ ██╔╝██╔══╝
██║  ██║██║ ╚████╔╝ ███████╗
╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝
```

[![Cybersecurity Projects](https://img.shields.io/badge/Cybersecurity--Projects-Honeypot_Network-red?style=flat&logo=github)](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/advanced/honeypot-network)
[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go&logoColor=white)](https://go.dev)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat&logo=react&logoColor=black)](https://react.dev)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Live Demo](https://img.shields.io/badge/Live-honeypot--network.carterperez--dev.com-green?style=flat&logo=googlechrome)](https://honeypot-network.carterperez-dev.com/)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat&logo=docker)](https://www.docker.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-27_Techniques-orange?style=flat)](https://attack.mitre.org/)

> Multi-protocol honeypot network that simulates six real services, captures attacker behavior, maps to MITRE ATT&CK, extracts IOCs, and visualizes everything through a real-time dashboard.

*This is a quick overview. Security theory, architecture, and full walkthroughs are in the [learn modules](#learn).*

## What It Does

- Simulates 6 services: SSH (fake shell with 25+ commands), HTTP (WordPress/phpMyAdmin fakes), FTP (PASV file capture), SMB (negotiate), MySQL (wire protocol), Redis (RESP)
- Captures every attacker interaction: credentials, commands, file uploads, scanning patterns, tool fingerprints
- Maps behavior to 27 MITRE ATT&CK techniques across 8 tactics with single-event and sliding-window detection
- Extracts IOCs (IPs, URLs, domains, user-agents, credentials) with confidence scoring and deduplication
- Exports threat intelligence as STIX 2.1 bundles and firewall blocklists (iptables, nginx deny, plain text, CSV)
- Records SSH sessions in asciicast v2 format, replayable in the browser via xterm.js
- Streams events in real time via WebSocket to a React dashboard with attack maps, MITRE heatmaps, and session replay

## Quick Start

```bash
git clone https://github.com/CarterPerez-dev/Cybersecurity-Projects.git
cd PROJECTS/advanced/honeypot-network
cp .env.example .env
docker compose -f dev.compose.yml up -d
```

Dashboard loads at `http://localhost:3000` or the live demo at [honeypot-network.carterperez-dev.com](https://honeypot-network.carterperez-dev.com/). Connect to the SSH honeypot to see your first captured session:

```bash
ssh root@localhost -p 2222
```

Use any password. Run commands like `ls`, `cat /etc/passwd`, `wget http://example.com/payload.sh`, and watch events stream into the dashboard.

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` to see all available commands.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## Architecture

```
                    ┌─────────────────────────────────────────────┐
    Attackers       │              Hive Backend                   │
                    │                                             │
  ┌──────┐         │  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐   │
  │ SSH  │────2222──│──│ sshd │  │ httpd│  │ ftpd │  │ smbd │   │
  │Client│         │  └──┬───┘  └──┬───┘  └──┬───┘  └──┬───┘   │
  └──────┘         │     │         │         │         │        │
  ┌──────┐         │  ┌──┴───┐  ┌──┴───┐                        │
  │MySQL │────3307──│──│mysqld│  │redisd│                        │
  │Client│         │  └──┬───┘  └──┬───┘                        │
  └──────┘         │     │         │                             │
                   │     ▼         ▼                             │
                   │  ┌─────────────────┐                        │
                   │  │    Event Bus    │  (fan-out pub/sub)      │
                   │  └────────┬────────┘                        │
                   │           │                                 │
                   │     ┌─────┴─────┐                           │
                   │     │ Processor │  (4 worker goroutines)    │
                   │     │  GeoIP    │                           │
                   │     │  MITRE    │                           │
                   │     │  Store    │                           │
                   │     │  Stream   │                           │
                   │     └───────────┘                           │
                   │                                             │
                   │  ┌─────────────────┐                        │
                   │  │   REST API      │  Chi router :8000      │
                   │  │   WebSocket     │  /ws/events             │
                   │  └─────────────────┘                        │
                   └──────────────┬──────────────────────────────┘
                                  │
                   ┌──────────────┴──────────────────┐
                   │         Frontend                │
                   │   React 19 + TypeScript         │
                   │   Dashboard • Events • Sessions │
                   │   MITRE Heatmap • Intel Export   │
                   └─────────────────────────────────┘
```

## Services

| Service | Port | Protocol | Interaction Depth |
|---------|------|----------|-------------------|
| SSH | 2222 | x/crypto/ssh | Full shell with filesystem, 25+ commands, session recording |
| HTTP | 8080 | net/http | WordPress/phpMyAdmin fakes, scanner detection, vulnerability path traps |
| FTP | 2121 | Raw TCP | AUTH + PASV data channel, file upload capture (1MB cap) |
| SMB | 4450 | Raw TCP | NetBIOS framing + negotiate response, SMB1/SMB2 detection |
| MySQL | 3307 | Raw TCP | Binary wire protocol greeting, auth capture, query handling |
| Redis | 6380 | tidwall/redcon | RESP protocol, PING/AUTH/INFO/CONFIG/SET/GET/KEYS |

## Stack

**Backend:** Go 1.25, Chi v5, nhooyr.io/websocket, pgxpool (PostgreSQL), go-redis, zerolog, Cobra CLI

**Frontend:** React 19, TypeScript, Vite 6, SCSS (OKLCH tokens), TanStack Query v5, Zustand, Recharts, react-leaflet, xterm.js

**Infrastructure:** Docker Compose, PostgreSQL 17, Redis 7.4, nginx reverse proxy, multi-stage builds

## API

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | Health check with version and sensor ID |
| `GET /api/stats/overview` | Total events, events by service, active sessions |
| `GET /api/stats/countries` | Event counts by country |
| `GET /api/stats/credentials` | Top captured username/password pairs |
| `GET /api/events` | Paginated events with IP filtering |
| `GET /api/sessions` | Paginated session list |
| `GET /api/sessions/{id}` | Session detail with commands and techniques |
| `GET /api/sessions/{id}/replay` | Asciicast v2 recording for session replay |
| `GET /api/attackers` | Attacker list with geo and tool info |
| `GET /api/mitre/techniques` | Full technique catalog |
| `GET /api/mitre/heatmap` | Technique detection counts for heatmap |
| `GET /api/iocs` | Paginated IOC list |
| `GET /api/iocs/export/stix` | STIX 2.1 bundle export |
| `GET /api/iocs/export/blocklist` | Blocklist export (plain, iptables, nginx, csv) |
| `WS /ws/events` | Real-time event stream |

## MITRE ATT&CK Coverage

Hive detects 27 techniques across 8 tactics:

| Tactic | Techniques |
|--------|------------|
| Reconnaissance | T1595, T1595.002 |
| Initial Access | T1078, T1190 |
| Execution | T1059.004 |
| Persistence | T1053.003, T1543.002, T1098.004 |
| Credential Access | T1110, T1110.001, T1110.003, T1552.001 |
| Discovery | T1082, T1083, T1046, T1018, T1049, T1016 |
| Lateral Movement | T1021.004 |
| Command and Control | T1105, T1071.001 |
| Impact | T1496, T1485, T1489 |

Detection uses two strategies: single-event pattern matching (command → technique) and multi-event sliding windows (5+ auth attempts in 5 minutes → T1110 Brute Force, 3+ distinct services in 60 seconds → T1046 Network Service Discovery).

## CLI

```bash
hive serve                       # Start all services
hive serve --config hive.yml     # Custom config file
hive migrate up                  # Apply database migrations
hive migrate down                # Rollback last migration
hive migrate status              # Show migration status
hive keygen                      # Generate SSH host key
```

## Configuration

All settings can be set via YAML config file or environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `HIVE_SENSOR_ID` | `hive-01` | Sensor identifier |
| `HIVE_SSH_ENABLED` | `true` | Enable SSH honeypot |
| `HIVE_SSH_PORT` | `2222` | SSH listen port |
| `HIVE_HTTP_ENABLED` | `true` | Enable HTTP honeypot |
| `HIVE_HTTP_PORT` | `8080` | HTTP listen port |
| `HIVE_FTP_ENABLED` | `true` | Enable FTP honeypot |
| `HIVE_FTP_PORT` | `2121` | FTP listen port |
| `HIVE_SMB_ENABLED` | `true` | Enable SMB honeypot |
| `HIVE_SMB_PORT` | `4450` | SMB listen port |
| `HIVE_MYSQL_ENABLED` | `true` | Enable MySQL honeypot |
| `HIVE_MYSQL_PORT` | `3307` | MySQL listen port |
| `HIVE_REDIS_ENABLED` | `true` | Enable Redis honeypot |
| `HIVE_REDIS_PORT` | `6380` | Redis listen port |
| `HIVE_API_ADDR` | `:8000` | Dashboard API listen address |
| `HIVE_DB_DSN` | `postgres://...` | PostgreSQL connection string |
| `HIVE_REDIS_URL` | `redis://...` | Infrastructure Redis URL |
| `HIVE_GEOIP_PATH` | `data/GeoLite2-City.mmdb` | MaxMind database path |
| `HIVE_SSH_HOSTKEY_PATH` | `data/hostkey_ed25519` | SSH host key path |
| `HIVE_LOG_LEVEL` | `info` | Log level (debug, info, warn, error) |

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
├── learn/                 # Learning modules
└── compose.yml            # Production Docker Compose
```

## Learn

| Module | Topic |
|--------|-------|
| [00 - Overview](learn/00-OVERVIEW.md) | Prerequisites, quick start, project structure |
| [01 - Concepts](learn/01-CONCEPTS.md) | Honeypot theory, protocol emulation, MITRE ATT&CK, IOC types |
| [02 - Architecture](learn/02-ARCHITECTURE.md) | Event-driven design, data flow, design patterns |
| [03 - Implementation](learn/03-IMPLEMENTATION.md) | SSH shell emulation, MySQL wire protocol, FTP state machine |
| [04 - Challenges](learn/04-CHALLENGES.md) | Add Telnet/SMTP, deploy to VPS, ML anomaly detection |

## Common Issues

**SSH host key error on repeated starts**
```
ssh: handshake failed: ssh: no common algorithm for host key
```
Delete `data/hostkey_ed25519` and restart. A new key will be auto-generated.

**PostgreSQL connection refused**
Make sure the database is running. With Docker: `docker compose up -d postgres`. Check that PostgreSQL is listening on port 5432.

**Frontend WebSocket not connecting**
The Vite dev server proxies `/ws/*` to the backend. Make sure the backend is running on port 8000 before starting the frontend.

## Legal Disclaimer

This tool is designed for authorized security research and educational purposes. Deploying honeypots on networks you do not own or control may violate local laws and regulations. Before deploying:

- Ensure you have authorization from network owners
- Check your cloud provider's acceptable use policy (some prohibit honeypots)
- Be aware that honeypots collect attacker data, which may include personal information subject to privacy regulations (GDPR, CCPA)
- Do not use captured data for offensive purposes
- If deploying on a public IP, understand that you are inviting connections from potentially hostile actors

The authors are not responsible for misuse of this software.

## License

AGPL 3.0
