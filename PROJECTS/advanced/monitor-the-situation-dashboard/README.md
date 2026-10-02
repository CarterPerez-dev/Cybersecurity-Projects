<!--
©AngelaMos | 2026
README.md
-->

```json
 ██████╗██╗ █████╗
██╔════╝██║██╔══██╗
██║     ██║███████║
██║     ██║██╔══██║
╚██████╗██║██║  ██║
 ╚═════╝╚═╝╚═╝  ╚═╝
```

[![Cybersecurity Projects](https://img.shields.io/badge/Cybersecurity--Projects-Project%20%2328-red?style=flat&logo=github)](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/advanced/monitor-the-situation-dashboard)
[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go&logoColor=white)](https://go.dev)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat&logo=react&logoColor=black)](https://react.dev)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Live Demo](https://img.shields.io/badge/Live-iminthewalls.com-green?style=flat&logo=googlechrome)](https://iminthewalls.com/)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat&logo=docker)](https://www.docker.com)

> Operator-grade real-time situational awareness dashboard. Eleven live feeds across cyber, world, and finance — fused into a single 3D-globe SOC view with WebSocket delivery and configurable alerting.

*The Learn docs are here: [learn modules](#learn).*

> The phrase "monitoring the situation" is a Twitter/X meme from June 2025. This is the version that actually monitors the situation.

## What It Does

- Aggregates 11 high-signal data feeds (DShield, Cloudflare Radar, NVD/EPSS, CISA KEV, ransomware.live, Coinbase WS, USGS, NOAA SWPC, Wikipedia ITN, GDELT, ISS) with per-source cadences from sub-second to daily
- WebSocket fan-out from a single Go binary — collectors run as errgroup goroutines, events flow through an in-process bus to all connected clients
- 3D MapLibre globe centerpiece with country-level outage shading, BGP hijack regions, mass-scan source ASN dots, ransomware victim markers, earthquake epicenters, and live ISS orbital track
- CVE velocity timeline with EPSS-weighted prioritization and CISA KEV diff alerts
- Configurable alerts (toast / banner / chime / Telegram / Discord) with AES-256 encryption of webhook secrets at rest
- BRIN-indexed Postgres time-series storage tuned for append-mostly event streams
- JWT auth with auto-rotating Ed25519 keys, public read-only mode, multi-device session management

## Quick Start

```bash
just dev-up
```

Visit `http://localhost:8432` or the live demo at [iminthewalls.com](https://iminthewalls.com/)

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` to see all available commands.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## Stack

**Backend:** Go 1.25, chi v5, `coder/websocket`, pgx + pgxpool, goose migrations, errgroup-driven collectors, Argon2id, JWT (Ed25519)

**Frontend:** React 19, TypeScript, Vite, TanStack Query v5, Zustand, MapLibre GL, D3, SCSS Modules

**Data:** PostgreSQL 16 (BRIN time-series indexes), Redis 7

**Infrastructure:** Docker Compose, nginx reverse proxy, Cloudflare Tunnel (prod), multi-stage builds, air for live reload

## Data Sources

| Panel | Source | Cadence | Auth |
|-------|--------|---------|------|
| Mass-scan firehose | DShield (SANS ISC) | 1h | none |
| Internet outages + BGP hijacks | Cloudflare Radar | 5m | `CF_RADAR_TOKEN` |
| CVE velocity + EPSS | NVD CVE 2.0 + FIRST EPSS | 2h | `NVD_API_KEY` (optional) |
| CISA KEV (in-the-wild) | CISA KEV catalog | 1h | none |
| Ransomware victims | ransomware.live | 15m | none |
| BTC + ETH live ticks | Coinbase Advanced Trade WS | persistent | none |
| Earthquakes (M2.5+) | USGS GeoJSON | 1m | none |
| Space weather (Kp / Bz / X-flux) | NOAA SWPC | 1m / 3h | none |
| World events | Wikipedia ITN + GDELT v2 | 5m / 15m | none |
| ISS position + passes | wheretheiss.at + CelesTrak | 10s / 24h | none |
| IP enrichment (BGP) | AbuseIPDB | on-demand | `ABUSEIPDB_API_KEY` (optional) |

## Production (Cloudflare Tunnel)

```bash
cp .env.example .env
just prod-redeploy
just migrate
```

## Tests

```bash
cd backend && go test -race ./...
```

## Learn

This project includes step-by-step learning materials covering security theory, architecture, and implementation.

| Module | Topic |
|--------|-------|
| [00 - Overview](learn/00-OVERVIEW.md) | Prerequisites and quick start |
| [01 - Concepts](learn/01-CONCEPTS.md) | Threat intel feeds, BGP hijacks, EPSS, KEV, situational awareness theory |
| [02 - Architecture](learn/02-ARCHITECTURE.md) | Single-binary collector pipeline, in-process event bus, WebSocket fan-out |
| [03 - Implementation](learn/03-IMPLEMENTATION.md) | Code walkthrough across collectors, snapshot, ws, alerts |
| [04 - Challenges](learn/04-CHALLENGES.md) | Extension ideas (additional feeds, custom alerts, deployment) |

## License

AGPL 3.0
