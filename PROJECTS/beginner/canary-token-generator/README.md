```yaml
 ██████╗ █████╗ ███╗   ██╗ █████╗ ██████╗ ██╗   ██╗
██╔════╝██╔══██╗████╗  ██║██╔══██╗██╔══██╗╚██╗ ██╔╝
██║     ███████║██╔██╗ ██║███████║██████╔╝ ╚████╔╝
██║     ██╔══██║██║╚██╗██║██╔══██║██╔══██╗  ╚██╔╝
╚██████╗██║  ██║██║ ╚████║██║  ██║██║  ██║   ██║
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝
```

[![Cybersecurity Projects](https://img.shields.io/badge/Cybersecurity--Projects-Project%20%2332-red?style=flat&logo=github)](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/beginner/canary-token-generator)
[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go&logoColor=white)](https://go.dev)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat&logo=react&logoColor=black)](https://react.dev)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-18-4169E1?style=flat&logo=postgresql&logoColor=white)](https://www.postgresql.org)
[![Redis](https://img.shields.io/badge/Redis-7-DC382D?style=flat&logo=redis&logoColor=white)](https://redis.io)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat&logo=docker)](https://www.docker.com)
[![MITRE Engage](https://img.shields.io/badge/MITRE-Engage-red?style=flat)](https://engage.mitre.org/)

[![Live Demo](https://img.shields.io/badge/Live-iglowinthedark.com-green?style=flat&logo=googlechrome)](https://iglowinthedark.com/)

> Self-hosted honeytoken generator. Mints seven kinds of tripwire artifacts — invisible web bugs, booby-trapped PDF/DOCX files, fake `.env` and kubeconfig credentials, and a real MySQL wire-protocol decoy — then alerts you on Telegram or a webhook the moment an attacker touches one.

*This is a quick overview — security theory, architecture, and full walkthroughs are in the [learn modules](#learn).*

## What It Does

- Seven token types, each disguised as something an attacker would actually try to use: `webbug`, `slowredirect`, `pdf`, `docx`, `envfile`, `kubeconfig`, and a real `mysql` listener that speaks the MySQL v10 handshake
- Per-token Telegram or webhook alerts the instant a token fires (HMAC-signed for webhooks)
- Async notification worker pool with per-channel timeouts and dedup gating (15-minute Redis silence window per `{token, source_ip}` so a curious attacker reloading the page doesn't spam you)
- GeoIP enrichment via MaxMind GeoLite2 (country, region, city, ASN, ASN org) attached to every event
- Browser fingerprint capture for `slowredirect` tokens via a 3-second JS-collection interstitial before the redirect resolves
- Public manage URL (UUID-gated) so you can share a single link with a teammate to view triggers without exposing operator credentials
- Operator-only admin API (constant-time bearer comparison) for global stats, token listing, and force-disable
- Cloudflare Turnstile on token creation, dual-window rate limiting (per-minute + per-hour) keyed by browser fingerprint
- Optional Cloudflare Tunnel overlay — expose the service publicly without opening a port or maintaining a TLS cert
- Defense-grade observability: OpenTelemetry traces, slog structured logs, `/healthz` liveness, graceful shutdown with load-balancer drain delay

## Quick Start

```bash
just init       # generates .env, .env.development, randomised ports, operator token
just dev-up     # launches nginx + Vite HMR + Go (Air hot-reload) + Postgres + Redis + Jaeger
```

Open the URL printed by `just init` (typically `http://localhost:22784`). Mint a token, watch the manage page, then trigger it from another tab and refresh.
or the live demo at [iglowinthedark.com](https://iglowinthedark.com/)

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` to see every available recipe grouped by area.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## Token Types

| Type | Artifact | Trigger Mechanism | Where You'd Plant It |
|------|----------|-------------------|----------------------|
| `webbug` | URL to a 1x1 JPEG | Any HTTP GET on the URL | HTML emails, internal wikis, "do-not-touch" docs |
| `slowredirect` | URL with a delayed redirect | Click-through; runs fingerprint JS before redirecting to a real destination | Phishing-bait links in honeyfile chat threads, fake admin panel URLs |
| `pdf` | Patched PDF | Acrobat opens, fires `/AA /O /URI` page-open action | `payroll-q3.pdf` on a shared drive, `vpn-creds.pdf` on a workstation |
| `docx` | Patched Word doc | Word/LibreOffice loads the footer, which contains a remote URI | `customer-list.docx`, `passwords.docx` in `Documents/` |
| `envfile` | Plain-text `.env` | Attacker `curl`s the fake `INTERNAL_METRICS_ENDPOINT` baked into the file | Repository roots, `~/.config/`, container `/app/` directories |
| `kubeconfig` | YAML kubeconfig | Attacker runs `kubectl --kubeconfig=stolen.yaml ...` and our server logs the bearer token | `~/.kube/config`, ops engineer laptops, CI runner home dirs |
| `mysql` | `mysql://...` connection string | Attacker connects with `mysql` CLI; our TCP listener replies with a real MySQL v10 handshake and an `Access denied` packet | `.env` files, `database.yml`, internal wiki snippets |

The `envfile` generator is the densest of the bunch. It picks recipes from `aws.go`, `db.go`, `github.go`, and `stripe.go`, shuffles the resulting sections, and buries a single canary line (`INTERNAL_METRICS_ENDPOINT=https://your-host/c/{tokenID}`) among plausible production config. The attacker harvesting the file gets a fistful of fake secrets to chase *and* trips the wire as soon as one of those secrets is touched.

## HTTP API

Token creation, manage view, and admin are mounted under `/api/`. Trigger routes live at the root so artifacts can carry short URLs.

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `POST` | `/api/tokens` | Turnstile + rate limit | Mint a new token (`type`, `memo`, `alert_channel`, channel config, type-specific metadata) |
| `GET` | `/api/tokens/types` | Public | List available token types and their metadata schemas |
| `GET` | `/api/m/{manageId}` | Manage UUID | Token details + paginated event feed + dedup silence counter |
| `DELETE` | `/api/m/{manageId}` | Manage UUID | Soft-disable the token (events stop, history retained) |
| `GET` | `/api/admin/stats` | Bearer | Tokens count, events count, breakdowns by type and alert channel |
| `GET` | `/api/admin/tokens` | Bearer | All tokens (offset paginated) |
| `POST` | `/api/admin/tokens/{id}/disable` | Bearer | Force-disable any token |
| `GET` | `/healthz` | Public | Liveness + readiness probe (used by Docker healthchecks) |
| `GET` | `/c/{tokenID}` | Public | **Trigger route.** Records event, fires notification, returns artifact body (pixel, GIF, HTML interstitial, etc.) |
| `POST` | `/c/{tokenID}/fingerprint` | Public | Receives JSON fingerprint payload from the `slowredirect` interstitial |
| `*` | `/k/{tokenID}[/*]` | Public | Kubeconfig trigger — matches `kubectl`'s wildcard API paths |

The MySQL listener does not run on HTTP. It's a separate TCP server bound to a configurable address; an attacker using the connection string from the artifact will speak the MySQL wire protocol with our `protocol.go` handshake builder before getting denied.

## Stack

**Backend:** Go 1.25, chi router, pgx + sqlx, goose migrations, koanf config, slog, validator/v10, OpenTelemetry, pdfcpu, MaxMind GeoLite2, miniredis (tests), testcontainers (integration)

**Frontend:** React 19, TypeScript, Vite, TanStack Query, Zod, Axios, Biome, Stylelint

**Storage:** PostgreSQL 18 (`tokens`, `events` tables; INET + JSONB columns), Redis 7 (dedup gate + rate-limit token buckets)

**Infra:** Docker Compose (dev: nginx + Vite HMR + Air + Postgres + Redis + Jaeger; prod: nginx + Go binary + Postgres + Redis), optional `cloudflared` overlay

## Project Layout

```
canary-token-generator/
├── backend/
│   ├── cmd/canary/                main.go — wiring, signal handling, MySQL listener spawn, retention loop
│   └── internal/
│       ├── token/                 Service, repository, handler, generator interface
│       │   └── generators/
│       │       ├── webbug/        Embedded JPEG pixel
│       │       ├── pixel/         Shared 1x1 GIF helper used by every "visited" response
│       │       ├── pdf/           Byte-exact PDF placeholder substitution (76-byte URL window)
│       │       ├── docx/          ZIP-aware footer rewrite
│       │       ├── envfile/       Recipe shuffler + canary line injection
│       │       │   └── recipes/   aws.go, db.go, github.go, stripe.go
│       │       ├── kubeconfig/    text/template renderer + wildcard /k/ handler
│       │       ├── mysql/         protocol.go (handshake + auth + err packets), server.go (TCP), handler.go
│       │       └── slowredirect/  HTML interstitial + fingerprint POST handler
│       ├── event/                 Event entity, service (geo enrich → insert → dedup → notify), repository
│       ├── notify/                Worker pool, queue, status writer
│       │   ├── webhook/           HMAC-signed POSTs with exponential backoff
│       │   └── telegram/          Bot API client
│       ├── middleware/            request_id, logging, recovery, realip, fingerprint, ratelimit, turnstile, operator_bearer, headers
│       ├── geoip/                 MaxMind MMDB lookup wrapper (nop when no DB present)
│       ├── turnstile/             Cloudflare Turnstile siteverify
│       ├── admin/                 Stats, listing, force-disable
│       ├── core/                  DB pool, Redis client, migrations, telemetry, errors, validation, response envelopes
│       ├── health/                /healthz handler with readiness/shutdown flags
│       └── server/                chi router shell with graceful shutdown + drain delay
├── frontend/
│   └── src/
│       ├── pages/landing/         Token creation form (type-aware metadata, Turnstile widget, artifact reveal)
│       └── pages/manage/          Token detail + event table (cursor paginated, GeoIP cells, dedup silence)
├── infra/
│   ├── nginx/                     prod.nginx, dev.nginx (Vite proxy)
│   └── docker/                    Dockerfiles for prod binary, Air hot-reload, Vite HMR
├── compose.yml                    Production stack
├── dev.compose.yml                Dev stack with Jaeger
├── cloudflared.compose.yml        Tunnel overlay
├── justfile                       Recipes grouped by frontend / backend / lint / compose / tunnel / dev / util
└── learn/                         You are here
```

## Learn

This project includes step-by-step learning materials covering deception theory, token mechanics, system design, and a code walkthrough.

| Module | Topic |
|--------|-------|
| [00 - Overview](learn/00-OVERVIEW.md) | Prerequisites, quick start, project structure |
| [01 - Concepts](learn/01-CONCEPTS.md) | Honeytokens, deception defense, Thinkst Canary, MITRE Engage, real breaches |
| [02 - Architecture](learn/02-ARCHITECTURE.md) | System design, request lifecycle, schema, dedup gate, notification pipeline |
| [03 - Implementation](learn/03-IMPLEMENTATION.md) | Code walkthrough: generators, trigger handler, event service, MySQL protocol |
| [04 - Challenges](learn/04-CHALLENGES.md) | Extension ideas — new token types, alert channels, evasion-resistance |

## License

AGPL 3.0
