<!-- © AngelaMos | 2026 | 00-OVERVIEW.md -->

# Canary Token Generator

## What This Is

A self-hosted honeytoken service. You mint a token through the web UI, drop the resulting artifact somewhere an attacker is likely to find it, and then sit back. The moment the artifact is opened, fetched, or used, the server records the event with IP, GeoIP, user agent, and (for some token types) a browser fingerprint — then fires a Telegram message or webhook to alert you.

It is the open-source spiritual cousin of Thinkst Canary and the Canarytokens.org service. Seven token types ship in the box: an invisible web bug, a slow-redirect link that captures a fingerprint before forwarding the victim onward, booby-trapped PDF and DOCX files, fake `.env` and kubeconfig credentials, and a real MySQL listener that completes the v10 handshake so an attacker's `mysql` CLI shows a plausible "Access denied" error while we log the bearer token they tried.

The backend is Go on chi, with PostgreSQL for tokens and events, Redis for dedup and rate limiting, MaxMind GeoLite2 for IP geolocation, and an async worker pool for outbound notifications. The frontend is React 19 with TanStack Query.

## Why This Matters

Mean time to detection for a breach is, depending on whose annual report you read, somewhere between two and eight *months*. The reason is straightforward: defenders watch the obvious signal sources — failed logins, IDS alerts, EDR telemetry — and skilled attackers know to stay out of those. By the time anyone notices, the attacker has been moving laterally for a long time.

Deception flips the asymmetry. A canary token has zero false-positive rate by construction. No legitimate user will ever connect to a database whose connection string only exists in a planted `.env` file. No real employee will open a PDF named `network-diagram-DO-NOT-SHARE.pdf` that nobody told them about. So when one of those events fires, you don't argue with it — you start the incident response clock and you already know the attacker is past your first-line controls.

This is not theoretical. The most famous canary-driven detection is probably the 2013 Target breach analysis, where investigators reconstructed the attacker's movement through credentialed pivots that would have been visible to honeytokens in those service accounts. More recently, MITRE published the Engage framework — a deliberate counterpart to ATT&CK that catalogues deception techniques and how defenders deploy them in real environments.

If you work on a blue team, this project shows you exactly how the primitives work: how a PDF can be patched byte-exact without breaking it, why the MySQL wire protocol is forgiving enough to fake, how dedup gates prevent a noisy attacker from drowning your alert channel, and how to enrich events with GeoIP and fingerprint data so the triage call goes faster.

## What You'll Learn

**Security Concepts:** Deception-based defense. Honeytoken mechanics across multiple file formats. The MITRE Engage framework and how it complements ATT&CK. Browser fingerprinting (the same technique advertisers use, but pointed at adversaries). Operational security for the canary infrastructure itself — why constant-time bearer comparison matters, why the trigger route returns the artifact body even when the token is invalid (enumeration resistance), and why dedup runs against `{token, source_ip}` rather than just `source_ip`. Detection patterns from real breach reports.

**Technical Skills:** Idiomatic Go service design — domain layout (`token/`, `event/`, `notify/`), generator interface with seven implementations, repository pattern over pgx/sqlx, slog for structured logging, koanf for layered config, goose for migrations, chi for routing. Async worker pools with bounded queues. Redis as a coordination primitive (atomic SETNX-based dedup, token-bucket rate limiting via `go-redis/redis_rate`). MySQL wire-protocol implementation from the spec. PDF byte-exact patching that preserves cross-reference offsets. DOCX manipulation as a ZIP archive. React 19 with TanStack Query, Zod, and a TypeScript-strict build. Docker Compose multi-service orchestration with health checks, drain delays, and a Cloudflare Tunnel overlay for zero-port-exposure deployments.

**Tools:** chi (router), pgx + sqlx (Postgres), goose (migrations), koanf (config), slog (logging), validator/v10 (request validation), pdfcpu (PDF parsing for the build-template command), MaxMind GeoLite2 (IP geolocation), Cloudflare Turnstile (bot mitigation on token creation), Cloudflare Tunnel (publication), miniredis + testcontainers (tests), OpenTelemetry + Jaeger (tracing), TanStack Query + Zod + Vite (frontend), Biome + Stylelint (frontend linting), Air (Go hot reload in dev).

## Prerequisites

### Required

- Go 1.25+
- Node.js 22+
- Docker and Docker Compose
- A passing familiarity with HTTP, TCP, and the request/response lifecycle

### Required Tools

- **just** as a command runner. Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`
- **pnpm** for Node package management (never npm). Install: `corepack enable && corepack prepare pnpm@10.29.1 --activate`
- **Docker Compose** (bundled with Docker Desktop or installed as a plugin)

### Optional But Useful

- A Telegram bot token + chat ID, or a webhook receiver (e.g. https://webhook.site), so you can see alerts arrive on a real channel
- A free MaxMind GeoLite2 account to download the City database — without it, events still record but the `geo_*` columns stay null
- A Cloudflare Turnstile site key + secret if you want to test the bot-mitigation flow on `POST /api/tokens`
- A Cloudflare Tunnel token if you want to expose your local instance to the public internet through `just tunnel-up`

## Quick Start

```bash
git clone https://github.com/CarterPerez-dev/Cybersecurity-Projects.git
cd Cybersecurity-Projects/PROJECTS/beginner/canary-token-generator
just init        # generates .env + .env.development, picks free random ports, writes an operator token
just dev-up      # nginx → Vite + Air-reloaded Go → Postgres → Redis → Jaeger
```

`just init` prints the URL it picked. Typically that's `http://localhost:22784`, but it will pick a different port if 22784 is taken.

Visit that URL. You'll land on the token creation form. Pick `Web Bug` from the dropdown, type "test token" in the memo, choose webhook as the alert channel, paste a https://webhook.site URL, then submit. The page renders the trigger URL and a manage URL.

Open the manage URL in a second tab. Open the trigger URL in a third tab — you should see a tiny broken-image placeholder (the 1x1 JPEG, which the browser does fetch but doesn't render meaningfully). Refresh the manage tab. The event table now has one row: your local IP, your user-agent, an empty GeoIP cell (you're on localhost), and a `pending` notify status that flips to `sent` once the webhook fires.

Check webhook.site. You should see a POST with the token ID, event ID, timestamp, source IP, user agent, and an HMAC-SHA256 signature in the `X-Canary-Signature` header.

Try the other token types from the dropdown. The `.env` and kubeconfig artifacts arrive as downloadable files. The PDF and DOCX arrive as base64-encoded content the UI converts to file downloads. The `slowredirect` token asks you for a destination URL; trigger it in another tab and you'll watch a 3-second interstitial run a fingerprinting script before redirecting you. Open the manage tab afterward — the event row now has a fingerprint JSON blob attached.

## Project Structure

```
canary-token-generator/
├── backend/
│   ├── cmd/canary/main.go            Wiring: config → DB → Redis → GeoIP → notify worker pool → router → MySQL listener → retention loop
│   ├── cmd/buildpdftemplate/         One-shot tool: bakes the PDF placeholder into template.pdf
│   ├── cmd/builddocxtemplate/        One-shot tool: bakes the DOCX placeholder into the footer
│   ├── cmd/healthcheck/              Tiny Docker HEALTHCHECK binary (no curl needed in the image)
│   └── internal/
│       ├── token/
│       │   ├── entity.go             Token domain type + NotifyInfo + Manage view
│       │   ├── repository.go         pgx/sqlx-backed CRUD
│       │   ├── service.go            Generate → persist → return artifact
│       │   ├── handler.go            POST /api/tokens, GET/DELETE /api/m/{manageId}, GET /c/{id} trigger
│       │   ├── types.go              Type constants (webbug, pdf, ...)
│       │   ├── dto.go                Create/Manage request/response shapes + validation tags
│       │   ├── contract.go           Interfaces for repository, generator registry, event recorder
│       │   └── generators/
│       │       ├── generator.go      Generator interface + Artifact + TriggerResponse types
│       │       ├── registry/         Map of Type → Generator
│       │       ├── webbug/           Embedded JPEG pixel
│       │       ├── pixel/            Shared 1x1 GIF helper for "visited" responses
│       │       ├── pdf/              Byte-exact placeholder substitution against embedded template.pdf
│       │       ├── docx/             ZIP rewrite of word/footer2.xml
│       │       ├── envfile/          Recipe shuffler + canary line injection
│       │       │   └── recipes/      aws.go, db.go, github.go, stripe.go — produce realistic fake secrets
│       │       ├── kubeconfig/       text/template render + wildcard /k/ handler
│       │       ├── mysql/            protocol.go (handshake/auth/err), server.go (TCP), handler.go, generator.go
│       │       └── slowredirect/     HTML interstitial + POST /c/{id}/fingerprint handler
│       ├── event/                    Event entity, service, repository, contract
│       ├── notify/                   Async worker pool (queue + dispatcher), status writer
│       │   ├── webhook/              HMAC-signed POST with exponential backoff
│       │   └── telegram/             Bot sendMessage client
│       ├── middleware/               request_id, logging, recovery, realip, fingerprint, ratelimit, turnstile, operator_bearer, headers
│       ├── geoip/                    MaxMind MMDB lookup (nop service when no DB)
│       ├── turnstile/                Cloudflare siteverify
│       ├── admin/                    Stats, listing, force-disable
│       ├── core/                     DB pool, Redis client, migrations driver, telemetry init, errors, response envelopes
│       ├── health/                   Liveness + readiness flags
│       └── server/                   chi router shell with drain delay + graceful shutdown
├── frontend/src/
│   ├── api/                          Axios client, hooks, types (Zod schemas)
│   ├── pages/landing/                Token creation form, type-aware metadata, Turnstile widget, artifact reveal
│   └── pages/manage/                 Token detail + event feed (cursor paginated, GeoIP, dedup silence count)
├── infra/
│   ├── nginx/                        prod.nginx, dev.nginx (Vite HMR proxy)
│   └── docker/                       Dockerfiles for prod binary, Air dev, Vite dev
├── compose.yml                       Production stack
├── dev.compose.yml                   Dev stack with Jaeger
├── cloudflared.compose.yml           Tunnel overlay
├── justfile                          Recipes grouped by frontend / backend / lint / compose / tunnel / dev / util
└── learn/                            You are here
```

## How It Works (Brief)

```
                       ┌──────────────────────────────┐
                       │  Operator (browser)          │
                       │  React 19 + TanStack Query   │
                       └──────────────┬───────────────┘
                                      │
                              POST /api/tokens
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────┐
│  nginx → chi router (Go)                                        │
│  Middleware chain:                                              │
│    request_id → logger → recovery → SecurityHeaders → CORS →    │
│    fingerprint-keyed rate limit → Turnstile → handler           │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                  token.Service.Create()
                               │
              ┌────────────────┼─────────────────┐
              ▼                ▼                 ▼
       generator.Generate   repo.Insert     return Artifact
       (webbug | pdf |     (Postgres)       (URL | file |
        docx | envfile |                     connection string)
        kubeconfig |
        slowredirect |
        mysql)

                          --- attacker opens artifact ---

         ┌──────────────────────────────────────────────┐
         │  GET /c/{tokenID}   (or TCP for mysql)       │
         └──────────────────────┬───────────────────────┘
                                │
                  token.Handler.HandleTrigger
                                │
                  generator.Trigger(token, request)
                                │
                  event.Service.Record(notifyInfo, evt)
                                │
              ┌─────────────────┼─────────────────┐
              ▼                 ▼                 ▼
         geo.Lookup(IP)   repo.Insert(evt)   Redis SETNX
         (GeoLite2)       (Postgres)         dedup:{id}:{ip}
                                │                  │
                                │       ┌──────────┴────────┐
                                │       ▼                   ▼
                                │   first hit?          duplicate?
                                │       │                   │
                                │   notify.Notify       UpdateNotifyStatus
                                │       │               (deduped)
                                │       ▼
                                │   worker pool (8) → telegram | webhook
                                │       │
                                ▼       ▼
                          UpdateNotifyStatus(sent | failed)
```

The flow is deliberately small. The trigger handler does almost no work synchronously — it records the event and hands off to the notification worker pool. That asymmetry matters: a curious attacker auto-fetching the URL from a thousand processes won't slow the response and won't crash the alert path either, because the worker queue is bounded and drops with a `failed` status instead of blocking ingestion.

## Next Steps

- [01 - Concepts](01-CONCEPTS.md): The honeytoken idea, Thinkst Canary's commercial product, the MITRE Engage framework, real breaches that honeytokens caught (and ones they would have)
- [02 - Architecture](02-ARCHITECTURE.md): Schema, request lifecycle, the dedup gate, the notification pipeline, enumeration resistance, why MySQL gets its own listener
- [03 - Implementation](03-IMPLEMENTATION.md): Walkthroughs of the generators (PDF byte-exact substitution, DOCX ZIP rewrite, MySQL v10 handshake), the trigger handler, the event service, and the worker pool
- [04 - Challenges](04-CHALLENGES.md): New token types (DNS, SMTP, AWS-API), new alert channels (Slack, PagerDuty), evasion-resistance hardening

## Common Issues

**`just init` says "no free port found":** The init script tries ranges and gives up if everything is in use. Edit `scripts/init.sh` to widen the range, or pass `NGINX_HOST_PORT=...` explicitly in `.env`.

**The Vite dev server logs `optimizing dependencies` forever:** First-run Vite cold start. Wait. Subsequent starts are fast.

**Manage page shows empty GeoIP fields for an IP that's clearly not localhost:** You haven't mounted a GeoLite2 City MMDB. Get a free MaxMind license, drop the `.mmdb` in `data/geoip/GeoLite2-City.mmdb`, set `GEOLITE_PATH` in `.env`, and restart.

**Notification never arrives but `notify_status` says `sent`:** The worker succeeded but Telegram/your webhook receiver rejected silently. Inspect the canary logs (`just logs canary`) for the request body — slog logs every send at debug level.

**Notification stuck at `pending` and never moves:** The worker pool is wedged. Most likely cause is a webhook URL that hangs forever; the 30-second per-job timeout should release it. If it doesn't, you're looking at a goroutine leak — file an issue.

**MySQL listener won't bind:** Port 3306 is probably taken by a local MySQL install. Set `MYSQL_FAKE_PORT` to something else in `.env` (the artifact's connection string uses `MYSQL_PUBLIC_HOST:MYSQL_PUBLIC_PORT`, so the public-facing values can differ from the internal listener address — useful when you're behind a port-forwarder).
