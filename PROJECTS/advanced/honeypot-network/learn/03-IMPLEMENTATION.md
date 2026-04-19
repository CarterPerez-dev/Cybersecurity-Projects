# Implementation

## File Structure

The codebase follows standard Go project layout. Public types live in `pkg/types/`, everything else is in `internal/`. Each honeypot service gets its own package named after the Unix daemon convention (sshd, httpd, ftpd, smbd, mysqld, redisd). This avoids conflicts with Go's stdlib packages.

```
internal/
├── sshd/           # SSH (most complex: shell, filesystem, commands, keys)
│   ├── server.go   # Accept loop, auth callbacks, channel handling
│   ├── shell.go    # Interactive terminal with x/term, MOTD, command loop
│   ├── commands.go # 25+ fake command handlers
│   ├── filesystem.go # In-memory /etc/passwd, /proc/cpuinfo, etc.
│   └── hostkey.go  # Ed25519 key generation and persistence
├── httpd/          # HTTP (WordPress/phpMyAdmin fakes, scanner detection)
├── ftpd/           # FTP (PASV mode, upload capture, state machine)
├── smbd/           # SMB (NetBIOS framing, negotiate only)
├── mysqld/         # MySQL (binary wire protocol, greeting, auth, queries)
├── redisd/         # Redis (RESP protocol via tidwall/redcon)
├── event/          # Fan-out pub/sub bus + worker pool processor
├── store/          # PostgreSQL (pgxpool) + Redis streaming
├── mitre/          # ATT&CK technique index + sliding window detector
├── intel/          # IOC extraction, SSH/HTTP fingerprinting, STIX, blocklists
├── api/            # Chi REST router + WebSocket handler
├── config/         # YAML + env loading, all constants
├── session/        # Thread-safe tracker + asciicast v2 recorder
├── geo/            # MaxMind GeoIP lookup
├── ratelimit/      # Per-IP token bucket
└── ui/             # Terminal banner, colors, spinner, symbols
```

## Building the SSH Honeypot

The SSH service is the flagship. It creates an `ssh.ServerConfig` with callbacks that accept any password or public key, then listens for connections.

When a client connects, the server completes the SSH handshake and handles channel requests. The `handleSession` function creates an `x/term.Terminal` with a realistic prompt, writes an Ubuntu MOTD banner, and enters a read-eval-print loop.

Each command typed by the attacker is dispatched through `DispatchCommand` in commands.go. This function pattern-matches on the command name and delegates to specific handlers. The `ls` command reads from the in-memory `FakeFS`, which contains realistic files like `/etc/passwd` with plausible user entries, `/proc/cpuinfo` with Intel CPU info, and `/etc/ssh/sshd_config`.

The entire session (every byte of terminal I/O) is recorded using the `session.Recorder`, which writes asciicast v2 format. This format uses newline-delimited JSON: a header line with terminal dimensions, followed by event lines with `[timestamp, "o", "output data"]` tuples. The dashboard replays these recordings using xterm.js.

## Building the MySQL Honeypot

MySQL uses a binary wire protocol. Every packet has a 4-byte header: 3 bytes for payload length (little-endian) and 1 byte for sequence number.

The server sends a Greeting packet when a client connects. This packet includes the protocol version (10), server version string ("5.7.42-0ubuntu0.18.04.1"), a connection ID, and a 20-byte authentication salt split into two parts. The greeting format must be exact. MySQL clients check specific byte offsets and will reject connections with malformed greetings.

After the greeting, the client sends an authentication packet containing the username and a password hash. The honeypot extracts the username (length-encoded string at a known offset) and publishes a login event. It always responds with an OK packet to let the client in.

In the command phase, the honeypot handles COM_QUERY (0x03) by pattern-matching common queries. `SELECT @@version_comment` returns the version string. `SHOW DATABASES` returns a result set with "information_schema", "mysql", "performance_schema", and "test". The result set encoding uses MySQL's length-encoded integer format and column definition packets, each with correct sequence numbering.

## Building the FTP Honeypot

FTP is text-based, which makes it simpler than MySQL but introduces state management. An FTP session is a state machine: the client starts in an unauthenticated state, sends USER and PASS to authenticate, then issues commands.

The `ftpConn` struct tracks three states (init, user-provided, authenticated). The USER command stores the username and advances state. The PASS command publishes a credential event and advances to authenticated. After authentication, the client can issue PWD, CWD, LIST, STOR, and other commands.

PASV mode is the interesting part. The client sends PASV, and the server opens a new TCP listener on a random port, then tells the client the IP and port in a specific format: `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)`. The client connects to this data channel for file transfers.

For file uploads (STOR), the honeypot accepts up to 1MB of data on the data channel and publishes a file upload event with the content. This captures malware samples that attackers try to upload via FTP.

## MITRE Detection Engine

The detector in `mitre/detector.go` combines two detection strategies.

Single-event rules fire immediately when a matching event arrives. A command event triggers pattern matching against known command categories. The patterns are checked against the uppercased command string, so `wget http://...` matches the "WGET " pattern in `isToolTransfer()`, mapping to T1105.

Multi-event rules maintain per-IP state. The `ipState` struct has two fields: `authHits` (a slice of timestamps) and `services` (a map of service types to their last-seen time). On each authentication event, the timestamp is appended to `authHits`, old entries outside the 5-minute window are pruned, and if 5 or more remain, T1110 (Brute Force) is detected. On each connection event, the service type is recorded, and if 3 or more distinct services have been contacted within 60 seconds, T1046 (Network Service Discovery) is detected.

The detector uses a mutex to protect the per-IP state map, since events from different services arrive on different goroutines.

`Detect` returns `[]*types.MITREDetection` rather than plain technique ID strings. Each object is fully populated: session ID, technique ID, tactic resolved from the embedded index (`reconnaissance`, `credential-access`, `execution`, etc.), confidence (100 for all rule matches), source IP, service type, the triggering event type as evidence, and detection timestamp. The processor uses these objects two ways: technique IDs are appended to the event's `Tags` slice so they survive in the event record for filtering, and each detection is persisted to the `mitre_detections` table via `InsertDetection` so the MITRE heatmap has real data to render.

## STIX Export

The `intel/stix.go` file generates STIX 2.1 bundles as JSON. A bundle contains an Identity SDO (representing the honeypot system) and one Indicator SDO per IOC.

Each indicator includes a STIX pattern expression. For IPv4 addresses, the pattern is `[ipv4-addr:value = '1.2.3.4']`. For file hashes, it is `[file:hashes.'SHA-256' = 'abc...']`. For user-agents, the pattern navigates to `[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '...']`.

UUIDs are generated using UUID v4 via `uuid.New()` from the google/uuid library. Each object gets a type prefix: `identity--uuid`, `indicator--uuid`, `bundle--uuid`. UUID v4 is the correct choice here: STIX 2.1 (Section 2.9) specifies that random identifiers must use UUIDv4 and deterministic identifiers must use UUIDv5. UUID v7 (time-ordered) is not a permitted STIX identifier format and would cause ingestion failures in strict platforms like OpenCTI.

## Event Bus Internals

The bus uses Go's `sync.RWMutex` for subscriber management. Publishing takes a read lock (allowing concurrent publishes), while subscribing takes a write lock. The publish path iterates over all subscribers, checks if the subscriber's topic set includes the event's topic or the wildcard "all" topic, and sends to the channel with a non-blocking select.

```go
select {
case sub.ch <- ev:
default:
}
```

The `default` case means if the channel is full, the event is silently dropped for that subscriber. This is the key design decision: producers are never blocked by slow consumers.

## Session Tracking

The `session.Tracker` is a thread-safe in-memory map from session ID to `types.Session`. It uses an `RWMutex` with read locks for lookups and write locks for mutations.

Persistence is wired through two callbacks registered at startup in `serve.go`. `SetOnStart` fires when `Start()` creates a new session — the serve command wires this to `pgStore.InsertSession`, writing the initial record (IP, port, service type, start time) to PostgreSQL before the attacker has even authenticated. `SetOnEnd` fires when `End()` removes the session — wired to `pgStore.UpdateSession`, which flushes the final state: command count, MITRE techniques, threat score, username, and end timestamp.

During a session, services call `IncrCommandCount()`, `SetLogin()`, and `AddTechnique()` to accumulate state in the in-memory struct. When the connection closes, `End()` removes it from the map and fires `onEnd` with the mutex already released, so the database write never blocks other sessions from starting or ending concurrently.

The tracker's `Active()` method returns a snapshot of all in-progress sessions, used by the dashboard's "active sessions" counter.

## Rate Limiting

The per-IP rate limiter uses `golang.org/x/time/rate.Limiter` (token bucket algorithm). Each IP gets its own limiter, created on first connection. A background goroutine runs every 10 minutes and removes limiters for IPs that have not been seen recently, preventing memory growth.

The rate limiter protects the honeypot from resource exhaustion. An attacker sending 10,000 connections per second would generate 10,000 events, each requiring GeoIP lookup, MITRE detection, and database insert. The limiter caps this at 10 events per second per IP.

## Frontend Architecture

The React frontend uses a layered architecture:

**Core layer**: Axios HTTP client with a response interceptor that normalizes errors into typed `ApiError` objects. React Router v7 browser router. A Zustand WebSocket store that maintains a buffer of the 200 most recent live events and a running total event counter. The WebSocket store implements exponential backoff reconnection starting at 1 second and capping at 30 seconds, so the dashboard recovers automatically from backend restarts without a page refresh.

**API layer**: TypeScript type definitions mirroring Go types, and TanStack Query v5 hooks for each endpoint. Hooks use named query strategies defined in `config.ts`: `live` (10s stale, 10s refetch) for the event feed, `dashboard` (15s) for overview stats, `slow` (60s) for country and credential aggregates, and `static` (infinite stale, no refetch) for the MITRE technique catalog. Query and mutation errors are surfaced automatically through Sonner toast notifications wired into the TanStack Query cache error handlers, so API failures always reach the user without per-hook error handling.

**Component layer**: Reusable UI components (StatCard, ServiceBadge, EventFeed, AttackMap, SessionPlayer) that compose into pages. The AttackMap uses react-leaflet. The SessionPlayer uses xterm.js to replay asciicast v2 recordings with play/pause/speed controls.

**Page layer**: Six pages (Dashboard, Events, Sessions, Attackers, MITRE, Intel) that combine components with data from hooks.

**Tooling**: Biome handles both linting and formatting (replacing ESLint + Prettier with a single config). Zod v4 validates API response shapes at the boundary. SCSS modules with OKLCH color tokens (`_tokens.scss`) provide the design system — OKLCH gives perceptually uniform color manipulation for the threat severity palette.

## Build and Deploy

Development:
```bash
just dev-up          # Start all services via Docker Compose
just dev-serve       # Run backend locally (needs Postgres + Redis)
cd frontend && pnpm dev  # Start Vite dev server with proxy
```

Production:
```bash
just up -d           # Multi-stage Docker build + nginx reverse proxy
```

The production build compiles the Go binary with `CGO_ENABLED=0` into a `scratch` container (no OS, just the binary), and builds the React app into static files served by nginx. The nginx config proxies `/api/*` to the backend and `/ws/*` with WebSocket upgrade headers.
