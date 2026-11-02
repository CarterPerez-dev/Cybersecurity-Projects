<!-- © AngelaMos | 2026 | 00-OVERVIEW.md -->

# C2 Beacon / Server

## What This Is

This is an educational Command and Control (C2) beacon and server built to demonstrate how real C2 frameworks like Cobalt Strike, Sliver, and Mythic operate under the hood. The beacon implant connects to the server over WebSocket, with traffic encoded using XOR and Base64. There are 10 commands mapped to MITRE ATT&CK techniques, a task queueing system, and a real-time operator dashboard where you can select beacons and issue commands through a terminal-style UI.

## Why This Matters

Cobalt Strike is referenced in nearly 70% of incident response engagements. It is, by a wide margin, the most commonly encountered C2 framework in real breaches. When defenders find Cobalt Strike beacons on a network, they need to understand how the beacon communicates, how tasks are queued, and how the operator controls the implant. Without that understanding, incident response is mostly guesswork.

The SolarWinds SUNBURST attack in 2020 used a custom C2 protocol tunneled over HTTP, with the implant disguised as a legitimate Orion software update. The beacon would collect system info, sleep for up to two weeks before making its first callback, and then receive tasking through DNS and HTTP responses crafted to look like normal telemetry. The sophistication was in the protocol design, not in the exploit itself.

APT29 (Cozy Bear) has been documented using custom C2 implants with jittered sleep intervals, domain fronting, and encrypted channels that blend into normal HTTPS traffic. The jitter makes network-based detection harder because the callback pattern looks irregular rather than mechanical. This project implements jittered sleep for the same reason, so you can see exactly how that technique works and why a fixed-interval beacon is trivial to fingerprint.

If you work on a blue team, in incident response, or in threat intelligence, understanding C2 architecture is foundational. You cannot write detection rules for something you do not understand. Building one from scratch, even a simplified educational version, gives you a mental model that reading reports alone does not.

## What You'll Learn

**Security Concepts:** C2 architecture and the beacon/server model. MITRE ATT&CK technique mapping (T1059 Command Execution, T1082 System Discovery, T1057 Process Discovery, T1105 Ingress Tool Transfer, T1113 Screen Capture, T1056 Input Capture, T1053 Persistence, T1029 Scheduled Transfer). Protocol encoding with XOR and Base64. Persistence techniques via cron. Detection strategies and how defenders spot C2 traffic.

**Technical Skills:** WebSocket programming on both sides of the connection. Async Python with asyncio, including subprocess execution and concurrent task handling. React with real time UI updates, Zustand state management, and Zod schema validation. Docker Compose orchestration with Nginx reverse proxy, health checks, and multi-service networking.

**Tools:** FastAPI for the server, aiosqlite for the database, psutil for system enumeration, websockets for the beacon transport layer, Vite for the frontend build, Zod for runtime type validation, and Pydantic for backend data modeling.

## Prerequisites

### Required

- Python 3.13+
- Node.js 22+
- Docker and Docker Compose
- Basic understanding of networking, HTTP, and how client-server communication works

### Required Tools

- **uv** for Python package management (never pip). Install: `curl -LsSf https://astral.sh/uv/install.sh | sh`
- **pnpm** for Node package management (never npm). Install: `corepack enable && corepack prepare pnpm@10.29.1 --activate`
- **just** as a command runner. Install: `cargo install just` or `brew install just`
- **Docker Compose** (comes with Docker Desktop, or install the plugin separately)

### Helpful But Not Required

- Familiarity with WebSockets and the connect/send/receive/close lifecycle
- Experience with async/await in Python or JavaScript
- Prior exposure to React (the dashboard is straightforward, but React knowledge helps)

## Quick Start

```bash
git clone https://github.com/CarterPerez-dev/Cybersecurity-Projects.git
cd PROJECTS/beginner/c2-beacon
docker compose -f dev.compose.yml up -d
```

Visit http://localhost:47430 in your browser. You should see the operator dashboard with an empty beacon table.

In a second terminal, start a beacon:

```bash
cd PROJECTS/beginner/c2-beacon
just beacon
```

You should see output like this from the beacon:

```
2026-02-14 10:32:01 INFO: Connecting to ws://localhost:47430/api/ws/beacon
2026-02-14 10:32:01 INFO: Registered as 3a7f1c29-8b42-4e91-a6d3-9f0e5c8d2b17
```

Back in the browser, the beacon appears in the dashboard table with its hostname, OS, username, and IP. Click the row to open a session. Type `shell whoami` in the terminal input and press Enter. The command is sent to the beacon, executed, and the output appears in the terminal UI.

Try a few more:

```
sysinfo
proclist
shell ls -la /tmp
```

Each command goes through the full pipeline: operator dashboard sends JSON over WebSocket to the server, server queues a task and forwards it (XOR+Base64 encoded) to the beacon, beacon executes the command, encodes the result, sends it back, and the server broadcasts it to the operator dashboard.

## Project Structure

```
c2-beacon/
├── backend/
│   └── app/
│       ├── core/
│       │   ├── encoding.py      XOR + Base64 encode/decode functions
│       │   ├── models.py        Pydantic models: BeaconRecord, TaskRecord, TaskResult
│       │   └── protocol.py      Message envelope: pack/unpack with type validation
│       ├── beacon/
│       │   ├── registry.py      In-memory beacon registry with aiosqlite persistence
│       │   ├── router.py        WebSocket endpoint for beacon connections
│       │   └── tasking.py       Task queue: create, assign, complete, retrieve
│       ├── ops/
│       │   ├── manager.py       Operator WebSocket connection manager + broadcasting
│       │   └── router.py        Operator WebSocket + REST endpoints
│       ├── config.py            Pydantic Settings: XOR key, ports, CORS, DB path
│       └── database.py          aiosqlite setup with table creation
├── beacon/
│   └── beacon.py                The implant (~514 lines, single file, 10 command handlers)
├── frontend/
│   └── src/
│       ├── core/
│       │   ├── ws.ts            Zustand store + useOperatorSocket hook
│       │   └── types.ts         Zod schemas for all WebSocket message types
│       └── pages/
│           ├── dashboard/       Beacon table with real-time status updates
│           └── session/         Terminal UI with command input and result display
├── infra/
│   ├── docker/                  Dockerfiles for dev (hot reload) and prod
│   └── nginx/                   Reverse proxy configs (WebSocket proxying)
├── dev.compose.yml              3-service dev stack: nginx, backend, frontend
├── compose.yml                  Production compose
├── justfile                     Command runner: just beacon, just dev-up, etc.
└── learn/                       You are here
```

## How It Works (Brief)

```
┌──────────┐    WebSocket     ┌──────────┐    WebSocket     ┌──────────┐
│  Beacon  │ ──XOR+Base64──>  │  Server  │ <──JSON────────  │ Operator │
│ (target) │ <──XOR+Base64──  │ (FastAPI)│ ──JSON────────>  │ (React)  │
└──────────┘                  └──────────┘                  └──────────┘
```

The beacon implant (`beacon/beacon.py`) connects to the server via WebSocket at `/ws/beacon`. On connect, it sends a REGISTER message containing system info: hostname, OS, username, PID, internal IP, and architecture. The server stores this in the beacon registry (in-memory dict backed by aiosqlite) and broadcasts a `beacon_connected` event to all connected operators.

The beacon then enters a loop. It sends periodic HEARTBEAT messages with jittered timing (base interval + random jitter percentage), which keeps the connection alive and updates the "last seen" timestamp on the server. Between heartbeats, it waits for TASK messages from the server.

On the operator side, the React dashboard connects via a separate WebSocket at `/ws/operator`. When you type a command in the session terminal, the frontend sends a JSON message to the server. The server creates a TaskRecord, queues it, and forwards the task to the target beacon as an XOR+Base64 encoded TASK message.

The beacon receives the task, dispatches it to the appropriate handler (shell, sysinfo, proclist, etc.), and sends back a RESULT message with the output. The server stores the result, marks the task as completed, and broadcasts it to the operator dashboard, which renders it in the terminal UI.

Two separate WebSocket channels keep concerns separated. The beacon channel uses XOR+Base64 encoding (simulating encrypted C2 comms). The operator channel uses plain JSON (trusted internal communication).

## Next Steps

- [01 - Concepts](01-CONCEPTS.md): C2 theory, MITRE ATT&CK mapping for each command, and how defenders detect beacons
- [02 - Architecture](02-ARCHITECTURE.md): Protocol design, data flow, encoding decisions, and why things are built this way
- [03 - Implementation](03-IMPLEMENTATION.md): Code walkthrough of every component, from the beacon implant to the React dashboard
- [04 - Challenges](04-CHALLENGES.md): Extensions and harder exercises (AES encryption, DNS tunneling, evasion techniques)

## Common Issues

**"WebSocket closed before established" in browser console:** This is React StrictMode doing a double-mount in development. The first WebSocket connects and immediately disconnects, then the second one connects and stays. Harmless. You will see it every time you reload the page in dev mode.

**Beacon cannot connect to the server:** Make sure the Docker containers are actually running. Run `just dev-ps` to check. The beacon connects through Nginx on port 47430, so all three services (nginx, backend, frontend) need to be healthy. If the backend shows as unhealthy, check its logs with `just dev-logs backend`.

**"No beacons connected" on the dashboard:** You need to run the beacon implant separately. It does not start automatically with Docker. Open a second terminal and run `just beacon`. The beacon should register within a few seconds and appear in the dashboard table.

**Commands return empty output:** Some commands require specific conditions. `screenshot` needs a display server (will fail in headless environments or Docker containers). `keylog_start` needs pynput, which requires an X11 or Wayland session. `persist` only works on Linux. The `shell` command works everywhere.
