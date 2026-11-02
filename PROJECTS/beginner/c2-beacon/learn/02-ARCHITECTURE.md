<!-- © AngelaMos | 2026 | 02-ARCHITECTURE.md -->

# Architecture: How the C2 System Fits Together

This document walks through every component in the C2 beacon project, how they connect, how data flows between them, and why the design decisions were made the way they were. By the end you should be able to trace a command from the operator dashboard all the way down to the beacon executing it on a target machine, and back again.

Estimated reading time: 20-30 minutes.

---

## Table of Contents

1. [High Level Architecture](#high-level-architecture)
2. [Component Breakdown](#component-breakdown)
3. [Data Flow](#data-flow)
4. [Protocol Design](#protocol-design)
5. [Database Schema](#database-schema)
6. [Design Decisions](#design-decisions)
7. [Security Architecture](#security-architecture)
8. [Deployment Architecture](#deployment-architecture)
9. [Key Files Reference](#key-files-reference)

---

## High Level Architecture

Here is the full picture of every moving part and how they talk to each other:

```
┌─────────────────────────────────────────────────────────────┐
│                        Docker Network                        │
│                                                              │
│  ┌──────────┐     ┌──────────┐     ┌──────────┐            │
│  │  Nginx   │────>│ Backend  │     │ Frontend │            │
│  │  :47430  │     │  :8000   │     │  :5173   │            │
│  └──────────┘     └──────────┘     └──────────┘            │
│       │                │                                     │
│       │           ┌────┴────┐                               │
│       │           │ SQLite  │                               │
│       │           │  (WAL)  │                               │
│       │           └─────────┘                               │
└───────┼─────────────────────────────────────────────────────┘
        │
   ┌────┴────┐
   │ Beacon  │  (runs on target machine, outside Docker)
   └─────────┘
```

Five components, three networks, one protocol. Let's break each one down.

### Nginx (port 47430)

Nginx is the single entry point for everything. Every request, whether from a beacon connecting over WebSocket, an operator viewing the dashboard, or a REST API call, enters through port 47430. Nginx inspects the URL path and routes accordingly:

- `/api/ws/*` goes to the backend WebSocket handlers. This covers both `/api/ws/beacon` (for beacon connections) and `/api/ws/operator` (for operator dashboard connections). Nginx upgrades these to WebSocket connections by setting the `Upgrade` and `Connection` headers.
- `/api/*` (non-WebSocket) goes to the backend REST endpoints. These serve beacon listings, task history, health checks, and the OpenAPI docs.
- Everything else (`/`) goes to the frontend. In development that means proxying to Vite's dev server on port 5173. In production Nginx serves the pre-built static files directly from disk.

The nginx configuration lives in `infra/nginx/dev.nginx` for development and `infra/nginx/prod.nginx` for production. The shared base config at `infra/nginx/nginx.conf` defines upstreams, rate limiting zones, gzip settings, and the WebSocket upgrade map.

One thing worth noticing: the WebSocket locations have `proxy_read_timeout 3600s`. Normal HTTP locations use 30-60 second timeouts. WebSocket connections are long-lived by nature, so nginx needs to know not to kill them after a minute of apparent inactivity.

### Backend (port 8000)

The backend is a FastAPI async application that does three jobs simultaneously:

1. **Beacon management.** It accepts WebSocket connections from beacons, validates their REGISTER messages, tracks them in memory and SQLite, and delivers tasks through per-beacon async queues.
2. **Operator management.** It accepts WebSocket connections from operator dashboards, sends them real-time events (beacon connected, heartbeat, task result), and receives task submission requests.
3. **REST API.** It serves beacon listings and task history for any client that needs them, plus health checks for Docker's container orchestration.

The backend uses FastAPI's `lifespan` context manager to initialize the database, the beacon registry, the task manager, and the operator broadcast manager at startup. All three singletons are attached to `app.state` so every request handler can access them. The app factory pattern in `backend/app/__main__.py` wires everything together: CORS middleware, routers for beacon WebSocket, operator WebSocket, and REST endpoints.

### Frontend (port 5173 dev)

The frontend is a React application built with Vite, TypeScript, and SCSS modules. It connects to the backend through a single WebSocket at `/api/ws/operator` and maintains all state in a Zustand store.

When the dashboard loads, the `useOperatorSocket` hook opens a WebSocket connection. The server immediately sends a `beacon_list` message with every known beacon. From there, the frontend receives real-time events: `beacon_connected`, `beacon_disconnected`, `heartbeat`, `task_result`, and `task_submitted`. The Zustand store in `frontend/src/core/ws.ts` processes each event type and updates the corresponding state slice.

The operator can select a beacon from the dashboard and open a session page, which provides a terminal-like interface for submitting commands. When the operator submits a task, the frontend sends a `submit_task` message over the same WebSocket. The server responds with a `task_submitted` confirmation mapping the local ID to the server-generated task ID, and later broadcasts the `task_result` when the beacon reports back.

### SQLite (WAL mode)

The database is a single SQLite file at `backend/data/c2.db`. It stores three tables: `beacons`, `tasks`, and `task_results`. The backend initializes the schema on startup in `backend/app/database.py` and enables WAL (Write-Ahead Logging) mode with `PRAGMA journal_mode=WAL`.

WAL mode is important here because the backend has concurrent reads happening. While one coroutine is writing a task result, another might be reading the beacon list for an operator query. WAL allows readers and writers to operate simultaneously without blocking each other. In the default rollback journal mode, a write would lock the entire database and block all reads until the write commits.

The `get_db()` async context manager yields a fresh `aiosqlite` connection each time, with `row_factory` set to `aiosqlite.Row` so query results come back as dict-like objects instead of plain tuples. Foreign keys are enabled on every connection.

### Beacon (runs on target)

The beacon is a standalone Python script at `beacon/beacon.py` that runs outside the Docker stack, on whatever machine you point it at. It has its own copy of the XOR encoding functions (deliberately duplicated so the beacon has zero dependencies on the server codebase) and a dispatch table mapping command strings to handler functions.

On startup, the beacon connects to the server via WebSocket, sends a REGISTER message with system metadata (hostname, OS, username, PID, internal IP, architecture), then enters its main loop. It sends periodic heartbeats with jitter applied to the sleep interval, and waits for TASK messages from the server. When a task arrives, the beacon dispatches it to the appropriate handler, collects the output, and sends a RESULT message back.

If the connection drops, the beacon uses exponential backoff (starting at 2 seconds, capping at 5 minutes) to reconnect. This is standard behavior for real-world implants, because hammering a dead server at full speed is a great way to get noticed by network monitoring.

---

## Component Breakdown

### Backend Layers

The backend follows a layered structure that separates protocol concerns from business logic from persistence:

```
backend/app/
├── __main__.py
├── config.py
├── database.py
├── core/
│   ├── encoding.py
│   ├── protocol.py
│   └── models.py
├── beacon/
│   ├── registry.py
│   ├── router.py
│   └── tasking.py
└── ops/
    ├── manager.py
    └── router.py
```

**`__main__.py`** is the application factory. It creates the FastAPI instance, configures CORS, sets up logging, initializes the database schema, and instantiates the three core singletons (BeaconRegistry, TaskManager, OpsManager) during the lifespan startup. The `create_app()` function mounts all routers and defines the health check endpoint. Uvicorn runs this directly via `app.__main__:app`.

**`config.py`** uses Pydantic Settings to load configuration from environment variables and the `.env` file. It defines the XOR key, database path, CORS origins, log level, and server bind options. The `@lru_cache` decorator on `get_settings()` ensures the `.env` file is parsed exactly once.

**`database.py`** owns the SQLite schema definition and provides two functions: `init_db()` for one-time schema creation at startup, and `get_db()` as an async context manager for per-request database connections.

**`core/encoding.py`** implements the XOR-with-repeating-key cipher plus Base64 wrapping. The `encode()` function takes a plaintext string and a key, XORs the UTF-8 bytes against the key bytes (cycling the key), and returns a Base64 ASCII string. The `decode()` function reverses the process. This is symmetric, so the same key works in both directions.

**`core/protocol.py`** defines the `Message` envelope (a Pydantic model with a `type` field and a `payload` dict) and the `MessageType` enum (REGISTER, HEARTBEAT, TASK, RESULT, ERROR). The `pack()` function serializes a Message to JSON and encodes it with XOR+Base64. The `unpack()` function decodes a raw string, parses the JSON, and validates it back into a Message. If any step fails (bad Base64, bad JSON, bad schema), it raises a `ValueError`.

**`core/models.py`** defines the Pydantic data models used across the system: `BeaconMeta` (registration payload), `BeaconRecord` (full database record), `TaskRequest` (operator submission), `TaskRecord` (persisted task), and `TaskResult` (beacon response). It also defines `CommandType` as a StrEnum listing all supported commands: shell, sysinfo, proclist, upload, download, screenshot, keylog_start, keylog_stop, persist, and sleep.

**`beacon/registry.py`** is the `BeaconRegistry` class. It maintains a dict of `beacon_id -> WebSocket` for active connections and provides methods to register, unregister, check active status, update heartbeat timestamps, and query the database for beacon records. When a beacon registers, it upserts to the `beacons` table (INSERT with ON CONFLICT DO UPDATE), so reconnecting beacons update their metadata without creating duplicates.

**`beacon/router.py`** defines the `/ws/beacon` WebSocket endpoint. This is the most complex piece of the backend. When a beacon connects, the handler accepts the WebSocket, waits for a REGISTER message, validates it, registers the beacon, then spawns two concurrent asyncio tasks: `_send_tasks` (which blocks on the beacon's task queue and sends TASK messages) and `_receive_messages` (which processes incoming HEARTBEAT and RESULT messages). The `asyncio.wait` with `FIRST_COMPLETED` pattern ensures that if either coroutine fails (usually because the WebSocket disconnected), the other gets cancelled cleanly.

**`beacon/tasking.py`** is the `TaskManager` class. It maintains a dict of `beacon_id -> asyncio.Queue[TaskRecord]` for per-beacon task delivery. When an operator submits a task, `submit()` writes it to SQLite and puts it on the queue. The `_send_tasks` coroutine in the beacon router calls `get_next()`, which blocks until a task appears. When a result comes back, `store_result()` writes it to the `task_results` table and marks the parent task as completed.

**`ops/manager.py`** is the `OpsManager` class. It tracks a set of operator WebSocket connections and provides a `broadcast()` method that sends a JSON event to all connected operators. If a send fails (connection already closed), the stale WebSocket is removed from the set. This fan-out pattern means every operator sees every event in real time.

**`ops/router.py`** defines two routers: `ws_router` for the `/ws/operator` WebSocket endpoint, and `rest_router` for the REST endpoints (`/beacons`, `/beacons/{id}`, `/beacons/{id}/tasks`). When an operator connects via WebSocket, the handler sends the full beacon list immediately, then enters a receive loop waiting for `submit_task` messages. The REST endpoints provide the same data for non-WebSocket clients or for initial page loads.

---

## Data Flow

### Beacon Registration Flow

Here is what happens from the moment a beacon starts up to when the operator sees it on their dashboard:

```
Beacon                    Server                    Operator Dashboard
  │                         │                              │
  │──REGISTER(sysinfo)────>│                              │
  │                         │──INSERT beacon──> SQLite     │
  │                         │                              │
  │                         │──beacon_connected──────────>│
  │                         │                              │
  │<──(connection held)────│                              │
  │                         │                              │
  │──HEARTBEAT────────────>│                              │
  │                         │──UPDATE last_seen─> SQLite   │
  │                         │──heartbeat────────────────>│
```

Step by step:

1. The beacon opens a WebSocket to `/api/ws/beacon` (which nginx proxies to the backend at `/ws/beacon`).
2. The beacon sends a REGISTER message containing system metadata: hostname, OS, username, PID, internal IP, and architecture. This payload goes through XOR+Base64 encoding before hitting the wire.
3. The server's `beacon_websocket` handler in `beacon/router.py` accepts the connection, unpacks the first message, validates it as a REGISTER type, and extracts the `BeaconMeta` fields.
4. The server calls `registry.register()`, which stores the WebSocket reference in memory and upserts the beacon record into SQLite. If this beacon ID was seen before (a reconnection), the metadata gets updated and `first_seen` is preserved.
5. The server broadcasts a `beacon_connected` event to all operator WebSocket connections via `ops_manager.broadcast()`.
6. The operator dashboard's Zustand store receives the event, calls `upsertBeacon()`, and the dashboard table re-renders with the new beacon showing a green "active" indicator.
7. The server spawns the `_send_tasks` and `_receive_messages` coroutines. The connection is now held open indefinitely.
8. Every few seconds (with jitter), the beacon sends a HEARTBEAT message. The server updates `last_seen` in SQLite and broadcasts the heartbeat to operators, keeping the "last seen" timestamp fresh on the dashboard.

### Task Execution Flow

Here is the full round trip when an operator issues a command:

```
Operator                  Server                    Beacon
  │                         │                         │
  │──submit_task──────────>│                         │
  │                         │──INSERT task──> SQLite  │
  │                         │──queue.put(task)        │
  │<──task_submitted───────│                         │
  │                         │                         │
  │                         │──TASK(XOR+B64)────────>│
  │                         │                         │──execute
  │                         │<──RESULT(XOR+B64)──────│
  │                         │──INSERT result─> SQLite │
  │                         │──UPDATE task status     │
  │<──task_result──────────│                         │
```

Step by step:

1. The operator types a command in the session terminal UI and hits enter. The frontend's `sendTask()` function sends a JSON message over the operator WebSocket: `{"type": "submit_task", "payload": {"beacon_id": "...", "command": "shell", "args": "whoami", "local_id": "..."}}`. This message is plain JSON because the operator-server channel runs entirely within Docker.
2. The server's `operator_websocket` handler in `ops/router.py` receives the message, creates a `TaskRecord` with a UUID, and calls `task_manager.submit()`.
3. `submit()` does two things: it INSERTs the task into the `tasks` table in SQLite (so it persists if the server restarts), and it puts the TaskRecord onto the `asyncio.Queue` for that specific beacon.
4. The server sends a `task_submitted` response back to the operator with the mapping of `local_id` to `task_id`. The frontend uses this to correlate results later.
5. Meanwhile, in `beacon/router.py`, the `_send_tasks` coroutine for this beacon has been blocked on `task_manager.get_next(beacon_id)`. The queue.put() unblocks it. The coroutine packs the task into a Message, encodes it with XOR+Base64, and sends it to the beacon over the WebSocket.
6. The beacon receives the raw text, unpacks it (Base64 decode, XOR decrypt, JSON parse), and dispatches the command to the appropriate handler. For a `shell` command, that means calling `asyncio.create_subprocess_shell()` and capturing stdout/stderr.
7. The beacon packs the result (task_id, output, error) into a RESULT message, encodes it, and sends it back to the server.
8. The server's `_receive_messages` coroutine receives the RESULT, unpacks it, creates a `TaskResult` object, and calls `task_manager.store_result()`. This writes the result to the `task_results` table and updates the parent task's status to `completed`.
9. The server broadcasts a `task_result` event to all operator WebSocket connections.
10. The operator dashboard's Zustand store receives the event, calls `addTaskResult()`, and the session terminal renders the output.

The entire round trip typically takes less than a second on a local network. The bottleneck is usually the command execution on the target machine.

---

## Protocol Design

### Message Types

Every message between the beacon and server follows the same envelope structure: a `type` string and a `payload` dictionary. Here are all five message types:

| Type | Direction | Payload Fields | Purpose |
|------|-----------|----------------|---------|
| REGISTER | Beacon -> Server | hostname, os, username, pid, internal_ip, arch, id | Initial handshake when beacon first connects |
| HEARTBEAT | Beacon -> Server | id | Keep-alive signal, updates last_seen timestamp |
| TASK | Server -> Beacon | id, command, args | Delivers a command for the beacon to execute |
| RESULT | Beacon -> Server | task_id, output, error | Returns command output back to the server |
| ERROR | Either direction | message | Reports a protocol or execution error |

The `Message` model in `backend/app/core/protocol.py` uses a Pydantic `BaseModel` with `type: MessageType` (a StrEnum) and `payload: dict[str, Any]`. The StrEnum means the type field is validated against the known set of message types during unpacking. If a beacon sends a message with `"type": "BOGUS"`, Pydantic's validation catches it and the server raises a ValueError.

### Encoding Pipeline

The beacon-server channel and the operator-server channel use different encoding strategies:

```
                    Beacon <-> Server
JSON string -> UTF-8 bytes -> XOR(key) -> Base64 -> WebSocket text frame

                    Server <-> Operator
JSON string -> WebSocket text frame (no encoding)
```

The beacon-server channel runs XOR+Base64 encoding on every message. The `encode()` function in `backend/app/core/encoding.py` takes a plaintext JSON string, converts it to UTF-8 bytes, XORs each byte against the corresponding byte of the repeating key, and Base64-encodes the result into an ASCII string suitable for a WebSocket text frame. The `decode()` function reverses this: Base64 decode, XOR with the same key, UTF-8 decode.

The operator-server channel sends plain JSON. No encoding at all.

Why the difference? The beacon-server channel simulates encrypted C2 communications. In a real C2 framework, this channel would use AES-256 or ChaCha20 with a per-session key negotiated through an asymmetric key exchange. Our XOR cipher is a placeholder that demonstrates the concept without the complexity of real cryptography. It shows where encoding happens in the pipeline, how symmetric keys work, and why you need the same key on both sides.

The operator-server channel skips encoding because the operator is a trusted party operating on the same infrastructure. The operator dashboard connects through nginx on the same Docker network. There is no untrusted network between them, so encoding the messages would add latency and complexity with no security benefit. In a production C2, you would still want TLS on this channel, but the application-layer encoding that protects beacon traffic is unnecessary for operator traffic.

### Why XOR and Not AES

XOR with a repeating key is one of the weakest ciphers that exists. It is vulnerable to known-plaintext attacks, frequency analysis, and key recovery if you know any part of the plaintext. We chose it deliberately because:

- It is easy to understand. You can trace through the encoding by hand with a calculator.
- It is symmetric. The same function encrypts and decrypts.
- It demonstrates the full pipeline. The encode/decode/pack/unpack functions would have the same signatures with AES.
- Swapping it for a real cipher later requires changing exactly two functions in `encoding.py` and their equivalents in the beacon.

The key is configured in `.env` as `XOR_KEY` and loaded through Pydantic Settings in `backend/app/config.py`. The beacon reads it from the `C2_XOR_KEY` environment variable. Both sides must have the same key, which is the fundamental property of symmetric encryption.

---

## Database Schema

The database has three tables with foreign key relationships:

```
beacons (id PK) <--- tasks (beacon_id FK) <--- task_results (task_id FK)
```

### beacons

```sql
CREATE TABLE IF NOT EXISTS beacons (
    id          TEXT PRIMARY KEY,
    hostname    TEXT NOT NULL,
    os          TEXT NOT NULL,
    username    TEXT NOT NULL,
    pid         INTEGER NOT NULL,
    internal_ip TEXT NOT NULL,
    arch        TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);
```

Each row is a beacon that has connected at least once. The `id` is a UUID generated by the beacon on first run. `first_seen` is set on initial registration and never updated. `last_seen` is updated on every heartbeat and on disconnect. The remaining columns capture the system metadata the beacon collected during registration.

Registration uses INSERT with ON CONFLICT(id) DO UPDATE, so if a beacon reconnects with the same ID, the metadata gets refreshed but `first_seen` is preserved from the original row.

### tasks

```sql
CREATE TABLE IF NOT EXISTS tasks (
    id           TEXT PRIMARY KEY,
    beacon_id    TEXT NOT NULL,
    command      TEXT NOT NULL,
    args         TEXT,
    status       TEXT NOT NULL DEFAULT 'pending',
    created_at   TEXT NOT NULL,
    completed_at TEXT,
    FOREIGN KEY (beacon_id) REFERENCES beacons(id)
);
```

Each row is a task submitted by an operator for a specific beacon. The `id` is a server-generated UUID. `command` is one of the `CommandType` enum values (shell, sysinfo, proclist, etc.). `args` is an optional string payload whose meaning depends on the command type. For a shell command, it is the shell command string. For an upload, it is a JSON blob with filename and content. For sleep, it is a JSON blob with interval and jitter.

`status` starts as `'pending'` and transitions to `'completed'` when a result comes back. `created_at` is set at submission time, `completed_at` is set when the result is stored.

### task_results

```sql
CREATE TABLE IF NOT EXISTS task_results (
    id         TEXT PRIMARY KEY,
    task_id    TEXT NOT NULL UNIQUE,
    output     TEXT,
    error      TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES tasks(id)
);
```

Each row is the result of a completed task. The `task_id` foreign key is UNIQUE, enforcing a one-to-one relationship with the tasks table (each task produces exactly one result). `output` contains the command's stdout or structured JSON, depending on the command type. `error` contains stderr or an error message. Both can be NULL.

### Why SQLite with WAL Mode

SQLite is the right choice for this project for several reasons:

**Single server, single writer.** Our C2 server is one process. There is no cluster of backend instances competing for database access. SQLite handles single-writer workloads perfectly.

**WAL mode handles concurrent reads.** The backend is async, so multiple coroutines might read the database simultaneously (an operator querying the beacon list while the server is processing a heartbeat). WAL mode allows concurrent readers without blocking, which the default rollback journal mode does not. The `init_db()` function in `database.py` enables WAL with `PRAGMA journal_mode=WAL`.

**Zero configuration.** SQLite is embedded in the Python process. There is no separate database server to configure, no connection pooling to tune, no network latency between the application and the database. The database is a single file at `backend/data/c2.db`.

**Good enough for educational scope.** A production C2 framework that needs to support multiple team servers, geographic distribution, or hundreds of concurrent beacons would use PostgreSQL. For a single-server educational project, SQLite keeps the focus on C2 architecture instead of database administration.

---

## Design Decisions

### Why WebSockets Over HTTP Polling

A C2 system needs bidirectional communication. The server needs to push tasks to beacons as soon as an operator submits them, and beacons need to push results back as they complete. There are a few ways to achieve this:

**HTTP polling** means the beacon sends a GET request every N seconds asking "do you have a task for me?" This works, and many real C2 frameworks use it because HTTP blends into normal web traffic. The downside is latency: if the polling interval is 30 seconds, a task might wait up to 30 seconds before the beacon picks it up.

**HTTP long polling** improves latency by having the server hold the request open until a task is available. This is better, but managing held connections adds complexity and each pending request consumes a server thread or connection slot.

**WebSockets** give us a persistent, full-duplex connection. The server can push a task to the beacon the instant it arrives, with zero polling latency. The beacon can send heartbeats and results at any time without opening new connections.

We chose WebSockets because they simplify the architecture. One connection, bidirectional, always open. The trade-off is operational security: a persistent WebSocket connection to a fixed endpoint (`/api/ws/beacon`) is easier for network security tools to detect than periodic HTTP requests that look like normal web browsing. A production C2 would offer both options and let the operator choose based on the target environment.

### Why SQLite Over PostgreSQL

Covered in the database schema section above. The short version: single server, single writer, WAL handles concurrent reads, zero configuration, appropriate for the educational scope.

### Why Zustand Over React Context

The frontend state management uses Zustand instead of React Context. There are concrete reasons for this:

**No provider wrapper.** React Context requires wrapping your component tree in a `<Provider>`. Zustand stores are module-level singletons. You import `useC2Store` and call it. This keeps the component tree clean and avoids provider nesting issues when you have multiple stores.

**Selector-based subscriptions.** With React Context, any update to the context value re-renders every component that consumes it. Zustand lets components subscribe to specific slices of state. The dashboard only subscribes to the beacons object. The session page only subscribes to task results. When a heartbeat updates a beacon's `last_seen`, the session page does not re-render.

**`useShallow` for derived arrays.** The `useBeacons` selector in `frontend/src/core/ws.ts` uses `useShallow` to wrap `Object.values(s.beacons)`. Without `useShallow`, `Object.values()` would create a new array reference on every store update, causing the component to re-render in an infinite loop even if the actual beacon data has not changed. `useShallow` performs a shallow comparison of the array elements and only returns a new reference if the contents actually differ.

**DevTools support.** The store is wrapped in Zustand's `devtools` middleware with `name: 'C2Store'`. This means you can open the Redux DevTools browser extension and inspect every state change, which is invaluable when debugging WebSocket message handling.

### Why Per-Beacon Task Queues

The `TaskManager` in `backend/app/beacon/tasking.py` maintains a separate `asyncio.Queue` for each beacon ID. When an operator submits a task for beacon A, it goes into beacon A's queue. Beacon B's queue is unaffected.

This design has several benefits:

**Independent delivery.** If beacon A is slow or disconnected, tasks for beacon B are not blocked. Each beacon's `_send_tasks` coroutine in `beacon/router.py` blocks on its own queue independently.

**Clean disconnection handling.** When a beacon disconnects, `task_manager.remove_queue(beacon_id)` drops the queue and any pending tasks in it. This prevents memory leaks from accumulating tasks for dead beacons.

**Simple ordering.** asyncio.Queue is FIFO, so tasks for a given beacon are delivered in the order they were submitted. There is no need for priority logic or sorting.

The alternative would be a single shared queue with filtering, or a database polling approach where the `_send_tasks` coroutine queries SQLite for pending tasks. The per-beacon queue approach is simpler, faster (no database queries in the hot path), and naturally maps to the one-coroutine-per-beacon architecture.

### Why Dual Coroutine Pattern (send + receive)

The beacon WebSocket handler in `backend/app/beacon/router.py` runs two coroutines concurrently for each beacon connection:

- `_send_tasks` blocks on `task_manager.get_next()` and sends TASK messages to the beacon.
- `_receive_messages` blocks on `ws.receive_text()` and processes HEARTBEAT and RESULT messages from the beacon.

These run under `asyncio.wait` with `return_when=FIRST_COMPLETED`:

```python
done, pending = await asyncio.wait(
    [send_task, recv_task],
    return_when=asyncio.FIRST_COMPLETED,
)

for task in pending:
    task.cancel()
```

This pattern is the standard way to handle bidirectional WebSocket communication in asyncio. Here is why both coroutines are necessary:

**`_send_tasks` must block independently.** It needs to await the task queue, which could take minutes or hours if no operator submits a task. You cannot interleave this with receiving messages in the same coroutine without complicated select/poll logic.

**`_receive_messages` must block independently.** It needs to await the next WebSocket frame, which could be a heartbeat every few seconds or a result after a long-running command.

**FIRST_COMPLETED handles disconnection.** If the beacon disconnects, `ws.receive_text()` raises `WebSocketDisconnect`, which terminates `_receive_messages`. The `asyncio.wait` returns immediately, the pending `_send_tasks` coroutine gets cancelled, and the `finally` block in the main handler cleans up the registry and task queue. The reverse works too: if `_send_tasks` fails (perhaps because `ws.send_text()` raises on a dead connection), it completes first and `_receive_messages` gets cancelled.

---

## Security Architecture

### Threat Model

This is an educational project, so the threat model is intentionally limited. Here is what we protect against, what we simulate, and what we deliberately leave open:

**What we simulate protecting against:**

- **Network eavesdropping.** The XOR+Base64 encoding on the beacon-server channel simulates transport encryption. If someone captures the WebSocket traffic, they see Base64 strings instead of plaintext JSON. Of course, XOR with a known-length repeating key is trivially breakable. The point is to demonstrate where encoding sits in the protocol stack, not to provide real confidentiality.
- **Message integrity.** The `unpack()` function validates incoming messages against the Pydantic schema. A malformed or garbage message gets rejected with a ValueError. This prevents basic protocol confusion, though it does nothing against a sophisticated attacker who knows the protocol format.
- **Beacon identity.** The shared XOR key acts as a weak form of authentication. If you do not have the key, your REGISTER message will not decode correctly and the server will reject it. This simulates the concept of pre-shared key authentication, even though the actual implementation is weak.

**What we intentionally do not protect against:**

- **Reverse engineering.** The beacon is a plaintext Python script. Anyone with access to the file can read the source, extract the XOR key, and understand the protocol completely.
- **EDR/AV detection.** The beacon makes no attempt to evade endpoint detection. It uses standard Python libraries, standard process names, and standard network calls.
- **Traffic analysis.** The WebSocket endpoint is always `/api/ws/beacon`. The heartbeat interval is predictable (even with jitter). A network analyst could easily fingerprint this traffic.
- **Key extraction from memory.** The XOR key sits in plaintext in the beacon's process memory. A memory dump reveals it immediately.
- **Operator authentication.** Anyone who can reach the `/api/ws/operator` endpoint can connect as an operator and issue commands. There is no login, no token, no access control. This is an intentional simplification.

### What a Production C2 Would Add

If you were building a real C2 framework (for authorized red team operations), you would add layers that we skip here:

**TLS for transport encryption.** All traffic would go over HTTPS/WSS. This provides real confidentiality and integrity at the transport layer, and it makes the C2 traffic blend in with normal HTTPS traffic.

**Certificate pinning.** The beacon would validate the server's TLS certificate against a pinned hash, preventing man-in-the-middle attacks even if the target environment has a corporate TLS interception proxy.

**Asymmetric key exchange.** Instead of a pre-shared XOR key, the beacon and server would negotiate a session key using RSA or ECDH. This provides forward secrecy: compromising one session key does not reveal past or future communications.

**Operator authentication.** The operator dashboard would require authentication (username/password, client certificates, or TOTP). Role-based access control would limit which operators can access which beacons.

**Beacon staging.** Instead of deploying the full beacon as a Python script, a production C2 uses a small "stager" that downloads the full payload from the server, decrypts it in memory, and executes it without touching disk. This reduces the file-based detection surface.

**Malleable C2 profiles.** Tools like Cobalt Strike let operators define "profiles" that reshape C2 traffic to look like legitimate web services (Slack API calls, Google Analytics beacons, etc.). This defeats signature-based network detection.

**Domain fronting or CDN hiding.** The beacon connects to a legitimate CDN domain (like cloudfront.net), and the CDN routes the request to the actual C2 server based on the Host header. From the network's perspective, the beacon is just talking to a CDN.

---

## Deployment Architecture

### Development Stack

The development stack is defined in `dev.compose.yml` and optimized for live editing with hot reload on every component:

```
dev.compose.yml
├── nginx        (nginx:1.27-alpine, port 47430)
│   └── volumes: dev.nginx config (read-only)
├── frontend     (Vite dev server, port 5173)
│   └── volumes: ./frontend mounted, node_modules in named volume
└── backend      (uvicorn --reload, port 8000)
    └── volumes: ./backend mounted, .venv in named volume
```

**Nginx** uses the stock `nginx:1.27-alpine` image with the development config mounted in. It proxies to both the Vite dev server and the FastAPI backend.

**Frontend** builds from `infra/docker/vite.dev.dockerfile` and runs `pnpm dev` with Vite's HMR (Hot Module Replacement) server on port 5173. The source directory `./frontend` is bind-mounted into the container, so any file change on your host triggers an instant browser refresh. The `node_modules` directory lives in a Docker named volume (`frontend_modules`) to avoid platform-specific binary conflicts between your host OS and the container's Linux.

**Backend** builds from `infra/docker/fastapi.dev.dockerfile` and runs uvicorn with `--reload` enabled. The source directory `./backend` is bind-mounted, so Python file changes trigger an automatic server restart. The `.venv` directory lives in a named volume (`backend_cache`) for the same platform isolation reason. Environment variables set `ENVIRONMENT=development`, `DEBUG=true`, and `RELOAD=true`.

The development compose uses Docker's `depends_on` with health checks to ensure the backend is ready before nginx starts proxying to it. The backend health check hits `http://localhost:8000/health` every 10 seconds with a 30-second startup grace period.

### Production Stack

The production stack is defined in `compose.yml` and differs from development in several ways:

```
compose.yml
├── nginx        (multi-stage build, port 47430)
│   └── Built frontend static files baked into image
└── backend      (gunicorn, port 8000)
    └── SQLite data in named volume (c2_data)
```

**Nginx** uses a multi-stage build defined in `infra/docker/frontend-builder.prod.dockerfile`. The first stage installs pnpm, runs `pnpm build`, and produces the static frontend files. The second stage copies those files into an nginx image with the production config (`prod.nginx`). There is no separate frontend container in production. Nginx serves the built files directly, which is faster and uses fewer resources.

**Backend** builds from `infra/docker/fastapi.prod.dockerfile` and runs with `ENVIRONMENT=production`, `DEBUG=false`, `RELOAD=false`. The SQLite database lives in a Docker named volume (`c2_data`) so it persists across container restarts. Resource limits are set: the backend gets up to 2 CPUs and 1GB RAM, nginx gets up to 1 CPU and 256MB RAM.

The production nginx config (`prod.nginx`) adds security headers (X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy), aggressive caching for static assets (1 year for `/assets/` with immutable), and tighter rate limits (burst=20 vs burst=50 in dev).

---

## Key Files Reference

Quick lookup table mapping concepts to their implementation files:

| Concept | File |
|---------|------|
| XOR encoding | `backend/app/core/encoding.py` |
| Protocol messages | `backend/app/core/protocol.py` |
| Data models | `backend/app/core/models.py` |
| Beacon WebSocket handler | `backend/app/beacon/router.py` |
| Task queue management | `backend/app/beacon/tasking.py` |
| Beacon registry | `backend/app/beacon/registry.py` |
| Operator REST + WebSocket | `backend/app/ops/router.py` |
| Operator broadcast manager | `backend/app/ops/manager.py` |
| App factory + lifespan | `backend/app/__main__.py` |
| Configuration (Pydantic Settings) | `backend/app/config.py` |
| Database schema + connection | `backend/app/database.py` |
| Beacon implant | `beacon/beacon.py` |
| Frontend Zustand store + WebSocket | `frontend/src/core/ws.ts` |
| Frontend Zod schemas + types | `frontend/src/core/types.ts` |
| Frontend route + endpoint config | `frontend/src/config.ts` |
| Nginx dev config | `infra/nginx/dev.nginx` |
| Nginx prod config | `infra/nginx/prod.nginx` |
| Nginx shared base config | `infra/nginx/nginx.conf` |
| Development Docker Compose | `dev.compose.yml` |
| Production Docker Compose | `compose.yml` |

---

**Next up:** [03-PROTOCOL-DEEP-DIVE.md](./03-PROTOCOL-DEEP-DIVE.md) will step through the encoding pipeline byte by byte, show you XOR in action with real data, and explain how to break it.
