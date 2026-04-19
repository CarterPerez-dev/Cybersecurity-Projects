# System Architecture

This document breaks down how AngelusVigil is designed and why each architectural decision was made. Read this before diving into the implementation.

## High Level Architecture

```
+----------------------------------------------------------------------+
|                        Docker Compose Stack                          |
|                                                                      |
|  +-----------+    +--------------------------------------------+     |
|  |  nginx    |    |            vigil-backend                   |     |
|  | (external)|    |                                            |     |
|  |           |    |  +--------+  +---------+  +-----------+    |     |
|  | access.log|--->|  | Tailer |->| Pipeline|->| Dispatcher|    |     |
|  |           |    |  +--------+  | (4-stage)|  +-----+----+    |     |
|  +-----------+    |              +-----+----+        |         |     |
|                   |                    |             |         |     |
|                   |              +-----+----+  +-----+------+ |     |
|                   |              |  Redis   |  | PostgreSQL | |     |
|                   |              | (windows |  | (events)   | |     |
|                   |              |  + pub/  |  +------------+ |     |
|                   |              |    sub)  |                  |     |
|                   |              +-----+----+                  |     |
|                   |                    |                       |     |
|                   |              +-----+----+                  |     |
|                   |              | WebSocket|                  |     |
|                   |              |  Relay   |                  |     |
|                   |              +-----+----+                  |     |
|                   |                    |   +---------------+   |     |
|                   |                    |   | FastAPI REST  |   |     |
|                   |                    |   | (6 routers)   |   |     |
|                   +--------------------+---+-------+-------+   |     |
|                                        |           |           |     |
|  +-------------------------------------+-----------+--------+  |     |
|  |        vigil-frontend               |           |        |  |     |
|  |  +-----------+  +----------+        |           |        |  |     |
|  |  | Dashboard |  | Threats  |<-------+<----------+        |  |     |
|  |  | (live)    |  | (table)  | WebSocket   REST API        |  |     |
|  |  +-----------+  +----------+                             |  |     |
|  +----------------------------------------------------------+  |     |
|                                                                 |     |
|  +--------------+  +--------------+                             |     |
|  | GeoIP        |  | MLflow       |                             |     |
|  | Updater      |  | (tracking)   |                             |     |
|  +--------------+  +--------------+                             |     |
+----------------------------------------------------------------------+
```

### Component Breakdown

**Log Tailer (tailer.py)**
- Purpose: Watch the nginx access log file for new lines and feed them into the pipeline
- Responsibilities: Handle log rotation (rename and create events), persist read position for crash recovery, push raw lines into the async queue without blocking the event loop
- Interface: Pushes `str` lines into `Pipeline.raw_queue` via `call_soon_threadsafe`

**4-Stage Pipeline (pipeline.py)**
- Purpose: Transform raw log lines into scored threat candidates through four sequential stages
- Responsibilities: Parse log entries, extract and encode features, score via rules + ML, dispatch results
- Interface: Accepts raw lines on `raw_queue`, emits `ScoredRequest` objects via the `on_result` callback

**Rule Engine (rules.py)**
- Purpose: Provide immediate pattern-based detection without ML models
- Responsibilities: Evaluate 9 regex rules, 2 threshold rules, double-encoding and scanner detection against each request
- Interface: `score_request(features, entry) -> RuleResult`

**Inference Engine (inference.py)**
- Purpose: Run the 3-model ONNX ensemble for ML-based scoring
- Responsibilities: Load ONNX sessions, apply RobustScaler normalization, compute autoencoder reconstruction error, extract RF probabilities, return raw per-model scores
- Interface: `predict(batch) -> dict[str, list[float]]`

**Alert Dispatcher (dispatcher.py)**
- Purpose: Route scored requests to storage, real-time alerts, and logging
- Responsibilities: Persist MEDIUM+ events to PostgreSQL, publish JSON alerts to Redis pub/sub, log all events as structured JSON
- Interface: `dispatch(scored) -> None` (async callback)

**Redis (sliding windows + pub/sub)**
- Purpose: Dual role as windowed feature store and real-time message broker
- Responsibilities: Store per-IP sorted sets for behavioral aggregation, relay alert messages from backend to WebSocket clients
- Interface: Sorted sets for `WindowAggregator`, pub/sub for `AlertDispatcher` -> WebSocket relay

**PostgreSQL (event storage)**
- Purpose: Persistent storage for threat events and model metadata
- Responsibilities: Store all MEDIUM+ severity events with full context (features, scores, geo, matched rules), store ML model training metadata and artifact paths
- Interface: SQLModel ORM via async SQLAlchemy

**React Frontend**
- Purpose: Visual interface for monitoring and investigation
- Responsibilities: Live dashboard with stats and alert feed, filterable threats table, model status and retraining controls
- Interface: REST API via Axios/React Query, WebSocket for live alerts

## Data Flow

### Primary Flow: Log Line to Alert

Step by step walkthrough of what happens when nginx writes a log line:

```
1. nginx writes to access.log
       │
       ▼
2. Watchdog PollingObserver fires on_modified
   _LogHandler._read_new_lines()
       │
       ▼
3. Raw line pushed to Pipeline.raw_queue (capacity: 1000)
   via loop.call_soon_threadsafe
       │
       ▼
4. Stage 1 (_parse_worker): parse_combined(line)
   Splits on quotes, extracts IP/method/path/status/UA
   Result: ParsedLogEntry
       │
       ▼
5. Stage 2 (_feature_worker):
   5a. GeoIP lookup → country_code, city, lat, lon
   5b. extract_request_features() → 23 per-request features
   5c. WindowAggregator.record_and_aggregate() → 12 windowed features
       (single Redis pipeline round-trip: 7 ZADD + 7 ZREMRANGEBYSCORE
        + 5 ZCOUNT + 4 ZRANGEBYSCORE + 7 EXPIRE)
   5d. encode_for_inference() → 35-dim float32 vector
   Result: EnrichedRequest
       │
       ▼
6. Stage 3 (_detection_worker):
   6a. RuleEngine.score_request() → RuleResult (score + matched rules)
   6b. If ML models loaded:
       InferenceEngine.predict() → raw {ae, rf, if} scores
       normalize + fuse + blend with rule score
   Result: ScoredRequest (final_score, detection_mode, ml_scores)
       |
       v
7. Stage 4 (_dispatch_worker):
   AlertDispatcher.dispatch(scored)
   7a. Log structured event to stdout
   7b. If severity >= MEDIUM:
       7b-i.  create_threat_event() → INSERT into threat_events
       7b-ii. Publish WebSocketAlert JSON to Redis "alerts" channel
       │
       ▼
8. Redis pub/sub → WebSocket relay → React dashboard AlertFeed
```

### Secondary Flow: Model Retraining

```
1. POST /models/retrain (API key required)
       │
       ▼
2. Fetch stored ThreatEvents from PostgreSQL
   Label via review_label or score thresholds
   Supplement with synthetic data if < 200 samples
       │
       ▼
3. TrainingOrchestrator.run(X, y)
   3a. prepare_training_data() → stratified split + SMOTE
   3b. train_autoencoder() on normal-only data (100 epochs)
   3c. train_random_forest() on labeled data (200 estimators)
   3d. train_isolation_forest() on normal-only data
       │
       ▼
4. Export to ONNX:
   ae.onnx, rf.onnx, if.onnx, scaler.json, threshold.json
       │
       ▼
5. validate_ensemble() on test set
   Quality gates: PR-AUC >= 0.85, F1 >= 0.80
       │
       ▼
6. Log to MLflow (params, metrics, artifacts)
       |
       v
7. Backend restart loads new ONNX models
   Switches detection_mode from "rules" to "hybrid"
```

## Design Patterns

### Poison-Pill Shutdown

**What it is:**
A shutdown signal propagated through the queue chain. When `Pipeline.stop()` is called, it puts `None` into `raw_queue`. Each worker checks for `None`, forwards it to the next queue, and exits.

**Where we use it:**
All four pipeline stages in `pipeline.py`. The poison pill cascades:
`raw_queue → parsed_queue → feature_queue → alert_queue`

**Why we chose it:**
Clean, deterministic shutdown. Every worker finishes its current item before exiting. No race conditions, no orphaned tasks. The alternative (cancelling `asyncio.Task` objects) leaves work in an inconsistent state if a worker is mid-processing.

**Trade-offs:**
- Pros: Guaranteed drain of in-flight items, simple to implement, no data loss
- Cons: Shutdown isn't instant (must wait for each stage to process its current item)

### Sidecar Deployment

**What it is:**
AngelusVigil runs alongside the target nginx server without modifying it. The backend reads nginx's access log file (read-only volume mount) and the frontend proxies API calls.

**Why we chose it:**
Zero code changes to the monitored application. You add AngelusVigil to your `compose.yml` and point it at the nginx log volume. The monitored application doesn't know it's being watched.

**Trade-offs:**
- Pros: Non-invasive, works with any nginx deployment, can be added and removed without affecting the target
- Cons: Limited to information in the access log (no request bodies, no response bodies, no headers beyond User-Agent and Referer)

### Factory Pattern with Lifespan

**What it is:**
The `create_app()` function constructs the FastAPI application, and the `lifespan` async context manager handles startup/shutdown of all subsystems.

**Where we use it:**
`factory.py` is the single entry point for the application. The lifespan creates the database engine, connects Redis, initializes GeoIP, builds the pipeline, starts the tailer, and tears everything down in reverse order on shutdown.

**Why we chose it:**
Centralized resource management. Every connection, file handle, and background task is created in one place and cleaned up in one place. This prevents resource leaks and makes the startup/shutdown sequence explicit and testable.

## Layer Separation

```
+----------------------------------------------+
|  API Layer (api/)                            |
|  - Route handlers, request validation        |
|  - Depends on: Services, Schemas             |
|  - Never touches: Database directly, Redis   |
+----------------------------------------------+
                    |
                    v
+----------------------------------------------+
|  Service Layer (services/)                   |
|  - Business logic, query building            |
|  - Depends on: Models, SQLAlchemy sessions   |
|  - Never touches: HTTP request objects       |
+----------------------------------------------+
                    |
                    v
+----------------------------------------------+
|  Core Layer (core/)                          |
|  - Detection, ingestion, features, alerts    |
|  - Depends on: Redis, GeoIP, ONNX           |
|  - Never touches: HTTP, database directly    |
+----------------------------------------------+
                    |
                    v
+----------------------------------------------+
|  Model Layer (models/)                       |
|  - SQLModel ORM definitions                  |
|  - Depends on: Nothing (leaf node)           |
|  - Never touches: Business logic             |
+----------------------------------------------+
```

### What Lives Where

**API Layer (api/):**
- Files: `health.py`, `threats.py`, `stats.py`, `models_api.py`, `ingest.py`, `websocket.py`, `deps.py`
- Imports from: `services/`, `schemas/`, `config`
- Forbidden: Direct database queries, Redis operations, ML inference

**Service Layer (services/):**
- Files: `threat_service.py`, `stats_service.py`
- Imports from: `models/`, SQLAlchemy types
- Forbidden: HTTP request/response handling, WebSocket management

**Core Layer (core/):**
- Files: Everything under `core/ingestion/`, `core/detection/`, `core/features/`, `core/alerts/`, `core/enrichment/`
- Imports from: Redis client, ONNX runtime, GeoIP library
- Forbidden: HTTP framework imports, direct database access (dispatcher uses the service layer)

**Model Layer (models/):**
- Files: `ThreatEvent.py`, `ModelMetadata.py`, `Base.py`
- Imports from: `sqlmodel`, `uuid`, standard library
- Forbidden: Business logic, framework dependencies

## Data Models

### ThreatEvent

```python
class ThreatEvent(TimestampedModel, table=True):
    __tablename__ = "threat_events"

    source_ip: str              # INET type, indexed
    method: str                 # HTTP method
    path: str                   # Request path
    status_code: int
    response_size: int
    user_agent: str
    threat_score: float         # Indexed, 0.0-1.0
    severity: str               # HIGH/MEDIUM/LOW, indexed
    component_scores: dict      # JSON: per-rule and per-model scores
    matched_rules: list[str]    # JSON array of matched rule names
    country: str | None
    city: str | None
    lat: float | None
    lon: float | None
    feature_vector: list[float] # JSON: full 35-dim vector for replay
    model_version: str | None
    ml_scores: dict | None      # JSON: {ae: 0.7, rf: 0.8, if: 0.3}
    reviewed: bool = False      # Analyst review flag
    review_label: str | None    # "true_positive" or "false_positive"
```

**Key design decisions:**
- `feature_vector` is stored as JSON to enable model retraining from historical events without re-extracting features
- `component_scores` stores both rule and ML per-model scores for explainability
- `reviewed` and `review_label` support the active learning loop: analysts mark events, those labels become training data
- Partial index on `reviewed=FALSE` for efficient querying of unreviewed events

### ModelMetadata

```python
class ModelMetadata(TimestampedModel, table=True):
    __tablename__ = "model_metadata"

    model_type: str             # "autoencoder", "rf", "if"
    version: str                # Content-addressable hash
    training_samples: int
    metrics: dict               # JSON: model-specific metrics
    artifact_path: str          # Path to ONNX file
    is_active: bool             # One active per model_type
    mlflow_run_id: str | None
    threshold: float | None     # AE anomaly threshold
    notes: str | None
```

**Key design decisions:**
- `is_active` flag with a partial index on `(model_type, is_active=TRUE)` ensures only one version per model type is active at a time
- `version` uses content-addressable hashing so identical model outputs produce the same version string

## Security Architecture

### Threat Model

What we're protecting against:
1. **Web application attacks** - SQL injection, XSS, command injection, path traversal, SSRF, and other OWASP Top 10 attack categories targeting the monitored nginx server
2. **Reconnaissance and scanning** - Automated tools (nikto, sqlmap, nmap) probing for vulnerabilities
3. **Behavioral anomalies** - Credential stuffing, application-layer DDoS, and other attacks that look normal on a per-request basis but are anomalous in aggregate

What we're NOT protecting against (out of scope):
- Network-layer attacks (SYN floods, IP spoofing) since we only see HTTP-layer data from access logs
- Encrypted request bodies, since nginx access logs don't contain POST data or non-standard headers
- Insider threats with direct database access to AngelusVigil itself

### Defense Layers

```
Layer 1: Rule Engine (immediate, deterministic)
    Pattern matching against known attack signatures
    Behavioral thresholds from windowed features
    ↓
Layer 2: ML Ensemble (learned, probabilistic)
    Autoencoder anomaly detection (unsupervised)
    Random forest classification (supervised)
    Isolation forest outlier detection (unsupervised)
    ↓
Layer 3: Score Blending + Severity Classification
    30% rule weight + 70% ML weight
    HIGH/MEDIUM/LOW severity tiers
    ↓
Layer 4: Alert Dispatch + Human Review
    Persistent storage for forensic analysis
    Real-time WebSocket alerts for immediate triage
    Analyst review labels for active learning
```

### API Security

- `X-API-Key` header validation on all mutation endpoints (batch ingest, retrain)
- Health and readiness probes are unauthenticated (required for Docker healthchecks)
- WebSocket endpoint is unauthenticated (it only streams alerts, not raw data)
- The backend container mounts the nginx log volume as read-only, preventing any write-back to the monitored system

## Storage Strategy

### PostgreSQL (Persistent Storage)

**What we store:**
- Threat events (MEDIUM+ severity) with full context for forensic analysis
- Model metadata and training metrics for version tracking

**Why PostgreSQL:**
ACID guarantees for threat event storage. You don't want to lose a detected attack because of a race condition. The JSON column support handles the variable-schema fields (component_scores, ml_scores, feature_vector) without requiring a document database. Async driver (asyncpg) integrates cleanly with the FastAPI async lifecycle.

**Storage estimate:**
Each threat event row is roughly 2-4 KB including the 35-float feature vector and JSON fields. At a 1-5% detection rate on moderate traffic (10K requests/hour), that's 100-500 events/hour or roughly 10 GB/month of storage.

### Redis (Ephemeral State + Messaging)

**What we store:**
- Per-IP sliding window sorted sets (7 sets per tracked IP, 15-minute TTL)
- Real-time alert pub/sub messages (ephemeral, no persistence needed)

**Why Redis:**
Sorted sets with score-based range queries are perfect for sliding window aggregation. `ZCOUNT key <5min_ago> +inf` runs in O(log N) time. The pipeline feature batches all 7 ZADD + 7 ZREMRANGEBYSCORE + 5 ZCOUNT + 4 ZRANGEBYSCORE + 7 EXPIRE operations into a single round-trip.

Pub/sub provides the fan-out mechanism for WebSocket relay. When the backend publishes an alert, every connected WebSocket client receives it regardless of which backend worker processed the original request. This decouples producers (pipeline) from consumers (WebSocket connections).

**Memory estimate:**
Each tracked IP uses 7 sorted sets with a 15-minute TTL. At 10K unique IPs with 50 members per set, that's roughly 10 MB of Redis memory.

## Configuration

### Environment Variables

```bash
# Server
HOST=0.0.0.0               # Bind address
PORT=8000                   # Backend port
DEBUG=false                 # Debug mode (enables tracebacks in responses)
LOG_LEVEL=INFO              # Python logging level
API_KEY=                    # Required for mutation endpoints

# Database
DATABASE_URL=postgresql+asyncpg://vigil:changeme@localhost:5432/angelusvigil

# Redis
REDIS_URL=redis://localhost:6379

# Paths
NGINX_LOG_PATH=/var/log/nginx/access.log
GEOIP_DB_PATH=/usr/share/GeoIP/GeoLite2-City.mmdb
MODEL_DIR=data/models

# Pipeline Tuning
RAW_QUEUE_SIZE=1000         # Backpressure capacity for raw log lines
PARSED_QUEUE_SIZE=500       # Capacity after parsing
FEATURE_QUEUE_SIZE=200      # Capacity after feature extraction
ALERT_QUEUE_SIZE=100        # Capacity for scored requests awaiting dispatch
BATCH_SIZE=32               # ML inference batch size
BATCH_TIMEOUT_MS=50         # Max wait before sending partial batch

# ML Ensemble
ENSEMBLE_WEIGHT_AE=0.40     # Must sum to 1.0
ENSEMBLE_WEIGHT_RF=0.40
ENSEMBLE_WEIGHT_IF=0.20
AE_THRESHOLD_PERCENTILE=99.5   # Autoencoder anomaly threshold calibration
MLFLOW_TRACKING_URI=file:./mlruns
```

### Configuration Strategy

Configuration is managed via Pydantic Settings (`config.py`) which loads from environment variables and `.env` files. A `model_validator` enforces that ensemble weights sum to 1.0 at startup, failing fast rather than silently producing wrong scores at runtime.

**Development:** The `.env` file provides defaults. The dev compose mounts source code volumes for hot-reload and uses shorter healthcheck timeouts.

**Production:** All secrets (API_KEY, POSTGRES_PASSWORD, GEOIP_LICENSE_KEY) are required via `${VAR:?error}` syntax in `compose.yml`, forcing explicit configuration rather than falling through to insecure defaults.

## Performance Considerations

### Bottlenecks

Where this system gets slow under load:

1. **ML inference** - ONNX inference takes 5-20ms per request unbatched. At 1000 req/s, this would create a backlog. The pipeline uses dynamic batching (collect up to 32 requests or wait 50ms, whichever comes first) to amortize the overhead.

2. **Redis round-trips** - Each request needs 7 ZADD + 7 trim + 5 count + 4 range + 7 expire operations. Pipelining reduces this from 30 round-trips to 1, but at very high request rates the Redis pipeline itself becomes a bottleneck.

3. **GeoIP lookups** - The MaxMind mmap'd database is fast (~100us) but blocks the thread. Wrapped with `asyncio.to_thread()` to avoid blocking the event loop.

### Optimizations

- **Dynamic batching** in the detection worker: Collects feature vectors into batches of up to 32 before running ONNX inference. This improves throughput from ~35 req/s (unbatched) to ~640 req/s
- **Single Redis pipeline** per request: All 30 windowed aggregation operations execute in a single pipeline round-trip (~1ms total vs. ~30ms sequential)
- **ONNX single-threaded execution**: `inter_op_num_threads=1` and `intra_op_num_threads=1` avoids thread contention in the async Python process. ONNX thread pools fight with asyncio's event loop for CPU time
- **Fast parser path**: String-split parsing for standard nginx combined format, with regex fallback only for non-standard lines. The split path is 3-5x faster

### Scalability

**Vertical scaling:**
Single-process throughput ceiling is around 640 req/s with batching. Adding more CPU cores doesn't help because the pipeline is single-threaded by design (asyncio event loop). Memory usage scales linearly with tracked IPs in Redis.

**Horizontal scaling:**
To handle higher throughput, run multiple backend instances each tailing a partition of the log stream (or use a shared log bus like Kafka). Redis pub/sub already fans out alerts to all WebSocket clients regardless of which backend processed the event. PostgreSQL handles concurrent writes from multiple backends without issue.

## Design Decisions

### Why ONNX Instead of Native PyTorch/sklearn

**What we chose:**
Export all three models to ONNX and use ONNX Runtime for inference.

**Alternatives considered:**
- Native PyTorch inference: Works but 27% slower on CPU, requires the full PyTorch dependency in the backend container
- TorchScript: Better than raw PyTorch but still requires the PyTorch runtime. ONNX is framework-agnostic
- TensorFlow Lite: Good inference performance but adds a second ML framework dependency alongside sklearn

**Trade-offs:**
ONNX Runtime is faster, lighter, and framework-agnostic. The export step adds complexity during training, and debugging ONNX models is harder than debugging native PyTorch. But since inference is the hot path and training is rare, optimizing inference latency wins.

### Why Rules + ML Instead of ML-Only

**What we chose:**
A hybrid system that blends rule-based and ML-based scores.

**Alternatives considered:**
- ML-only: Simpler architecture, but useless on day one with no training data
- Rules-only: Proven approach (ModSecurity CRS), but can't detect novel attacks or behavioral anomalies

**Trade-offs:**
The hybrid approach provides immediate coverage (rules) that improves over time (ML). The 30/70 blend weight gives rules enough influence to catch high-confidence matches while letting ML dominate for nuanced scoring. The cost is architectural complexity: two scoring paths that must be normalized and blended.

### Why Redis Sorted Sets for Windowed Features

**What we chose:**
Redis sorted sets with Unix timestamps as scores, trimmed by `ZREMRANGEBYSCORE`.

**Alternatives considered:**
- In-memory sliding windows (Python `deque` with timestamp): Simpler but doesn't survive process restarts and doesn't share state across multiple backend instances
- PostgreSQL window functions: Correct but too slow. Each request would need a database query with a window function over recent events. At 500 req/s, the database becomes the bottleneck
- Redis Streams: Better for ordered event processing but worse for random-access aggregation. Sorted sets support `ZCOUNT` for range counting in O(log N)

**Trade-offs:**
Redis sorted sets give us sub-millisecond windowed queries that survive backend restarts and support horizontal scaling. The cost is operational complexity (another service to run) and the 7-sorted-set-per-IP data model that requires careful key management.

## Deployment Architecture

```
+---------------------------------------------+
|       Docker Compose (compose.yml)          |
|                                             |
|  +----------+  +----------+  +-----------+  |
|  | postgres |  |  redis   |  |  geoip    |  |
|  | :5432    |  |  :6379   |  |  updater  |  |
|  +----+-----+  +----+-----+  +-----------+  |
|       |              |                       |
|       +------+-------+                       |
|              |                               |
|       +------+------+                        |
|       |   backend   | :8000 (internal)       |
|       |  (FastAPI)  |                        |
|       +------+------+                        |
|              |                               |
|       +------+------+                        |
|       |  frontend   | :80 (host-mapped)      |
|       |  (nginx +   |                        |
|       |   React)    |                        |
|       +-------------+                        |
+---------------------------------------------+
```

**Services:**
- **postgres** (18-alpine): Persistent volume, healthcheck via `pg_isready`, 30s start period
- **redis** (7.4-alpine): Custom `redis.conf` for tuning, AOF persistence, healthcheck via `redis-cli ping`
- **backend**: Multi-stage Docker build with uv, reads nginx logs via read-only volume, 180s start period (allows initial model training)
- **frontend**: Vite production build served by nginx, proxies `/api` and `/ws` to backend
- **geoip-updater**: MaxMind sidecar, refreshes GeoLite2-City database every 168 hours

**Networks:**
- `vigil_network`: Internal bridge connecting all services
- `certgames_net`: External network for integration with the monitored application (CertGames)

**Volumes:**
- `postgres_data`, `redis_data`: Persistent state
- `geoip_data`: Shared between updater and backend
- `model_data`: ONNX model artifacts
- `nginx_logs`: External volume from the monitored nginx (read-only mount in backend)

## Error Handling Strategy

### Error Types

1. **Parse errors** - Malformed log lines that don't match nginx combined format. Counted in `stats["parse_errors"]`, logged, and skipped. The pipeline continues processing the next line.

2. **Feature extraction errors** - GeoIP lookup failures, Redis connection issues during windowed aggregation. Logged with the source IP for debugging. The request is dropped from the pipeline but doesn't crash the worker.

3. **ML inference errors** - ONNX session failures, shape mismatches. The detection worker falls back to rules-only scoring for that request. If the inference engine fails consistently, it's marked as not loaded.

4. **Dispatch errors** - PostgreSQL write failures, Redis pub/sub publish failures. Logged and counted. The event is lost but the pipeline continues. PostgreSQL write failures are rare with connection pooling; Redis pub/sub failures mean the WebSocket relay drops that alert but the next one works fine.

### Recovery Mechanisms

**Log tailer crash recovery:**
The tailer persists `(inode, offset)` to a JSON position file after each batch of reads. On restart, it resumes from the saved position if the inode matches (same file). If the inode changed (log was rotated), it starts from position 0 of the new file.

**Pipeline backpressure:**
Each queue has a max size (1000/500/200/100). If a downstream stage falls behind, the upstream queue fills up and the `await queue.put()` call blocks the upstream worker. This prevents memory exhaustion and propagates backpressure all the way to the log tailer, which drops lines when the raw queue is full (logged as warnings).

**Graceful degradation:**
If ONNX models aren't available, the system runs in rules-only mode. If Redis is down, windowed features return zeros (feature extraction catches the exception). If GeoIP is unavailable, geographic enrichment is skipped. Each subsystem's failure is isolated from the others.

## Extensibility

### Where to Add Features

**Adding a new detection rule:**
Add a `_PatternRule` entry to `_PATTERN_RULES` in `rules.py` with a compiled regex and a score. The rule engine will automatically evaluate it against every request. No registration or wiring needed.

**Adding a new ML model to the ensemble:**
1. Add a training function in `ml/`
2. Add an export function in `ml/export_onnx.py`
3. Load the new ONNX session in `inference.py`
4. Add a normalization function in `ensemble.py`
5. Add the model key and weight to the ensemble weights config
6. Update the `_score_with_ml` method in `pipeline.py`

**Adding a new feature:**
1. Compute the feature in `extractor.py` (per-request) or `aggregator.py` (windowed)
2. Add the feature name to `FEATURE_ORDER` in `mappings.py`
3. Update `encode_for_inference` in `encoder.py` if the feature needs special encoding
4. Retrain all models (the feature vector dimension changes)

**Adding a new API endpoint:**
Create a new router file in `api/`, add route handlers, and register it in `create_app()` in `factory.py`.

## Limitations

Current architectural limitations:

1. **Single log file source** - The tailer watches one file. Multi-server deployments would need a log aggregation layer (Fluentd, Filebeat) feeding into a shared bus. Not hard to add, but not built yet.

2. **No request body analysis** - Nginx access logs don't contain POST bodies or custom headers. Attacks hidden in request bodies (like the original Struts2 CVE-2017-5638 exploit via Content-Type header) are invisible. Extending to nginx error logs or application-level logs would close this gap.

3. **Retraining requires restart** - After training new models, the backend must restart to load the new ONNX sessions. Hot-reloading ONNX sessions without downtime would require a model registry and version-swap mechanism.

4. **No distributed pipeline** - The 4-stage pipeline runs in a single Python process. For traffic above ~640 req/s, you need to partition the log stream. A Kafka-based architecture with consumer groups would remove this ceiling.

These are conscious trade-offs. Fixing them adds operational complexity that isn't justified for the target deployment scale (sidecar for a single nginx instance).

## Comparison to Similar Systems

### vs. ModSecurity + OWASP CRS

ModSecurity is the industry standard WAF engine. It runs inline (as an nginx module) and can block requests in real time. AngelusVigil runs out-of-band (reading logs after the fact) and can only detect, not block.

The trade-off: ModSecurity has zero deployment friction for blocking but is rules-only. AngelusVigil adds ML detection and behavioral analysis at the cost of being detection-only. In practice, many teams run both: ModSecurity for blocking known attacks, and a system like AngelusVigil for detecting what ModSecurity missed.

### vs. Elastic SIEM / Splunk

Elastic SIEM and Splunk are full-featured SIEMs that ingest logs from many sources, correlate events, and provide dashboards. AngelusVigil does one thing: analyze nginx HTTP traffic for threats.

The trade-off: SIEMs are more general but require significant infrastructure and tuning. AngelusVigil is purpose-built for HTTP threat detection with a trained ML ensemble. You'd use AngelusVigil as a specialized detector feeding events into a SIEM for broader correlation.

### vs. AWS WAF / Cloudflare WAF

Cloud WAFs operate at the CDN/load balancer layer and can block traffic before it reaches your server. They use proprietary ML models trained on aggregate traffic from millions of sites.

The trade-off: Cloud WAFs have massive training datasets and zero deployment effort, but they're opaque (you can't inspect the models) and expensive at scale. AngelusVigil is fully transparent, customizable, and free, but requires your own infrastructure and training data.

## Key Files Reference

Quick map of where to find things:

- `backend/app/factory.py` - Application lifecycle (start/stop all subsystems)
- `backend/app/config.py` - All configuration with defaults and validation
- `backend/app/core/ingestion/pipeline.py` - The 4-stage async pipeline
- `backend/app/core/ingestion/tailer.py` - Watchdog-based log file tailer
- `backend/app/core/detection/rules.py` - Rule engine with 9 patterns + 2 thresholds
- `backend/app/core/detection/inference.py` - ONNX inference engine (3 models)
- `backend/app/core/detection/ensemble.py` - Score normalization and fusion
- `backend/app/core/features/extractor.py` - 23 per-request features
- `backend/app/core/features/aggregator.py` - 12 Redis-backed windowed features
- `backend/ml/orchestrator.py` - End-to-end training pipeline
- `frontend/src/pages/dashboard/index.tsx` - Dashboard with live alert feed
- `frontend/src/api/hooks/useAlerts.ts` - WebSocket connection with Zustand

## Next Steps

Now that you understand the architecture:
1. Read [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) for a detailed code walkthrough
2. Try modifying the ensemble weights in `.env` and observing how severity distribution changes on the dashboard
