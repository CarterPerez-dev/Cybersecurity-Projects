# Implementation Guide

This document walks through the actual code. We'll trace how data flows from raw log lines to scored threat alerts, explain each component's implementation, and cover the decisions behind the code.

## File Structure Walkthrough

```
backend/
├── app/
│   ├── api/
│   │   ├── deps.py              # Dependency injection (DB sessions, API key)
│   │   ├── health.py            # GET /health, GET /ready
│   │   ├── ingest.py            # POST /ingest/batch (manual log ingestion)
│   │   ├── models_api.py        # GET /models/status, POST /models/retrain
│   │   ├── stats.py             # GET /stats (time-windowed aggregates)
│   │   ├── threats.py           # GET /threats, GET /threats/{id}
│   │   └── websocket.py         # WS /ws/alerts (real-time alert stream)
│   ├── core/
│   │   ├── alerts/
│   │   │   └── dispatcher.py    # Routes scored events to storage + pub/sub
│   │   ├── detection/
│   │   │   ├── ensemble.py      # Score normalization, fusion, severity
│   │   │   ├── inference.py     # ONNX runtime (3-model inference)
│   │   │   └── rules.py         # ModSecurity-inspired rule engine
│   │   ├── enrichment/
│   │   │   └── geoip.py         # MaxMind GeoLite2 lookups
│   │   ├── features/
│   │   │   ├── aggregator.py    # Redis sorted set windowed features
│   │   │   ├── encoder.py       # Feature dict -> float32 vector
│   │   │   ├── extractor.py     # 23 per-request feature extraction
│   │   │   ├── mappings.py      # Feature order, encoders, constants
│   │   │   ├── patterns.py      # Compiled attack regex patterns
│   │   │   └── signatures.py    # Bot and scanner UA signatures
│   │   └── ingestion/
│   │       ├── parsers.py       # Nginx log line parser (split + regex)
│   │       ├── pipeline.py      # 4-stage async pipeline
│   │       └── tailer.py        # Watchdog file tailer with rotation
│   ├── models/
│   │   ├── Base.py              # TimestampedModel base class
│   │   ├── ModelMetadata.py     # ML model version tracking
│   │   └── ThreatEvent.py       # Stored threat events
│   ├── schemas/                 # Pydantic response models
│   ├── services/
│   │   ├── stats_service.py     # Aggregate query builder
│   │   └── threat_service.py    # CRUD for threat events
│   ├── config.py                # Pydantic Settings
│   └── factory.py               # App factory + lifespan
├── ml/
│   ├── autoencoder.py           # ThreatAutoencoder PyTorch module
│   ├── experiment.py            # MLflow experiment wrapper
│   ├── export_onnx.py           # PyTorch/sklearn -> ONNX export
│   ├── orchestrator.py          # End-to-end training pipeline
│   ├── scaler.py                # IQR-based FeatureScaler
│   ├── splitting.py             # Stratified split + SMOTE
│   ├── train_autoencoder.py     # AE training with early stopping
│   ├── train_classifiers.py     # RF + IF training
│   └── validation.py            # Ensemble validation + quality gates
├── cli/
│   └── main.py                  # Typer CLI (train, retrain, replay)
└── tests/                       # pytest suite
```

## Building the Log Ingestion Pipeline

### Step 1: Parsing Nginx Log Lines

The parser turns raw text into structured data. An nginx combined-format line looks like:

```
93.184.216.34 - - [15/Mar/2026:09:22:31 +0000] "GET /api/users?id=1 HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
```

The `parse_combined` function in `parsers.py` tries a fast string-split path first, falling back to regex for edge cases:

```python
def parse_combined(line: str) -> ParsedLogEntry | None:
    if not line:
        return None

    result = _parse_split(line)
    if result is not None:
        return result

    return _parse_regex(line)
```

The split parser exploits the fact that nginx combined format uses quotes as delimiters. Splitting on `"` gives predictable segments:

```python
def _parse_split(line: str) -> ParsedLogEntry | None:
    try:
        parts = line.split('"')
        if len(parts) < 6:
            return None

        prefix = parts[0]
        request_line = parts[1]
        status_size = parts[2]
        referer_raw = parts[3]
        user_agent = parts[5]

        bracket_open = prefix.index("[")
        bracket_close = prefix.index("]")
        ip = prefix[:bracket_open].split()[0]
        timestamp = datetime.strptime(
            prefix[bracket_open + 1:bracket_close],
            _TIMESTAMP_FMT,
        )
        ...
```

**Why this works:** Nginx combined format always quotes the request line, referer, and user-agent. The segments between quotes follow a fixed pattern. String splitting is 3-5x faster than regex matching because it avoids backtracking.

**When the split path fails:** If the log line has an unusual format (extra quotes in the request, malformed fields), `_parse_split` returns `None` and the regex fallback handles it:

```python
_COMBINED_RE = re.compile(
    r"(?P<ip>\S+) \S+ \S+ "
    r"\[(?P<timestamp>[^\]]+)\] "
    r'"(?P<request>[^"]*)" '
    r"(?P<status>\d{3}) "
    r"(?P<size>\S+) "
    r'"(?P<referer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"'
)
```

The result is a frozen, slotted `ParsedLogEntry` dataclass. Frozen because parsed entries should never be mutated. Slotted for memory efficiency when processing thousands of entries.

### Step 2: The 4-Stage Pipeline

The `Pipeline` class in `pipeline.py` chains four async workers connected by sized queues:

```
raw_queue (1000) → [parse] → parsed_queue (500) → [features]
→ feature_queue (200) → [detect] → alert_queue (100) → [dispatch]
```

Each queue has a max size that provides backpressure. If the detection stage falls behind, the feature queue fills up, which blocks the feature worker, which backs up the parsed queue, which eventually backs up the raw queue. When the raw queue is full, the tailer drops lines (logged as warnings).

The pipeline spawns four `asyncio.Task` objects:

```python
async def start(self) -> None:
    self._tasks = [
        asyncio.create_task(self._parse_worker(), name="parse"),
        asyncio.create_task(self._feature_worker(), name="feature"),
        asyncio.create_task(self._detection_worker(), name="detection"),
        asyncio.create_task(self._dispatch_worker(), name="dispatch"),
    ]
```

Each worker follows the same pattern: pull from input queue, process, push to output queue, loop. Shutdown uses a poison-pill (`None`) that cascades through the chain:

```python
async def stop(self) -> None:
    await self.raw_queue.put(None)
    await asyncio.gather(*self._tasks)
```

When the parse worker sees `None`, it forwards it to the parsed queue and exits. The feature worker sees `None` on the parsed queue, forwards it, and exits. This cascades until all workers have stopped.

### Step 3: File Tailing with Rotation Detection

The `LogTailer` in `tailer.py` watches the nginx log file using Watchdog's `PollingObserver` (not inotify, because Docker volumes don't always propagate inotify events).

The handler responds to three events:

- `on_modified`: New data appended. Read new lines and push to queue.
- `on_moved`: Log rotation via rename (`access.log` -> `access.log.1`). Finish reading the old file, then reopen the target at position 0.
- `on_created`: Log rotation where a new file appears at the target path. Same as `on_moved`.

Position persistence is the critical detail for crash recovery:

```python
def _save_position(self) -> None:
    if self._position_path is None or self._file is None:
        return
    try:
        self._position_path.write_text(
            json.dumps({
                "inode": self._inode,
                "offset": self._file.tell(),
            }),
        )
    except OSError:
        logger.debug("Failed to save tailer position")
```

On restart, `_open_target` checks if the saved inode matches the current file. If it does, the tailer resumes from the saved offset. If the inode changed (file was rotated), it starts from the beginning of the new file.

**Why inode tracking matters:** The filename `access.log` can point to different files over time due to rotation. The inode is the file system's identity for the actual file. If the inode changed, the file we were reading was rotated away and a new one was created.

**Why `call_soon_threadsafe`:** Watchdog runs its callback handlers in a separate thread. The asyncio queue belongs to the event loop's thread. `call_soon_threadsafe` bridges the gap by scheduling the `put_nowait` call on the event loop thread.

## Building the Feature Extraction System

### Per-Request Features

The `extract_request_features` function in `extractor.py` computes 23 features from a single `ParsedLogEntry`:

```python
def extract_request_features(
    entry: ParsedLogEntry,
    country_code: str = "",
) -> dict[str, int | float | bool | str]:
    full_uri = entry.path
    if entry.query_string:
        full_uri = f"{entry.path}?{entry.query_string}"

    ua_lower = entry.user_agent.lower()
    non_alnum = sum(1 for c in entry.path if not c.isalnum())
    path_len = len(entry.path)

    _, ext = splitext(entry.path)

    return {
        "http_method": entry.method,
        "path_depth": len([s for s in entry.path.split("/") if s]),
        "path_entropy": _shannon_entropy(entry.path),
        ...
    }
```

Each feature is deliberately chosen for a specific detection signal:

- `path_entropy` catches attack payloads that have high randomness compared to normal URL paths
- `special_char_ratio` flags paths with unusual concentrations of non-alphanumeric characters (common in SQL injection and XSS payloads)
- `has_double_encoding` detects evasion techniques where attackers encode their payloads twice to bypass basic URL decoding
- `is_known_scanner` matches User-Agent strings against a curated list of known scanning tools

### Windowed Aggregation

The `WindowAggregator` in `aggregator.py` computes 12 per-IP behavioral features using Redis sorted sets. The entire operation happens in a single pipelined round-trip:

```python
async def record_and_aggregate(
    self, ip, request_id, path, path_depth,
    method, status_code, user_agent, response_size, timestamp,
) -> dict[str, float]:
    prefix = f"ip:{ip}"
    keys = {
        "requests": f"{prefix}:requests",
        "paths": f"{prefix}:paths",
        "statuses": f"{prefix}:statuses",
        ...
    }

    pipe = self._redis.pipeline()

    pipe.zadd(keys["requests"], {request_id: timestamp})
    pipe.zadd(keys["paths"], {_hash_member(path): timestamp})
    ...

    for key in keys.values():
        pipe.zremrangebyscore(key, "-inf", trim_boundary)

    pipe.zcount(keys["requests"], w1m, "+inf")
    pipe.zcount(keys["requests"], w5m, "+inf")
    ...

    results = await pipe.execute()
```

The pipeline packs 30 Redis commands into a single round-trip:
- 7 `ZADD` to record the new request across all sorted sets
- 7 `ZREMRANGEBYSCORE` to trim entries older than 15 minutes
- 5 `ZCOUNT` for request counts at 1m/5m/10m windows and unique counts
- 4 `ZRANGEBYSCORE` for detailed member retrieval (statuses, sizes, methods, depths)
- 7 `EXPIRE` to set TTL on all keys

**Why MD5 hashing for some members:** Sorted sets use members as unique identifiers. For paths and user agents, we want to count unique values. Hashing provides a fixed-size member that deduplicates effectively without storing full strings in Redis:

```python
def _hash_member(value: str) -> str:
    return hashlib.md5(value.encode(), usedforsecurity=False).hexdigest()[:16]
```

The `usedforsecurity=False` flag avoids FIPS compliance warnings since we're using MD5 for deduplication, not cryptographic security.

**Inter-request time statistics** capture the timing pattern of requests from a single IP:

```python
def _inter_request_time_stats(entries):
    if len(entries) < 2:
        return 0.0, 0.0
    timestamps = sorted(score for _, score in entries)
    deltas = [
        (timestamps[i + 1] - timestamps[i]) * 1000
        for i in range(len(timestamps) - 1)
    ]
    mean = sum(deltas) / len(deltas)
    if len(deltas) < 2:
        return mean, 0.0
    variance = sum((d - mean)**2 for d in deltas) / len(deltas)
    return mean, math.sqrt(variance)
```

Legitimate users have irregular request spacing (reading pages, clicking links). Automated tools have uniform spacing. A low standard deviation relative to the mean is a bot fingerprint.

### Feature Encoding

The `encode_for_inference` function in `encoder.py` transforms the mixed-type feature dictionary into a 35-element `float32` vector:

```python
def encode_for_inference(features):
    vector: list[float] = []

    for name in FEATURE_ORDER:
        raw = features[name]

        if name in BOOLEAN_FEATURES:
            vector.append(1.0 if raw else 0.0)
        elif name in CATEGORICAL_ENCODERS:
            vector.append(float(CATEGORICAL_ENCODERS[name].get(str(raw), 0)))
        elif name == "country_code":
            vector.append(_encode_country(str(raw)))
        else:
            vector.append(float(raw))

    return vector
```

`FEATURE_ORDER` defines the canonical ordering. This ordering must be identical at training and inference time. The `InferenceEngine` validates this by checking the `feature_names` field in `scaler.json` against `FEATURE_ORDER` at model load time.

Country codes use deterministic ordinal encoding (A=1, Z=26, two characters -> 1 to 676). This avoids one-hot encoding which would blow up the feature dimension.

## Building the Detection Engine

### The Rule Engine

The `RuleEngine` in `rules.py` evaluates every request against pattern rules, behavioral thresholds, and auxiliary checks:

```python
class RuleEngine:
    def score_request(self, features, entry) -> RuleResult:
        matched: list[tuple[str, float]] = []

        uri = entry.path
        if entry.query_string:
            uri = f"{entry.path}?{entry.query_string}"

        for rule in _PATTERN_RULES:
            if rule.pattern.search(uri):
                matched.append((rule.name, rule.score))

        if DOUBLE_ENCODED.search(uri):
            matched.append(("DOUBLE_ENCODING", _DOUBLE_ENCODING_SCORE))

        ua_lower = entry.user_agent.lower()
        if any(sig in ua_lower for sig in SCANNER_USER_AGENTS):
            matched.append(("SCANNER_UA", _SCANNER_UA_SCORE))

        for trule in _THRESHOLD_RULES:
            value = features.get(trule.feature_key, 0)
            if isinstance(value, int | float) and value > trule.threshold:
                matched.append((trule.name, trule.score))
```

The scoring logic applies a boost for multi-rule matches:

```python
        scores = sorted([s for _, s in matched], reverse=True)
        threat_score = min(
            scores[0] + _BOOST_PER_ADDITIONAL_RULE * (len(scores) - 1),
            1.0,
        )
```

A request matching SQL injection (0.85) + double encoding (0.40) + scanner UA (0.35) scores `0.85 + 0.05 * 2 = 0.95` because the highest rule score (0.85) gets a 0.05 boost per additional match (2 more rules = +0.10).

### ONNX Inference

The `InferenceEngine` in `inference.py` loads three ONNX sessions and runs them in sequence on each batch:

```python
def predict(self, batch: np.ndarray) -> dict[str, list[float]] | None:
    if not self._loaded:
        return None

    ae_input = self._scale_for_ae(batch)
    ae_reconstructed = self._ae_session.run(None, {"features": ae_input})[0]
    ae_errors = np.mean((ae_input - ae_reconstructed)**2, axis=1)

    rf_result = self._rf_session.run(None, {"features": batch})
    rf_proba = self._extract_rf_proba(rf_result[1])

    if_scores_raw = self._if_session.run(
        None, {"features": batch}
    )[1].flatten()

    return {
        "ae": ae_errors.tolist(),
        "rf": rf_proba.tolist(),
        "if": if_scores_raw.tolist(),
    }
```

**Why `_scale_for_ae` only applies to the autoencoder:** The autoencoder was trained on RobustScaler-normalized data. The scaler parameters (center and scale arrays) are saved alongside the model in `scaler.json` and applied at inference time. The random forest and isolation forest were trained on raw feature vectors, so they receive the unscaled batch.

**Why single-threaded ONNX sessions:** The backend runs on asyncio's single-threaded event loop. If ONNX Runtime spins up its own thread pool, those threads compete with the event loop for CPU. Setting `inter_op_num_threads=1` and `intra_op_num_threads=1` keeps everything on one core and avoids contention.

### Score Blending in the Pipeline

The detection worker in `pipeline.py` ties rules and ML together:

```python
async def _detection_worker(self) -> None:
    while True:
        enriched = await self._feature_queue.get()
        if enriched is None:
            ...
            break
        try:
            rule_result = self._rule_engine.score_request(
                enriched.features, enriched.entry,
            )

            final_score = rule_result.threat_score
            detection_mode = "rules"
            per_model_scores = None

            if (self._inference_engine is not None
                    and self._inference_engine.is_loaded
                    and np is not None):
                per_model_scores = self._score_with_ml(
                    enriched.feature_vector,
                )
                if per_model_scores is not None:
                    ml_fused = fuse_scores(
                        per_model_scores, self._ensemble_weights,
                    )
                    final_score = blend_scores(
                        ml_fused, rule_result.threat_score,
                    )
                    detection_mode = "hybrid"
```

When ML models are available, the flow is: rule score + ML ensemble fused score -> blended final score. When ML is unavailable (cold start), the rule score becomes the final score directly. The `detection_mode` field on `ScoredRequest` tracks which path was taken.

## Building the ML Training Pipeline

### The Training Orchestrator

`TrainingOrchestrator.run()` in `orchestrator.py` executes the full pipeline:

```python
def run(self, X: np.ndarray, y: np.ndarray) -> TrainingResult:
    self._output_dir.mkdir(parents=True, exist_ok=True)

    split = prepare_training_data(X, y)

    with VigilExperiment(self._experiment_name) as experiment:
        experiment.log_params({
            "epochs": self._epochs,
            "batch_size": self._batch_size,
            "n_samples": len(X),
            "n_attack": int(np.sum(y == 1)),
            "n_normal": int(np.sum(y == 0)),
            "n_features": X.shape[1],
        })

        ae_result = self._train_ae(split.X_normal_train)
        rf_result = self._train_rf(split.X_train, split.y_train)
        if_result = self._train_if(split.X_normal_train)

        self._export_models(ae_result, rf_result, if_result)
        ...
```

Note the training data used by each model:
- Autoencoder: `X_normal_train` (normal traffic only, no attacks)
- Random Forest: `X_train, y_train` (labeled mix of normal + attack, with SMOTE)
- Isolation Forest: `X_normal_train` (normal traffic only)

The autoencoder and isolation forest learn what "normal" looks like. The random forest learns to distinguish normal from attack. This mix of supervised and unsupervised approaches is the core of the ensemble strategy.

### Autoencoder Training

The training loop in `train_autoencoder.py` uses standard PyTorch patterns with a few specific choices:

```python
model = ThreatAutoencoder(input_dim=input_dim)
optimizer = torch.optim.AdamW(
    model.parameters(), lr=lr, weight_decay=1e-5, betas=(0.9, 0.999)
)
scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
    optimizer, mode="min", factor=0.5, patience=5, min_lr=1e-6
)
```

- **AdamW** instead of plain Adam: Weight decay regularization helps prevent the autoencoder from memorizing training data. We want it to learn general patterns of normal traffic, not specific requests.
- **ReduceLROnPlateau**: Halves the learning rate when validation loss plateaus for 5 epochs. This prevents oscillating around a minimum.
- **Gradient clipping** at `max_norm=1.0`: The mixed feature types (some 0-1, some 0-100000) can cause gradient explosions. Clipping stabilizes training.
- **Early stopping** with patience 10: Stops training when validation loss hasn't improved for 10 epochs. Prevents overfitting.

The threshold calibration happens after training completes:

```python
model.eval()
with torch.no_grad():
    val_errors = model.compute_reconstruction_error(val_tensor)
threshold = float(np.percentile(val_errors.numpy(), percentile))
```

The 99.5th percentile of reconstruction errors on the validation set becomes the anomaly threshold. This means roughly 0.5% of normal traffic will be flagged as anomalous, which is the baseline false positive rate.

### Ensemble Validation and Quality Gates

After training, `validate_ensemble` in `validation.py` tests the full ensemble against a held-out test set:

```python
def validate_ensemble(
    model_dir, X_test, y_test,
    ensemble_weights=None, pr_auc_gate=0.85, f1_gate=0.80,
) -> ValidationResult:
    engine = InferenceEngine(model_dir=str(model_dir))
    raw_scores = engine.predict(X_test.astype(np.float32))

    fused = _compute_fused_scores(raw_scores, engine.threshold, weights)
    y_pred = (fused >= BINARY_THRESHOLD).astype(np.int32)

    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1_val = float(f1_score(y_test, y_pred, zero_division=0))
    pr_auc_val = float(average_precision_score(y_test, fused))
    ...
```

**Why PR-AUC instead of ROC-AUC as the primary gate:** In threat detection, the class distribution is heavily imbalanced (1-5% attacks vs. 95-99% normal). ROC-AUC can look great even when the model has a high false positive rate because the overwhelming number of true negatives inflates the metric. PR-AUC focuses on precision and recall for the positive class (attacks), making it a more honest metric for imbalanced detection problems.

The quality gates (PR-AUC >= 0.85, F1 >= 0.80) prevent deploying models that would flood analysts with false positives. If either gate fails, `passed_gates` is `False` and the retrain endpoint reports the failure without swapping models.

## Building the Alert System

### Dispatcher

The `AlertDispatcher` in `dispatcher.py` receives `ScoredRequest` objects from the pipeline's dispatch stage:

```python
async def dispatch(self, scored: ScoredRequest) -> None:
    severity = classify_severity(scored.final_score)

    logger.info(
        "threat_event severity=%s score=%.2f mode=%s ip=%s path=%s rules=%s",
        severity, scored.final_score, scored.detection_mode,
        scored.entry.ip, scored.entry.path, scored.rule_result.matched_rules,
    )

    if severity in ("HIGH", "MEDIUM"):
        await self._store_event(scored)
        await self._publish_alert(scored, severity)
```

Every event is logged (structured JSON to stdout). Only MEDIUM and HIGH severity events are stored to PostgreSQL and published to the WebSocket channel. This keeps storage bounded while ensuring analysts have full context for non-trivial threats.

The pub/sub publish sends a Pydantic-serialized JSON payload:

```python
async def _publish_alert(self, scored, severity):
    alert = WebSocketAlert(
        timestamp=scored.entry.timestamp,
        source_ip=scored.entry.ip,
        request_method=scored.entry.method,
        request_path=scored.entry.path,
        threat_score=scored.final_score,
        severity=severity,
        component_scores={
            **scored.rule_result.component_scores,
            **(scored.ml_scores or {}),
        },
    )
    await self._redis.publish(ALERTS_CHANNEL, alert.model_dump_json())
```

### WebSocket Relay on the Frontend

The `useAlerts` hook in `useAlerts.ts` manages the WebSocket connection with Zustand state and exponential backoff reconnect:

```typescript
function connect() {
  const ws = new WebSocket(getWsUrl())
  wsRef.current = ws

  ws.onmessage = (event) => {
    const parsed = WebSocketAlertSchema.safeParse(JSON.parse(event.data))
    if (parsed.success) {
      addAlert({ ...parsed.data, id: crypto.randomUUID() })
    }
  }

  ws.onclose = () => {
    setConnected(false)
    scheduleReconnect()
  }
}

function scheduleReconnect() {
  const delay = Math.min(
    ALERTS.RECONNECT_BASE_MS * 2 ** retryCountRef.current,
    ALERTS.RECONNECT_MAX_MS
  )
  retryCountRef.current += 1
  retryTimerRef.current = setTimeout(connect, delay)
}
```

**Why Zod validation:** The WebSocket receives raw JSON from the server. `safeParse` validates the shape matches `WebSocketAlertSchema` before adding it to state. This prevents corrupt or unexpected messages from crashing the UI.

**Why a ring buffer:** The alert store caps at `ALERTS.MAX_ITEMS` (100). New alerts prepend and old ones are dropped. This bounds memory usage and keeps the feed focused on recent activity.

**Why exponential backoff:** If the backend restarts or the network hiccups, the WebSocket connection drops. Exponential backoff (500ms, 1s, 2s, 4s, ... capped at 30s) prevents hammering the server during an outage while recovering quickly from brief interruptions.

## Application Lifecycle

The `factory.py` lifespan manages startup and shutdown:

```python
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    engine = create_async_engine(settings.database_url)
    app.state.session_factory = async_sessionmaker(engine, ...)

    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    await redis_manager.connect()
    geoip = GeoIPService(settings.geoip_db_path)

    dispatcher = AlertDispatcher(
        redis_client=redis_manager.client,
        session_factory=app.state.session_factory,
    )

    inference_engine = _load_inference_engine()
    app.state.detection_mode = "hybrid" if inference_engine else "rules"

    pipeline = Pipeline(
        redis_client=redis_client, rule_engine=RuleEngine(),
        geoip=geoip, on_result=dispatcher.dispatch,
        inference_engine=inference_engine, ...
    )
    await pipeline.start()

    tailer = LogTailer(settings.nginx_log_path, pipeline.raw_queue, loop)
    tailer.start()

    yield  # Application runs here

    tailer.stop()
    await pipeline.stop()
    geoip.close()
    await redis_manager.disconnect()
    await engine.dispose()
```

The startup order matters: database first (schema creation), then Redis (pipeline depends on it), then GeoIP, then the pipeline (depends on all three), then the tailer (feeds the pipeline). Shutdown reverses the order: stop input (tailer), drain pipeline, close connections.

The `_load_inference_engine` function attempts to load ONNX models and returns `None` if they don't exist or onnxruntime isn't installed. This graceful fallback is what makes rules-only mode work on fresh deployments.

## Configuration Management

Pydantic Settings in `config.py` loads from environment variables and `.env`:

```python
class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    ensemble_weight_ae: float = 0.40
    ensemble_weight_rf: float = 0.40
    ensemble_weight_if: float = 0.20

    @model_validator(mode="after")
    def _check_ensemble_weights(self) -> Self:
        total = (
            self.ensemble_weight_ae
            + self.ensemble_weight_rf
            + self.ensemble_weight_if
        )
        if abs(total - 1.0) > 1e-6:
            raise ValueError(
                f"Ensemble weights must sum to 1.0, got {total:.6f}"
            )
        return self
```

The `model_validator` catches misconfiguration at startup. If someone sets the weights to 0.4/0.4/0.3 (sums to 1.1), the application fails immediately with a clear error instead of silently computing wrong scores.

## Testing Strategy

### Unit Tests

Parser tests verify both the fast and fallback paths:

```python
def test_parse_combined_standard_line():
    line = '93.184.216.34 - - [15/Mar/2026:14:22:31 +0000] "GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
    entry = parse_combined(line)
    assert entry is not None
    assert entry.ip == "93.184.216.34"
    assert entry.method == "GET"
    assert entry.path == "/api/users"
    assert entry.status_code == 200
```

Feature extraction tests verify specific detection signals:

```python
def test_sqli_payload_detected():
    entry = make_entry(path="/search", query_string="q=1' OR '1'='1")
    features = extract_request_features(entry)
    assert features["has_attack_pattern"] is True
    assert features["query_string_length"] > 0
```

### Integration Tests

End-to-end pipeline tests push a log line through all four stages and verify the output:

```python
async def test_pipeline_processes_log_line():
    pipeline = Pipeline(redis_client=mock_redis, rule_engine=RuleEngine())
    results = []
    pipeline._on_result = lambda scored: results.append(scored)
    await pipeline.start()

    await pipeline.raw_queue.put(SAMPLE_LOG_LINE)
    await pipeline.raw_queue.put(None)
    await asyncio.gather(*pipeline._tasks)

    assert len(results) == 1
    assert results[0].final_score >= 0.0
```

### Running Tests

```bash
just test            # Run full suite
just test-v          # Verbose output
just test-cov        # With coverage report
```

## Common Implementation Pitfalls

### Pitfall 1: Forgetting to Normalize ML Scores

**Symptom:**
The autoencoder scores are 0.001-0.05 while the random forest scores are 0.0-1.0. The ensemble fusion produces scores dominated by the RF because the AE scores are tiny.

**Cause:**
Raw autoencoder scores are reconstruction errors (MSE), not probabilities. They need normalization against the calibrated threshold.

**Fix:**
Always normalize before fusing:
```python
per_model["ae"] = normalize_ae_score(raw["ae"][0], engine.threshold)
per_model["rf"] = raw["rf"][0]  # Already a probability
per_model["if"] = normalize_if_score(raw["if"][0])
```

### Pitfall 2: Feature Ordering Mismatch

**Symptom:**
The model produces nonsensical scores. A clearly benign request scores 0.95, an obvious SQL injection scores 0.02.

**Cause:**
The feature vector at inference time is ordered differently than at training time. Feature 0 at training was `http_method`, but at inference it's `path_depth`.

**Fix:**
Both training and inference must use `FEATURE_ORDER` from `mappings.py`. The inference engine validates this at load time by checking the `feature_names` array in `scaler.json`.

### Pitfall 3: Redis Key Bloat

**Symptom:**
Redis memory usage grows indefinitely. The `INFO memory` command shows increasing `used_memory`.

**Cause:**
The `EXPIRE` commands in the aggregator pipeline are failing silently, or the trim boundary calculation is wrong, so old entries never get cleaned up.

**Fix:**
Verify that `KEY_TTL = 900` (15 minutes) is set and that `ZREMRANGEBYSCORE` is trimming entries older than the window. Check Redis key counts with `DBSIZE` and inspect individual keys with `ZCARD`.

## Debugging Tips

### Pipeline Not Processing Logs

**Problem:** The dashboard shows no activity even though nginx is writing logs.

**How to debug:**
1. Check the tailer: `GET /health` returns `pipeline_running: true` and stats showing `parsed > 0`
2. Check the log file exists: `docker compose exec backend ls -la /var/log/nginx/access.log`
3. Check tailer permissions: The backend container must have read access to the nginx log volume
4. Check Redis connectivity: If Redis is down, the feature worker fails silently and drops requests

### Model Training Fails Quality Gates

**Problem:** Training completes but `passed_gates: false`. The retrain endpoint reports failure.

**How to debug:**
1. Check the MLflow metrics: Look at `pr_auc` and `f1` in the training output
2. Check class distribution: If the training data is 99% normal with very few attack samples, the model can't learn to distinguish. Supplement with synthetic attack data
3. Check feature quality: If all features are zero or constant, the models have nothing to learn from. Verify that the feature extraction pipeline produces non-trivial values

### WebSocket Alerts Not Reaching Dashboard

**Problem:** The backend logs threat events but the dashboard alert feed is empty.

**How to debug:**
1. Check Redis pub/sub: `redis-cli SUBSCRIBE alerts` in a separate terminal should show messages when threats are detected
2. Check WebSocket connection: The browser dev tools Network tab should show a WebSocket connection to `/ws/alerts`
3. Check the connection status: The `useAlerts` hook exposes `connectionError` which the dashboard displays as a banner

## Build and Deploy

### Building

```bash
just build            # Build production Docker images
just rebuild          # Force rebuild without cache
```

### Local Development

```bash
just dev-up           # Start dev stack (hot-reload enabled)
just dev-logs backend # Follow backend logs
just devlog-up        # Start the synthetic traffic generator
```

### Production Deployment

```bash
# Set required environment variables
export POSTGRES_PASSWORD=<strong-password>
export API_KEY=<generated-api-key>
export GEOIP_ACCOUNT_ID=<maxmind-account>
export GEOIP_LICENSE_KEY=<maxmind-key>

just start            # Start production stack (detached)
just logs             # Follow all service logs
```

Key differences from dev:
- No hot-reload (uvicorn runs without `--reload`)
- Multi-stage Docker build (smaller images, no dev dependencies)
- Longer healthcheck start period (180s for initial model training)
- External nginx log volume mount (not the dev-log generator)

## Next Steps

You've seen how the code works. Now:

1. **Try the challenges** - [04-CHALLENGES.md](./04-CHALLENGES.md) has extension ideas from easy to expert
2. **Modify the ensemble weights** - Change `ENSEMBLE_WEIGHT_AE/RF/IF` in `.env` and observe how detection behavior changes on the dashboard
3. **Add a new detection rule** - Add an entry to `_PATTERN_RULES` in `rules.py` and test it with the dev-log simulator
