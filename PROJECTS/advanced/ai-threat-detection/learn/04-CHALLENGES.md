# Extension Challenges

You've built the base project. Now make it yours by extending it with new features.

These challenges are ordered by difficulty. Start with the easier ones to build confidence, then tackle the harder ones when you want to dive deeper.

## Easy Challenges

### Challenge 1: Add a New Detection Rule

**What to build:**
Add a detection rule for XML External Entity (XXE) injection attacks. XXE payloads contain strings like `<!ENTITY`, `<!DOCTYPE`, `SYSTEM "file:///`, and `xmlns:xi` in URL parameters or paths.

**Why it's useful:**
XXE (CWE-611) was in the OWASP Top 10 until 2021 when it was merged into A05:2021 Security Misconfiguration. The 2014 Facebook XXE vulnerability allowed reading arbitrary files from their servers. Any application that parses XML input from users is potentially vulnerable.

**What you'll learn:**
- How the rule engine pattern matching works
- Writing regex patterns that catch evasion variants
- Calibrating rule scores relative to existing rules

**Hints:**
- Add a compiled regex to `patterns.py` covering common XXE payloads
- Add a `_PatternRule` entry to `_PATTERN_RULES` in `rules.py` with an appropriate score (think about where XXE falls between FILE_INCLUSION at 0.75 and COMMAND_INJECTION at 0.90)
- Test with the dev-log simulator: modify `simulate.py` to generate XXE payloads

**Test it works:**
```bash
curl "http://localhost:8000/api/test?xml=%3C!DOCTYPE%20foo%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22file%3A%2F%2F%2Fetc%2Fpasswd%22%3E%5D%3E"
```
Check the dashboard for a new threat event with your rule name in the matched_rules field.

### Challenge 2: Add Request Method Anomaly Detection

**What to build:**
Add a threshold rule that fires when an IP sends an unusual mix of HTTP methods. Normal users predominantly send GET requests with occasional POSTs. An IP sending lots of PUT, DELETE, PATCH, or OPTIONS requests within 5 minutes is likely probing the API for misconfigured endpoints.

**Why it's useful:**
API enumeration attacks often use uncommon HTTP methods to discover endpoints that respond differently (returning 200 instead of 405). The 2019 First American Financial breach was partially enabled by direct object reference vulnerabilities discovered through API probing.

**What you'll learn:**
- How threshold rules use windowed features
- Working with the `WindowAggregator` Redis data
- The difference between pattern rules (regex on URI) and threshold rules (numeric conditions on features)

**Hints:**
- `method_entropy_5m` is already computed by the aggregator. An entropy above 1.5 (more than 3 distinct methods with roughly equal frequency) is suspicious for most web applications
- Add a `_ThresholdRule` in `rules.py` targeting `method_entropy_5m`
- Score it around 0.25-0.35 since this is a behavioral signal with potential for false positives on legitimate API clients

**Test it works:**
Use the dev-log simulator to send a mix of GET/POST/PUT/DELETE/OPTIONS from a single IP and verify the rule fires.

### Challenge 3: Add a Country Blocklist Feature

**What to build:**
Add a configurable list of country codes that automatically boost the threat score of requests originating from those countries. Many organizations restrict traffic from regions where they have no customers.

**Why it's useful:**
Geo-blocking is a common defense layer. The `country_code` feature already exists in the pipeline. This challenge extends it from a passive feature (used by ML models) to an active rule (directly influencing scores).

**What you'll learn:**
- How GeoIP enrichment feeds into the detection pipeline
- Adding configurable parameters via Pydantic Settings
- The tension between geographic blocking and false positives (VPNs, CDNs, traveling employees)

**Hints:**
- Add a `blocked_countries` setting in `config.py` as a comma-separated string, parsed into a `set[str]`
- Add a check in `RuleEngine.score_request` that matches the `country_code` feature against the blocklist
- Score it around 0.20-0.30 since geographic origin alone isn't a strong indicator

**Test it works:**
Set `BLOCKED_COUNTRIES=CN,RU` in `.env`, restart, and verify that requests from those country codes get a score boost.

## Intermediate Challenges

### Challenge 4: Build an Active Learning Feedback Loop

**What to build:**
Add API endpoints for analysts to mark threat events as true positives or false positives, and use those labels to automatically trigger retraining when enough new labels accumulate.

**Implementation approach:**

1. **Add review endpoints** to handle analyst feedback
   - `PATCH /threats/{id}/review` with body `{"label": "true_positive"}` or `{"label": "false_positive"}`
   - Store the label in `ThreatEvent.review_label` and set `reviewed = True`
   - Files to modify: `threats.py`, `threat_service.py`

2. **Add automatic retrain trigger**
   - Track the count of new labels since last training
   - When the count exceeds a threshold (e.g., 50 new labels), trigger retraining automatically
   - Files to create: a background task that periodically checks label counts

3. **Use labels as training data**
   - Modify the retrain endpoint to use `review_label` as ground truth instead of score-based labeling
   - `true_positive` events become attack samples, `false_positive` events become normal samples
   - Files to modify: `models_api.py`

**What you'll learn:**
- Active learning: using human feedback to iteratively improve ML models
- The cold start problem: initial labels are scarce, so the system must work with weak labels (score thresholds) until analysts provide enough real labels
- How false positive reduction directly impacts analyst trust and alert fatigue

**Hints:**
- The `reviewed` and `review_label` fields already exist on `ThreatEvent`. The infrastructure is there, you just need to wire it up
- Consider adding a `labels_since_last_train` counter to `ModelMetadata`
- Be careful with class balance: if analysts only label obvious true positives, the retraining data will be biased

**Extra credit:**
Build a simple "review queue" page in the frontend that shows unreviewed MEDIUM-severity events (the most ambiguous ones) and lets analysts click "True Positive" or "False Positive" buttons.

### Challenge 5: Add Request Body Analysis via Error Logs

**What to build:**
Extend the tailer to also watch nginx error logs, which contain request body information for failed requests. Parse the error log format and extract features from POST bodies.

**Real world application:**
Many injection attacks (SQL injection, XXE, deserialization) are delivered in POST request bodies. The access log only shows the method and path. Error logs often include the actual payload that caused the error, giving the detection system visibility into the attack content.

**What you'll learn:**
- nginx error log format (different from access log combined format)
- Extending the tailer to watch multiple files
- Feature extraction from unstructured text (request bodies contain arbitrary content)
- How the 2017 Equifax breach (CVE-2017-5638) used a Content-Type header payload that would have been visible in error logs but not access logs

**Implementation approach:**

1. **Extend the tailer**
   - Add a second `_LogHandler` instance watching the nginx error log
   - Both handlers push to the same `raw_queue` with a line prefix indicating the source (`[access]` vs `[error]`)

2. **Add an error log parser**
   - Parse the nginx error log format to extract timestamp, error level, client IP, and the error message (which often contains the request body)
   - Create a new `ParsedErrorEntry` dataclass

3. **Extract body features**
   - Compute entropy, length, and attack pattern matches on the extracted body text
   - Add these as additional features (expanding the vector beyond 35 dimensions, which means retraining)

**Hints:**
- nginx error log format: `2026/03/15 09:22:31 [error] 7#7: *1234 upstream prematurely closed connection while reading response header from upstream, client: 93.184.216.34`
- The tricky part is that error logs are much less structured than access logs. You'll need robust parsing for various error message formats
- Consider keeping access log features and error log features as separate feature sets that get concatenated

**Extra credit:**
Add a feature that correlates access log entries with error log entries by timestamp and IP, linking the full request context (from access log) with the error detail (from error log).

### Challenge 6: Add Prometheus Metrics Export

**What to build:**
Add a `/metrics` endpoint that exports pipeline statistics, detection metrics, and system health in Prometheus exposition format.

**Why it's useful:**
Production threat detection systems need monitoring. You want to know: How many requests per second is the pipeline processing? What's the detection rate by severity? Are any queues backing up? How fast is inference?

**What you'll learn:**
- Prometheus metric types (counters, gauges, histograms)
- Instrumenting async Python code without adding latency to the hot path
- The difference between monitoring the monitored system (threat metrics) and monitoring the monitoring system (pipeline health)

**Implementation approach:**

1. **Add prometheus-client dependency**
2. **Instrument the pipeline** with counters and histograms
   - `vigil_requests_processed_total` (counter by stage)
   - `vigil_threats_detected_total` (counter by severity)
   - `vigil_inference_duration_seconds` (histogram)
   - `vigil_queue_depth` (gauge per queue)
3. **Add the `/metrics` endpoint** using `generate_latest()`
4. **Add a Grafana dashboard** JSON in `infra/grafana/`

**Hints:**
- Use `time.perf_counter()` around the ONNX inference call for latency measurement
- Queue depths can be sampled periodically (every 5 seconds) via a background task rather than instrumenting every put/get
- The pipeline `stats` dict already tracks processed/error counts. Expose these as Prometheus counters

## Advanced Challenges

### Challenge 7: Add a 4th Model (Transformer)

**What to build:**
Add a small transformer encoder model to the ensemble that processes sequences of requests from the same IP (not just individual requests). This model sees the temporal ordering of requests, which the other three models don't.

**Why this is hard:**
The current models process one request at a time. A transformer needs a sequence of recent requests from the same IP as input. This means buffering recent requests per-IP, padding/truncating to a fixed sequence length, and computing attention across the sequence. The training data pipeline also needs to generate sequences, not individual samples.

**What you'll learn:**
- Transformer architecture for sequential anomaly detection
- Attention mechanisms and what they learn about request sequences
- Integrating a sequence model with per-request models in an ensemble
- How to handle variable-length sequences (padding, masking)

**Architecture changes needed:**

```
                        ┌───────────────────┐
                        │  Existing Models   │
                        │  (per-request)     │
Feature Vector ────────►│  AE + RF + IF      ├───┐
                        └───────────────────┘   │
                                                 │
                        ┌───────────────────┐   ├──► Ensemble
Recent N requests ─────►│  Transformer       │───┘    Fusion
 (from same IP)         │  (per-sequence)    │
                        └───────────────────┘
```

**Implementation steps:**

1. **Buffer recent requests per-IP** in Redis or in-memory
   - Store the last 16 feature vectors per IP
   - Pad with zeros if fewer than 16 are available

2. **Build the transformer model**
   - Small encoder-only model: 2 layers, 4 attention heads, 64 embedding dim
   - Input: (batch, seq_len=16, features=35)
   - Output: anomaly score (single float)
   - Train on sequences of normal traffic, flag sequences that contain anomalies

3. **Integrate with the ensemble**
   - Add a 4th weight (e.g., AE 0.30, RF 0.30, IF 0.15, Transformer 0.25)
   - Export to ONNX alongside the other models

4. **Update the training pipeline**
   - Generate sequence samples from the training data
   - Handle the cold start (fewer than 16 requests from a new IP)

**Gotchas:**
- The transformer's input shape is (batch, seq, features), not (batch, features). ONNX export handles this but the batch inference in the pipeline needs updating
- Attention can be expensive. Profile the inference latency carefully. A 2-layer transformer with 16 sequence length should be manageable (< 5ms per batch of 32)

**Resources:**
- Vaswani et al., "Attention Is All You Need" (2017), Section 3 for the encoder architecture
- PyTorch `nn.TransformerEncoder` documentation for implementation details

### Challenge 8: Build a Distributed Pipeline with Kafka

**What to build:**
Replace the `asyncio.Queue`-based pipeline with Apache Kafka topics. Each pipeline stage becomes a consumer group that reads from one topic and produces to the next. This removes the single-process throughput ceiling.

**Why this is hard:**
Kafka changes the concurrency model fundamentally. Currently, one Python process handles everything sequentially. With Kafka, you can run multiple parse workers, feature workers, and detection workers independently. But this introduces challenges: message ordering, exactly-once semantics, partition assignment, consumer lag monitoring, and schema evolution.

**What you'll learn:**
- Kafka producer/consumer patterns with aiokafka
- Partitioning strategies (partition by source IP for windowed features)
- Consumer groups and rebalancing
- Schema registry for evolving message formats
- How production systems like Cloudflare's WAF pipeline handle millions of requests per second

**Implementation phases:**

**Phase 1: Topic Design**
- `vigil.raw` - Raw log lines (partitioned by hash of source IP)
- `vigil.parsed` - Parsed log entries (same partition key)
- `vigil.enriched` - Enriched feature vectors
- `vigil.scored` - Final scored results for dispatch

**Phase 2: Replace Queues with Kafka**
- Swap `asyncio.Queue.put/get` with Kafka produce/consume
- Use Avro or JSON Schema for message serialization
- Maintain partition affinity by source IP so windowed features stay consistent

**Phase 3: Scale Out**
- Run 4 parse workers, 2 feature workers, 2 detection workers
- Monitor consumer lag to detect bottlenecks
- Add auto-scaling based on lag thresholds

**Phase 4: Observability**
- Add Kafka metrics to the Prometheus exporter
- Monitor consumer lag, produce latency, and partition distribution
- Build a Grafana dashboard showing pipeline throughput per stage

**Known challenges:**
1. **Windowed features require partition affinity** - All requests from the same IP must go to the same feature worker so the Redis sorted sets are consistent. Use source IP as the Kafka partition key.
2. **Exactly-once semantics** - If a detection worker crashes mid-processing, the message should be reprocessed, not lost. Use Kafka consumer offsets with manual commit after successful processing.

**Success criteria:**
- [ ] Pipeline handles 5000+ req/s sustained (10x current ceiling)
- [ ] Adding/removing workers doesn't cause data loss
- [ ] Consumer lag stays under 1000 messages during normal operation
- [ ] Partition affinity ensures windowed features are correct

## Expert Challenges

### Challenge 9: Build a Full SOAR Integration

**What to build:**
Build a Security Orchestration, Automation, and Response (SOAR) layer that automatically responds to detected threats. HIGH severity events should trigger automated responses: add the source IP to an nginx blocklist, send a Slack/Discord notification, create a ticket in a tracking system, and enrich the alert with threat intelligence from public feeds.

**Prerequisites:**
You should have completed Challenge 4 (active learning) and Challenge 6 (Prometheus metrics) first because this builds on analyst feedback workflows and monitoring infrastructure.

**What you'll learn:**
- SOAR automation patterns used in enterprise SOCs
- Playbook-driven incident response (if-this-then-that automation)
- Threat intelligence integration (AbuseIPDB, VirusTotal, Shodan)
- The risks of automated blocking (false positives lock out real users)
- How tools like Splunk SOAR and Palo Alto XSOAR implement these patterns

**Planning this feature:**

Before you code, think through:
- What actions should be fully automated vs. requiring human approval?
- How do you handle false positive automated blocks? (Answer: auto-unblock after a TTL, require analyst confirmation for permanent blocks)
- What's the blast radius if the ML model goes wrong and generates mass false positives?

**High level architecture:**

```
Scored Request (HIGH severity)
    │
    ├──► Playbook Engine
    │       │
    │       ├──► Block IP (nginx blocklist update)
    │       ├──► Notify (Slack webhook)
    │       ├──► Enrich (AbuseIPDB lookup)
    │       └──► Ticket (create incident)
    │
    └──► Audit Log (all actions recorded)
```

**Implementation phases:**

**Phase 1: Playbook Engine**
- Define playbooks as YAML files describing trigger conditions and actions
- Build a simple rule evaluator that matches scored requests to playbooks
- Log all automated actions for audit

**Phase 2: Response Actions**
- nginx blocklist: Write blocked IPs to a file that nginx includes via `deny` directive, then send SIGHUP to reload
- Slack notification: POST to a webhook URL with threat details
- AbuseIPDB enrichment: GET the IP's abuse confidence score and history

**Phase 3: Safety Rails**
- Rate limit automated blocks (max 10 IPs per hour)
- Auto-unblock after a configurable TTL (default 1 hour)
- Require analyst confirmation for blocks that affect more than N requests
- Kill switch: disable all automated responses via an API endpoint

**Phase 4: Dashboard Integration**
- Show automated response status on the threat detail page
- Display enrichment data (AbuseIPDB score, VirusTotal results)
- "Undo Block" button for analysts

**Success criteria:**
- [ ] HIGH severity events trigger automated Slack notifications within 5 seconds
- [ ] Blocked IPs are automatically unblocked after the configured TTL
- [ ] All automated actions are logged with full context
- [ ] The kill switch disables all automation within one API call
- [ ] False positive automated blocks can be reversed by analysts from the dashboard

## Mix and Match

Combine features for bigger projects:

**Project Idea 1: Full SOC Stack**
- Combine Challenge 4 (active learning) + Challenge 6 (Prometheus) + Challenge 9 (SOAR)
- Add a case management system for tracking incidents from detection to resolution
- Result: A miniature Security Operations Center in a Docker Compose stack

**Project Idea 2: Multi-Source Detection**
- Combine Challenge 5 (error logs) + Challenge 7 (transformer) + Challenge 8 (Kafka)
- Ingest from multiple log sources, use the transformer to detect multi-stage attacks that span request sequences
- Result: A distributed, multi-source threat detection platform

## Real World Integration Challenges

### Integrate with Elasticsearch and Kibana

**The goal:**
Ship all scored threat events to Elasticsearch for long term storage and build Kibana dashboards for investigation.

**What you'll need:**
- Elasticsearch 8.x cluster (can run locally via Docker)
- Kibana for visualization
- Understanding of Elasticsearch index mappings and ILM policies

**Implementation plan:**
1. Add an Elasticsearch output to the `AlertDispatcher` (parallel to PostgreSQL, not replacing it)
2. Define an index mapping that includes GeoIP fields as `geo_point` type for map visualizations
3. Build a Kibana dashboard with:
   - Threat map showing source IPs on a world map
   - Timeline of threat scores over time
   - Top attack types by rule name
   - Drill-down from severity to individual events

**Watch out for:**
- Elasticsearch bulk indexing latency can slow down the dispatch stage. Use async bulk operations with a buffer
- Index lifecycle management (ILM) to prevent unbounded storage growth. Roll indices daily and delete after 30 days

### Deploy to Kubernetes

**The goal:**
Convert the Docker Compose stack to Kubernetes manifests and deploy to a cluster.

**What you'll learn:**
- Writing Kubernetes Deployments, Services, ConfigMaps, and Secrets
- Persistent volume claims for PostgreSQL and model data
- Health probes (liveness, readiness, startup) mapped from Docker healthchecks
- Horizontal Pod Autoscaler for the backend based on queue depth metrics

**Steps:**
1. Convert each Docker Compose service to a Kubernetes Deployment
2. Create Services for internal communication (postgres, redis, backend)
3. Use a ConfigMap for non-secret configuration and Secrets for credentials
4. Create PersistentVolumeClaims for postgres data and model artifacts
5. Add an Ingress resource for frontend traffic
6. Set up HPA for the backend based on Prometheus metrics (Challenge 6)

**Production checklist:**
- [ ] All secrets are stored in Kubernetes Secrets, not ConfigMaps
- [ ] PostgreSQL uses a StatefulSet with persistent storage
- [ ] Backend readiness probe gates traffic until models are loaded
- [ ] Resource requests and limits are set for all pods
- [ ] Network policies restrict access to PostgreSQL and Redis

## Performance Challenges

### Challenge: Handle 5000 Requests Per Second

**The goal:**
Make the single-process pipeline handle 5000 req/s without dropping logs.

**Current bottleneck:**
ML inference at ~640 req/s with batch size 32. The detection stage is the ceiling.

**Optimization approaches:**

**Approach 1: Increase batch size**
- How: Set `BATCH_SIZE=128` and `BATCH_TIMEOUT_MS=100`
- Gain: Larger batches amortize ONNX session overhead. Expected 2-3x throughput
- Tradeoff: Higher latency (up to 100ms wait for a full batch vs. 50ms)

**Approach 2: Quantize the ONNX models**
- How: Use ONNX Runtime's quantization tools to convert float32 models to int8
- Gain: 2-4x inference speedup on CPU with minimal accuracy loss
- Tradeoff: Small accuracy degradation, especially for the autoencoder. Validate with the quality gates

**Approach 3: Skip ML inference for clearly benign traffic**
- How: If the rule engine scores 0.0 (no rules matched), skip ML inference and output the rule score directly
- Gain: 90-95% of traffic is benign, so this skips inference for most requests
- Tradeoff: You lose ML-only detections (anomalies that don't match any rule). Acceptable if rule coverage is good

**Benchmark it:**
```bash
just devlog-simulate normal 10000 -d 0.0001
```

Target metrics:
- Throughput: 5000+ req/s sustained
- Queue depths: raw_queue never full
- p99 latency: < 200ms end-to-end

### Challenge: Reduce Memory Footprint

**The goal:**
Run the entire stack on a 2GB RAM machine (currently needs 4GB+).

**Profile first:**
```bash
docker stats --no-stream
```

**Common optimization areas:**
- ONNX models: 50-200MB. Quantization (int8) reduces this by 2-4x
- GeoIP database: ~60MB mmap'd. Switch to the smaller GeoLite2-Country (~5MB) if city-level precision isn't needed
- PostgreSQL: Reduce `shared_buffers` and `work_mem` in `postgresql.conf`
- Redis: Set `maxmemory 64mb` with `allkeys-lru` eviction to cap memory usage

## Security Challenges

### Challenge: Add TLS Mutual Authentication for the API

**What to implement:**
Require client certificates for API access instead of (or in addition to) the X-API-Key header.

**Threat model:**
This protects against:
- API key theft (the key is a static string that could be leaked in logs, config files, or commit history)
- Replay attacks (a stolen API key can be used from any network location)

**Implementation:**
- Generate a CA certificate, server certificate, and client certificate using `openssl`
- Configure uvicorn to require client certificates (or put nginx in front of the backend with `ssl_verify_client on`)
- Validate the client certificate's subject CN against an allowlist

**Testing the security:**
- Try to hit the API without a client certificate (should get 403)
- Try with a certificate signed by a different CA (should get 403)
- Verify that certificate rotation works (issue new certs, old ones still work until revoked)

### Challenge: Pass CIS Docker Benchmark

**The goal:**
Make the Docker Compose stack compliant with the CIS Docker Benchmark.

**Current gaps:**
- Containers run as root (add `USER` directives to Dockerfiles)
- No resource limits (add `mem_limit` and `cpus` to compose.yml)
- No read-only root filesystem (add `read_only: true` where possible)
- No security options (add `security_opt: [no-new-privileges:true]`)

**Remediation:**
Run `docker-bench-security` against the stack and address each finding. Focus on the host configuration, daemon configuration, and container runtime sections.

## Contribution Ideas

Finished a challenge? Share it back:

1. **Fork the repo**
2. **Implement your extension** in a new branch
3. **Document it** in this learn folder
4. **Submit a PR** with:
   - Your implementation
   - Tests
   - Updated learn documentation
   - Example output showing it works

Good extensions might get merged into the main project.

## Challenge Yourself Further

### Build Something New

Use the concepts you learned here to build:
- A **network traffic anomaly detector** that analyzes pcap files instead of HTTP logs, using the same ensemble approach but with network-layer features (packet sizes, protocol distribution, connection patterns)
- A **DNS threat detector** that monitors DNS query logs for tunneling, DGA domains, and anomalous resolution patterns
- A **container runtime anomaly detector** that watches syscall traces from Falco and flags unusual process behavior

### Study Real Implementations

Compare your implementation to production tools:
- **Suricata** - Open source IDS/IPS. Look at how their rule engine handles signature matching at wire speed. Their multi-threaded architecture handles 10 Gbps+
- **Elastic ML** - Elasticsearch's anomaly detection module. Compare their time-series decomposition approach with our autoencoder approach
- **AWS GuardDuty** - Amazon's managed threat detection. Read their documentation on how they combine ML, threat intelligence, and behavioral analysis

Read their code (Suricata is open source), understand their tradeoffs, steal their good ideas.

### Write About It

Document your extension:
- Blog post explaining what you built and what you learned about threat detection
- Comparison between rule-based and ML-based detection approaches using concrete examples from your experience with this project
- Analysis of false positive rates at different ensemble weight configurations

Teaching others is the best way to verify you understand it.

## Getting Help

Stuck on a challenge?

1. **Debug systematically**
   - What did you expect to happen?
   - What actually happened?
   - What's the smallest test case that reproduces it?

2. **Read the existing code**
   - The rule engine in `rules.py` shows the pattern for adding detection logic
   - The pipeline in `pipeline.py` shows how stages communicate
   - The orchestrator in `orchestrator.py` shows the full training flow

3. **Search for similar problems**
   - FastAPI async patterns: fastapi.tiangolo.com
   - ONNX Runtime issues: github.com/microsoft/onnxruntime
   - Redis sorted set patterns: redis.io/docs/data-types/sorted-sets

4. **Ask for help**
   - Post in GitHub Discussions
   - Include: what you tried, what happened, what you expected
   - Show the relevant code and error messages, not just the stack trace

## Challenge Completion

Track your progress:

- [ ] Easy 1: Add XXE detection rule
- [ ] Easy 2: Add method anomaly detection
- [ ] Easy 3: Add country blocklist
- [ ] Intermediate 4: Build active learning feedback loop
- [ ] Intermediate 5: Add error log analysis
- [ ] Intermediate 6: Add Prometheus metrics
- [ ] Advanced 7: Add transformer model
- [ ] Advanced 8: Build Kafka distributed pipeline
- [ ] Expert 9: Build SOAR integration

Completed all of them? You've mastered this project. Time to build something new or contribute back to the community.
