# Extension Challenges

You've built the base project. Now make it yours by extending it with new features.

These challenges are ordered by difficulty. Start with the easier ones to build confidence, then tackle the harder ones when you want to dive deeper.

## Easy Challenges

### Challenge 1: Add a Telnet Honeypot

**What to build:**
A Telnet service at `internal/telnetd/` that accepts connections on port 2323, performs IAC option negotiation, presents a login prompt, and drops into a fake shell reusing `sshd`'s `FakeFS` and `DispatchCommand`.

**Why it's useful:**
Telnet remains one of the most targeted protocols on the internet. Mirai and its variants scan for Telnet on port 23 by default. The SANS Internet Storm Center reports Telnet brute force attempts rivaling SSH in volume, particularly against IoT devices. Having both SSH and Telnet honeypots lets you compare attack tooling across the two protocols.

**What you'll learn:**
- Telnet IAC (Interpret As Command) option negotiation
- Reusing existing components across services

**Hints:**
- Telnet negotiation is simple: send `IAC WILL ECHO`, `IAC WILL SUPPRESS_GO_AHEAD`, `IAC WONT LINEMODE` at connect time, then strip IAC sequences from incoming data
- Reuse `sshd.FakeFS` and `sshd.DispatchCommand` directly, they have no SSH-specific dependencies
- The `session.Recorder` works the same way since Telnet and SSH both produce raw terminal I/O

**Test it works:**
`telnet localhost 2323` should present a login prompt, accept any credentials, and let you run commands like `ls`, `whoami`, and `cat /etc/passwd` with the same fake output as the SSH honeypot.

### Challenge 2: Add GeoIP Enrichment to the Dashboard Map

**What to build:**
Download the free MaxMind GeoLite2 database and wire up `internal/geo/lookup.go` to return real coordinates, countries, and ASN information for each source IP. The attack map in the dashboard already renders markers from `geo` data in the events; this challenge makes those markers appear at correct locations instead of zeroed-out coordinates.

**Why it's useful:**
Geographic attack distribution is one of the first things SOC teams look at when analyzing honeypot data. GreyNoise publishes daily reports showing that scanning activity concentrates in specific ASNs and countries. Real GeoIP data lets you correlate source regions with attack types.

**What you'll learn:**
- MaxMind GeoLite2 MMDB binary format
- IP geolocation accuracy limitations (city-level is ~50km radius for most IPs)

**Hints:**
- Sign up for a free MaxMind account to get a license key for GeoLite2-City and GeoLite2-ASN downloads
- `internal/geo/lookup.go` already has the `Resolve(ip)` signature and `GeoInfo` return type; you need to replace the zero-value return with an actual MMDB lookup
- The `oschwald/maxminddb-golang` package is already in `go.mod`
- For Docker, add a `geoip-updater` init container that downloads the database on first start

**Test it works:**
Connect to the SSH honeypot from a machine with a public IP (or use a VPN). The dashboard attack map should show a marker at the correct geographic location. The event detail should display country, city, and ASN fields.

### Challenge 3: Add Credential Analytics

**What to build:**
A new API endpoint `GET /api/stats/credentials/trending` that tracks which username/password combinations are growing in frequency over time. Store credential attempt counts per hour in PostgreSQL and return the top 10 fastest-growing pairs over the last 24 hours.

**Why it's useful:**
When a new credential list hits the botnet ecosystem, honeypots see a sudden spike in specific username/password combinations. In 2023, the emergence of the Kaiten botnet variant brought a new default credential list targeting Hikvision DVRs (`admin/12345`, `admin/888888`). Trending credential analysis catches these shifts in real time.

**What you'll learn:**
- Time-series aggregation in PostgreSQL with `date_trunc`
- Growth rate calculation using window functions

**Hints:**
- Add a `credential_hourly` materialized view or table that aggregates `(username, password, hour, count)` from the credentials table
- Growth rate: compare the current 6-hour window to the previous 6-hour window, rank by the ratio
- The frontend `CredentialStats` type already exists; extend it or add a new type

**Test it works:**
Run Hydra against the SSH honeypot with a custom wordlist. The trending endpoint should show those specific username/password pairs rising in the rankings within minutes.

## Intermediate Challenges

### Challenge 4: Add an SMTP Honeypot

**What to build:**
An SMTP service at `internal/smtpd/` that implements enough of RFC 5321 to accept email delivery. Handle EHLO, MAIL FROM, RCPT TO, DATA, and QUIT commands. Capture the full email including headers and body. Extract sender addresses, recipient addresses, and any URLs or attachments from the message body.

**Real world application:**
Compromised servers are frequently used as spam relays. Attackers scan for open SMTP relays, test credential stuffing against mail servers, and use honeypot mail servers as test targets before launching phishing campaigns. SMTP honeypots capture phishing email templates, malware-laden attachments, and the infrastructure behind spam campaigns.

**What you'll learn:**
- SMTP protocol state machine (RFC 5321)
- Email MIME parsing for attachment and URL extraction
- IOC extraction from email content (sender domains, embedded URLs, attachment hashes)

**Implementation approach:**

1. **Create the SMTP protocol handler**
   - Files to create: `internal/smtpd/server.go`, `internal/smtpd/commands.go`
   - Implement a line-based state machine: INIT → EHLO → MAIL → RCPT → DATA → DONE

2. **Extract IOCs from captured emails**
   - Pull sender domain, all URLs in the body, and SHA-256 hashes of attachments
   - Publish IOC events to the bus for the intel layer to pick up

3. **Test edge cases:**
   - What if the client sends STARTTLS? (respond with 454 and continue plaintext)
   - How do you handle multi-part MIME messages with nested attachments?

**Hints:**
- SMTP is text-based like FTP; the `ftpd` package is a good structural reference
- The DATA phase ends with a line containing only `.` (RFC 5321 Section 4.5.2)
- Capture the raw email to disk (capped at 5MB) and publish a file event

**Extra credit:**
Parse the `Received:` headers to trace the email's path through relays. Extract the originating IP and add it as an IOC.

### Challenge 5: Session Threat Scoring

**What to build:**
A scoring engine that assigns a threat score (0-100) to each session based on the commands executed, MITRE techniques detected, duration, and credential attempts. Store the score on the Session record and expose it in the API.

**Real world application:**
SOC teams triaging honeypot data need to prioritize which sessions to investigate first. A session where the attacker just connected and disconnected is less interesting than one where they ran discovery commands, downloaded tools, and set up persistence. Automated scoring lets analysts focus on the high-value sessions.

**What you'll learn:**
- Weighted scoring algorithms
- Real-time score updates using the event bus

**Implementation approach:**

1. **Define scoring weights**
   - Authentication event: +5 per attempt (brute force contributes heavily)
   - Discovery commands (uname, id, cat /etc/passwd): +10 each
   - Tool transfer (wget, curl to external URL): +20
   - Persistence (crontab, systemd): +25
   - MITRE technique detected: +15 per unique technique
   - Session duration beyond 30 seconds: +10

2. **Integrate with the session tracker**
   - Update the score in `session.Tracker` on each event
   - Store the final score when `End()` is called
   - Add `min_score` query parameter to `GET /api/sessions`

3. **Add a dashboard indicator**
   - Color-code session rows: green (0-25), yellow (26-50), orange (51-75), red (76-100)

**Hints:**
- Cap the score at 100 to prevent runaway values from long brute force sessions
- The `session.Tracker` already has `AddTechnique()`; use a similar pattern for `AddScore(points int)`
- Consider normalizing brute force scores: 100 login attempts should not score 500

**Extra credit:**
Train a simple logistic regression model on labeled session data (manually tag 50 sessions as benign/suspicious/malicious) and compare its rankings to the heuristic scorer.

### Challenge 6: Real-time Alerting via Webhooks

**What to build:**
A webhook notification system that sends POST requests to configured URLs when specific conditions are met: high-threat sessions, brute force detection, tool download attempts, or new MITRE techniques observed.

**Real world application:**
Production honeypots need to alert security teams in real time. Integrating with Slack, PagerDuty, or a SIEM via webhooks turns the honeypot from a passive data collector into an active detection system. Deutsche Telekom's T-Pot platform sends honeypot alerts directly to their SOC dashboard through a similar mechanism.

**What you'll learn:**
- Webhook delivery with retry logic and exponential backoff
- Alert deduplication to prevent notification floods
- Fan-out from the event bus to external systems

**Implementation approach:**

1. **Add webhook configuration**
   - Files to create: `internal/alert/webhook.go`, `internal/alert/rules.go`
   - Config: URL, secret (for HMAC signing), event types to trigger on, cooldown period

2. **Implement alert rules**
   - Subscribe to the event bus with topic filters
   - Evaluate conditions: brute force threshold, tool transfer detected, session score above N
   - Deduplicate: same IP + same rule = one alert per cooldown period

3. **Send webhooks**
   - POST JSON payload with event details, session context, and MITRE mappings
   - HMAC-SHA256 signature in the `X-Hive-Signature` header
   - Retry 3 times with exponential backoff (1s, 4s, 16s)

**Hints:**
- Use a buffered channel and a dedicated goroutine for webhook delivery, same pattern as the event processor
- The HMAC signing follows the same pattern as GitHub webhook signatures
- Add a `GET /api/alerts` endpoint to show recent alerts in the dashboard

**Extra credit:**
Add a Slack-specific formatter that sends rich block-kit messages with attacker IP, country, commands executed, and a link to the session replay.

## Advanced Challenges

### Challenge 7: Multi-Sensor Deployment

**What to build:**
Support for running multiple Hive instances that report to a central aggregation server. Each sensor registers with the central server, sends events over gRPC, and the central server stores and correlates data across all sensors.

**Why this is hard:**
This transforms Hive from a single-node tool into a distributed system. You need to handle sensor registration, heartbeats, event delivery guarantees, clock synchronization for cross-sensor correlation, and a unified dashboard view across all sensors.

**What you'll learn:**
- gRPC service definitions and streaming RPCs
- Distributed system coordination (registration, heartbeats, failure detection)
- Cross-sensor attack correlation

**Architecture changes needed:**

```
  Sensor A (SSH, HTTP)      Sensor B (FTP, MySQL)     Sensor C (SMB, Redis)
       │                         │                          │
       └─── gRPC stream ────────┼──── gRPC stream ─────────┘
                                 │
                        ┌────────▼────────┐
                        │  Central Server  │
                        │  ┌────────────┐  │
                        │  │ Correlator │  │
                        │  │ Store      │  │
                        │  │ Dashboard  │  │
                        │  └────────────┘  │
                        └──────────────────┘
```

**Implementation steps:**

1. **Research phase**
   - Read about gRPC bidirectional streaming in Go
   - Understand the trade-offs between push (sensor → central) vs pull (central → sensor)
   - Look at how Elastic Agent and Wazuh agent architectures handle multi-sensor coordination

2. **Design phase**
   - Define protobuf messages for sensor registration, event streaming, and heartbeat
   - Decide on event delivery semantics: at-least-once (with dedup) vs at-most-once
   - Plan how the dashboard distinguishes events from different sensors

3. **Implementation phase**
   - Start with a minimal `hive agent` mode that forwards events over gRPC
   - Add a `hive central` mode that receives, stores, and serves the dashboard
   - Add cross-sensor correlation: same attacker IP hitting multiple sensors within a time window

4. **Testing phase**
   - Run three local instances on different ports
   - Simulate an attacker scanning all three
   - Verify the central dashboard shows a unified attacker timeline

**Gotchas:**
- Clock drift between sensors: use the central server's timestamp for ordering, not the sensor's
- Network partitions: buffer events locally when the central server is unreachable, replay on reconnect

**Resources:**
- gRPC Go tutorial and bidirectional streaming examples
- Wazuh agent architecture documentation for real-world multi-sensor design patterns

### Challenge 8: SIEM Integration Pipeline

**What to build:**
Export honeypot events in formats consumable by major SIEM platforms: Elastic Common Schema (ECS) for Elasticsearch, Common Event Format (CEF) for ArcSight/QRadar, and syslog (RFC 5424) for any syslog collector.

**Why this is hard:**
Each SIEM has its own event schema, field naming conventions, and transport requirements. ECS uses nested JSON with specific field names like `source.ip`, `event.category`, and `threat.technique.id`. CEF uses a pipe-delimited header with key=value extensions. Getting the field mapping right determines whether the events actually show up correctly in SIEM dashboards and correlation rules.

**What you'll learn:**
- Elastic Common Schema (ECS) field mapping
- CEF and syslog event formatting
- Streaming event export via Redis Streams or Kafka

**Architecture changes needed:**

```
  Event Bus ─── Processor ─── Store (PostgreSQL)
                    │
                    ├── Redis Stream (existing)
                    │
                    ├── ECS Formatter ──→ Elasticsearch
                    ├── CEF Formatter ──→ Syslog/QRadar
                    └── Syslog Formatter ──→ rsyslog/Splunk
```

**Implementation steps:**

1. **Research phase**
   - Read the ECS field reference, focusing on `event.*`, `source.*`, `destination.*`, and `threat.*` field sets
   - Read the CEF specification (ArcSight Common Event Format)
   - Understand how syslog structured data (RFC 5424 SD-ELEMENT) works

2. **Design phase**
   - Map each Hive `EventType` to ECS categories and CEF event class IDs
   - Decide transport: HTTP bulk API for Elasticsearch, UDP/TCP for syslog, Kafka for high-volume
   - Plan configuration: users should pick their SIEM and provide connection details

3. **Implementation phase**
   - Create `internal/export/ecs.go`, `internal/export/cef.go`, `internal/export/syslog.go`
   - Add an `Exporter` interface that the processor calls after persistence
   - Make exporters configurable in the YAML config

4. **Testing phase**
   - Stand up an Elasticsearch container and verify events appear in Kibana
   - Send CEF to a syslog collector and verify field parsing
   - Load test: 1000 events/second should not back-pressure the processor

**Gotchas:**
- ECS requires specific `event.kind` values: `event` for normal events, `alert` for MITRE detections
- CEF has a 1023-byte limit per syslog message; truncate `serviceData` if needed
- Elasticsearch bulk API returns per-item status; handle partial failures

**Resources:**
- Elastic Common Schema reference documentation
- ArcSight CEF Developer Guide (HPE/Micro Focus)
- RFC 5424 (The Syslog Protocol)

## Expert Challenges

### Challenge 9: ML-Based Anomaly Detection

**What to build:**
A machine learning layer that detects anomalous attacker behavior by learning normal patterns from historical honeypot data. Train an autoencoder on session feature vectors (command sequences, timing patterns, protocol usage) and flag sessions that deviate significantly from learned patterns.

**Prerequisites:**
You should have completed Challenge 5 (Session Threat Scoring) first because this builds on session-level feature extraction.

**What you'll learn:**
- Feature engineering from security event data
- Autoencoder architecture for anomaly detection
- Online learning from streaming data
- Integrating Python ML models with a Go backend

**Planning this feature:**

Before you code, think through:
- How does this affect the event processing pipeline latency?
- What features are most discriminative for session anomaly detection?
- How do you handle cold start (no training data on first deployment)?
- What happens when the model drifts as attack patterns change?

**High level architecture:**

```
  Event Processor
       │
       ├── Existing: GeoIP → MITRE → Store → Stream
       │
       └── New: Feature Extractor
                    │
              ┌─────▼──────┐
              │  Session    │
              │  Features   │
              │  (vector)   │
              └─────┬──────┘
                    │
           ┌────────▼────────┐
           │   ML Service    │
           │  (Python/ONNX)  │
           │                 │
           │  Autoencoder    │
           │  Reconstruction │
           │  Error → Score  │
           └────────┬────────┘
                    │
              anomaly_score
              stored on Session
```

**Implementation phases:**

**Phase 1: Feature Engineering**
- Extract per-session features: command count, unique commands, session duration, bytes transferred, number of auth attempts, number of unique MITRE techniques, time between commands (mean/std), presence of tool transfer, presence of persistence
- Normalize features to [0, 1] range using min-max scaling from training data statistics

**Phase 2: Model Training**
- Build an autoencoder in PyTorch: encoder (input → 32 → 16 → 8), decoder (8 → 16 → 32 → input)
- Train on completed sessions from the first week of deployment
- Export to ONNX for inference

**Phase 3: Integration**
- Create a Python microservice that loads the ONNX model and exposes a gRPC or HTTP scoring endpoint
- Call the scoring endpoint from the Go event processor when a session ends
- Store the anomaly score on the Session record
- Add an `anomaly_score` field to the API and dashboard

**Phase 4: Continuous Learning**
- Retrain weekly on accumulated session data
- Track reconstruction error distribution over time to detect model drift
- Alert when the anomaly rate exceeds a threshold (possible new attack pattern)

**Known challenges:**

1. **Cold start problem**
   - Problem: No training data on first deployment
   - Hint: Start with rule-based scoring (Challenge 5) and switch to ML after collecting 1000+ sessions. Ship a pre-trained model from publicly available Cowrie honeypot datasets as a starting point.

2. **Class imbalance**
   - Problem: Most honeypot sessions are similar (brute force bots). Genuinely novel sessions are rare.
   - Hint: Autoencoders naturally handle this since they learn the common pattern. High reconstruction error means "unusual," not necessarily "malicious." Combine the anomaly score with the MITRE detection count for final classification.

3. **Feature drift**
   - Problem: Attack patterns shift over months. A model trained in January may not flag new techniques appearing in June.
   - Hint: Track the mean reconstruction error per week. If it trends upward, the model needs retraining. Implement automated retraining triggered by drift detection.

**Success criteria:**
Your implementation should:
- [ ] Extract at least 10 features per session
- [ ] Train an autoencoder that achieves < 0.05 mean reconstruction error on normal sessions
- [ ] Flag sessions with tool downloads or persistence as high-anomaly (reconstruction error > 2 standard deviations)
- [ ] Score a session in < 10ms (ONNX inference)
- [ ] Handle cold start gracefully (fall back to rule-based scoring)
- [ ] Retrain without downtime (hot-swap the model file)

### Challenge 10: Attacker Playbook Reconstruction

**What to build:**
An analysis engine that reconstructs the full attack narrative from a session: what the attacker was trying to achieve, which techniques they used in which order, and how their session compares to known attack playbooks (Mirai, Muhstik, XMRig dropper, Mozi, etc.).

**Prerequisites:**
You should have completed Challenge 5 (Session Threat Scoring) and have MITRE detection working. Familiarity with the MITRE ATT&CK framework at the tactic level is essential.

**What you'll learn:**
- Attack sequence modeling and tactic chain analysis
- Pattern matching against known threat actor playbooks
- Automated report generation

**Planning this feature:**

Before you code, think through:
- How do you define a "playbook" in a way that's flexible enough to match variant behaviors?
- What granularity of matching is useful? Exact command match? Technique sequence? Tactic order?
- How do you handle partial matches (attacker completed 3 of 5 steps)?

**High level architecture:**

```
  Completed Session
       │
       ▼
  ┌─────────────┐
  │  Technique   │
  │  Sequence    │
  │  Extractor   │
  └──────┬──────┘
         │
    [T1110, T1082, T1105, T1053.003]
         │
  ┌──────▼──────┐     ┌──────────────────┐
  │  Playbook   │◄────│  Known Playbooks │
  │  Matcher    │     │  (Mirai, Muhstik │
  │             │     │   XMRig, Mozi)   │
  └──────┬──────┘     └──────────────────┘
         │
  ┌──────▼──────┐
  │  Narrative  │
  │  Generator  │
  │             │
  │  "Attacker  │
  │   performed │
  │   brute     │
  │   force..." │
  └─────────────┘
```

**Implementation phases:**

**Phase 1: Playbook Definitions**
- Define 5-10 known attack playbooks as ordered sequences of MITRE technique IDs
- Mirai: T1110 → T1082 → T1105 → T1053.003 (brute force → discovery → download bot → cron persistence)
- XMRig dropper: T1110 → T1105 → T1496 (brute force → download miner → resource hijacking)
- Include branching paths: attackers may skip steps or perform them out of order

**Phase 2: Sequence Matching**
- Implement subsequence matching with tolerance for missing/reordered steps
- Score matches as a percentage of the playbook completed
- Handle multiple partial matches (session might match 60% Mirai and 40% XMRig)

**Phase 3: Narrative Generation**
- Template-based report: "This session matches the [Mirai] playbook with [80%] confidence. The attacker performed brute force authentication (T1110), system discovery (T1082), and downloaded a payload from [url] (T1105). The session did not reach the persistence phase."
- Include a timeline view: timestamp + command + MITRE technique + tactic

**Phase 4: API and Dashboard**
- Add `GET /api/sessions/{id}/playbook` endpoint
- Add a "Playbook" tab to the session detail page showing the matched playbook, confidence score, completed/remaining steps, and the narrative summary

**Known challenges:**

1. **Sequence flexibility**
   - Problem: Attackers rarely follow playbooks exactly. They may run commands in different orders, use different tool names for the same technique, or skip steps.
   - Hint: Use technique IDs (not commands) for matching, and allow gaps in the sequence. A "longest common subsequence" approach handles reordering.

2. **Multiple matches**
   - Problem: A session may partially match several playbooks.
   - Hint: Rank by completion percentage and present the top 3 matches.

**Success criteria:**
Your implementation should:
- [ ] Define at least 5 known attack playbooks
- [ ] Match sessions to playbooks with completion percentage
- [ ] Generate readable narrative summaries
- [ ] Display playbook analysis in the dashboard
- [ ] Handle sessions that do not match any known playbook (classify as "novel")

## Real World Integration Challenges

### Deploy to a VPS

**The goal:**
Get Hive running on a public-facing VPS to capture real attacker traffic.

**What you'll learn:**
- Production deployment with Docker Compose
- Firewall configuration for honeypot ports
- Log management and disk space monitoring

**Steps:**
1. Provision a $5-10/month VPS (DigitalOcean, Vultr, Hetzner)
2. Configure firewall: allow honeypot ports (22, 80, 21, 445, 3306, 6379) from anywhere, restrict dashboard port (3000) to your IP only
3. Move the real SSH service to a non-standard port (e.g., 22222) before starting the honeypot on port 22
4. Deploy with `docker compose up -d`
5. Set up log rotation and disk monitoring (honeypot data grows fast)

**Production checklist:**
- [ ] Real SSH moved to non-standard port with key-only auth
- [ ] Dashboard accessible only from your IP (firewall rule)
- [ ] Automated database backup (pg_dump cron job)
- [ ] Disk usage alerts (warn at 80%, critical at 90%)
- [ ] Log rotation for Docker container logs
- [ ] Automatic restart on crash (Docker restart policy: unless-stopped)

**Watch out for:**
- Do NOT run the honeypot on port 22 while your real SSH is still there. You will lock yourself out.
- Some VPS providers prohibit honeypots in their TOS. Check before deploying.
- Expect 10,000+ events per day on a public IP. Plan storage accordingly.

### Integrate with OpenCTI

**The goal:**
Feed Hive's STIX bundles into an OpenCTI instance for threat intelligence correlation.

**What you'll need:**
- OpenCTI instance (Docker deployment or cloud)
- OpenCTI API token with write permissions
- Understanding of STIX 2.1 object types

**Implementation plan:**
1. Configure an OpenCTI connector that periodically exports STIX bundles via `GET /api/iocs/export/stix`
2. POST the STIX bundle to OpenCTI's STIX import endpoint
3. Map Hive's confidence scores to OpenCTI's confidence scale
4. Create OpenCTI labels for honeypot-sourced data

**Watch out for:**
- OpenCTI deduplicates by STIX ID. Hive generates random UUID v4 identifiers, so re-exporting the same IOC list produces a new bundle with different IDs — OpenCTI will create duplicate objects. For true idempotency, switch the STIX generator to UUID v5 with a fixed namespace seeded by `ioc.Type + ":" + ioc.Value`, giving the same ID for the same IOC on every export.
- Large bundles (1000+ indicators) should be split into batches of 100 for OpenCTI's import API.
- Rate limits on the OpenCTI API: add a 1-second delay between batch submissions.

## Performance Challenges

### Handle 10,000 Events Per Second

**The goal:**
Make Hive sustain 10,000 events per second from concurrent brute force attacks across all six services without dropping events or degrading attacker responsiveness.

**Current bottleneck:**
The event processor's worker pool (4 goroutines) handles GeoIP lookup, MITRE detection, up to five sequential PostgreSQL writes (events, detections, credentials, attacker upsert, IOC upsert), and Redis publish per event. At roughly 2–5ms per event depending on how many write paths fire, the ceiling is around 800–2,000 events/second across all workers.

**Optimization approaches:**

**Approach 1: Batch database inserts**
- How: Buffer events for 100ms or 100 events (whichever comes first), then batch INSERT
- Gain: PostgreSQL handles batch inserts 10-20x more efficiently than individual inserts
- Tradeoff: Up to 100ms delay before events appear in the database

**Approach 2: Increase worker pool size**
- How: Make worker count configurable, default to `runtime.NumCPU()`
- Gain: Linear scaling up to the database connection pool limit
- Tradeoff: More database connections, potential for connection exhaustion

**Approach 3: Async GeoIP with cache**
- How: Cache GeoIP results in an LRU cache (most attackers send hundreds of events from the same IP)
- Gain: Eliminates redundant MMDB lookups for repeated IPs
- Tradeoff: Cache memory usage (~100 bytes per entry, negligible for 10k IPs)

**Benchmark it:**
```bash
for i in $(seq 1 100); do
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        root@localhost -p 2222 &
done
```

Target metrics:
- Event processing latency: < 5ms p99
- Dashboard WebSocket lag: < 100ms from event to browser
- Zero dropped events in the processor pipeline

## Security Challenges

### Harden the Honeypot Against Escape

**What to implement:**
Defense-in-depth measures that prevent an attacker from using the honeypot as a pivot point or discovering it is a honeypot.

**Threat model:**
This protects against:
- Attackers using the honeypot's outbound network access to scan other hosts
- Fingerprinting the honeypot through timing analysis or missing system behaviors
- Resource exhaustion (fork bombs, memory floods)

**Implementation:**
1. Network isolation: Configure Docker network rules to block outbound connections from the backend container (except to PostgreSQL and Redis)
2. Resource limits: Set CPU and memory limits in `compose.yml` for the backend container
3. Anti-fingerprint: Add random delays (10-50ms) to command responses to prevent timing-based honeypot detection
4. Connection limits: Cap concurrent connections per service (e.g., 50 SSH, 100 HTTP)

**Testing the security:**
- Try to `ping` or `curl` an external host from within the SSH honeypot shell (should appear to work but produce no actual network traffic)
- Run a fork bomb in the SSH shell and verify the container survives
- Use `honeypot-detector` tools (shodan honeyscore, honeypot-hunter) against the running instance

## Study Real Implementations

Compare your implementation to production tools:
- **Cowrie** (Python SSH/Telnet honeypot) — Study their command emulation depth and session replay format
- **T-Pot** (Deutsche Telekom multi-honeypot platform) — Study their Docker orchestration and ELK integration
- **HoneyDB** (community honeypot data aggregation) — Study their API design for sharing threat intelligence across sensors
- **Dionaea** (C-based multi-protocol honeypot) — Study their approach to capturing malware binaries and SMB exploitation

Read their code, understand their tradeoffs, steal their good ideas.

## Challenge Completion

Track your progress:

- [ ] Easy 1: Telnet Honeypot
- [ ] Easy 2: GeoIP Enrichment
- [ ] Easy 3: Credential Analytics
- [ ] Intermediate 4: SMTP Honeypot
- [ ] Intermediate 5: Session Threat Scoring
- [ ] Intermediate 6: Webhook Alerting
- [ ] Advanced 7: Multi-Sensor Deployment
- [ ] Advanced 8: SIEM Integration Pipeline
- [ ] Expert 9: ML-Based Anomaly Detection
- [ ] Expert 10: Attacker Playbook Reconstruction
