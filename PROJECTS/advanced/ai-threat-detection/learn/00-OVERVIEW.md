# AngelusVigil: AI Threat Detection

## What This Is

AngelusVigil is a real-time threat detection engine that analyzes nginx web server logs using a 3-model ML ensemble (autoencoder + random forest + isolation forest) to classify HTTP traffic as benign or malicious. It deploys as a dockerized sidecar alongside any nginx-based infrastructure with zero code changes required. The system processes logs through a 4-stage async pipeline, extracts 35-dimensional feature vectors, scores traffic using both rule-based and ML detection, and surfaces alerts through a React dashboard with live WebSocket updates.

## Why This Matters

Web application firewalls (WAFs) catch known attack patterns, but they miss novel attacks and struggle with behavioral anomalies. In the 2017 Equifax breach (CVE-2017-5638), attackers exploited an Apache Struts vulnerability that signature-based tools missed for months. The 2021 Log4Shell vulnerability (CVE-2021-44228) spread across millions of servers before WAF rules were updated. The Capital One breach in 2019 involved a misconfigured WAF that an insider exploited to exfiltrate 100 million customer records.

ML-based detection fills these gaps by learning what "normal" looks like for your specific traffic and flagging deviations. This project builds that system from scratch.

**Real world scenarios where this applies:**
- A SaaS platform running nginx as a reverse proxy wants to detect SQL injection, path traversal, and credential stuffing without buying a commercial WAF
- A DevSecOps team needs real time alerting when attack patterns spike against their API endpoints, with enough context (GeoIP, feature vectors, matched rules) to triage quickly
- A security team wants to combine signature based detection (day 0 coverage) with ML models that improve over time as they label true/false positives from production traffic

## What You'll Learn

This project teaches you how ML-powered threat detection works at the infrastructure level. By building it yourself, you'll understand:

**Security Concepts:**
- Anomaly detection using autoencoders trained exclusively on normal traffic, so anything the model can't reconstruct well is suspicious
- Ensemble learning where multiple models vote on whether a request is malicious, reducing false positives from any single model
- Cold-start detection using ModSecurity CRS-inspired rules that provide immediate coverage before ML models are trained
- Feature engineering for HTTP traffic, turning raw log lines into 35-dimensional numeric vectors that capture request structure, behavioral patterns, and temporal signals

**Technical Skills:**
- Building async data pipelines with backpressure using `asyncio.Queue` and poison-pill shutdown propagation
- Training and exporting PyTorch and scikit-learn models to ONNX format for fast CPU inference
- Implementing sliding window aggregation with Redis sorted sets for per-IP behavioral features
- Writing a Watchdog-based file tailer that handles nginx log rotation without missing lines

**Tools and Techniques:**
- ONNX Runtime for cross-framework model serving (27% faster than native PyTorch inference)
- MLflow experiment tracking for model versioning and metric logging
- Redis pub/sub for real-time WebSocket relay across multiple backend workers
- Docker Compose orchestration of a 5-service production stack

## Prerequisites

Before starting, you should understand:

**Required knowledge:**
- Python async/await (you'll work with `asyncio.Queue`, `asyncio.Task`, and async context managers throughout the pipeline)
- Basic machine learning concepts (what training/inference means, what loss functions do, the difference between supervised and unsupervised learning)
- HTTP fundamentals (request methods, status codes, query strings, headers, how nginx access logs are structured)
- Docker and Docker Compose (the entire system runs as containers)

**Tools you'll need:**
- Docker and Docker Compose v2
- Python 3.13+ (the backend uses modern type syntax like `dict[str, float]` and `X | None`)
- Node.js 20+ and pnpm (for the React frontend)
- just (command runner, like make but better)
- uv (Python package manager)

**Helpful but not required:**
- Experience with FastAPI or any async Python web framework
- Familiarity with PyTorch or scikit-learn
- Understanding of Redis data structures (sorted sets, pub/sub)

## Quick Start

Get the project running locally:

```bash
cd PROJECTS/advanced/ai-threat-detection

# Install just if you don't have it
# https://github.com/casey/just

# One-time setup: install deps and create .env
just setup

# Edit .env with your values (at minimum set POSTGRES_PASSWORD and API_KEY)
# GEOIP credentials are optional for local dev

# Start the dev stack (postgres, redis, backend with hot-reload, frontend)
just dev-up

# In another terminal, start the dev log generator to simulate traffic
just devlog-up

# Generate some mixed traffic (normal + attacks)
just devlog-simulate mixed 200
```

Expected output: Open `http://localhost:5173` in your browser. You should see the dashboard with stat cards showing detected threats, a severity distribution bar, a live alert feed receiving WebSocket events, and ranked lists of top attacker IPs and most targeted paths.

The backend starts in rules-only mode. To enable ML detection, train the models:

```bash
just vigil-train
```

After training completes (about 2 minutes with synthetic data), restart the backend and it will load the ONNX models and switch to hybrid detection mode.

## Project Structure

```
ai-threat-detection/
├── backend/
│   ├── app/
│   │   ├── api/               # FastAPI route handlers (health, threats, stats, models, ws)
│   │   ├── core/
│   │   │   ├── alerts/        # AlertDispatcher: store + publish scored events
│   │   │   ├── detection/     # RuleEngine, InferenceEngine, ensemble scoring
│   │   │   ├── enrichment/    # GeoIP lookups via MaxMind
│   │   │   ├── features/      # Feature extraction, Redis aggregation, encoding
│   │   │   └── ingestion/     # Log tailer, parsers, 4-stage pipeline
│   │   ├── models/            # SQLModel ORM (ThreatEvent, ModelMetadata)
│   │   ├── schemas/           # Pydantic request/response models
│   │   ├── services/          # Database query logic (threat_service, stats_service)
│   │   ├── config.py          # Pydantic Settings (env vars, defaults, validation)
│   │   └── factory.py         # App factory with async lifespan
│   ├── ml/                    # Training pipeline (orchestrator, splitting, export, validation)
│   ├── cli/                   # Typer CLI (train, retrain, replay commands)
│   ├── tests/                 # pytest suite (parsers, features, detection, integration)
│   └── alembic/               # Database migrations
├── frontend/
│   ├── src/
│   │   ├── api/               # React Query hooks, Zod schemas, Axios client
│   │   ├── components/        # AlertFeed, SeverityBadge, MethodBadge, StatCard, ThreatDetail
│   │   ├── core/              # Router config, shell layout, query client
│   │   └── pages/             # Dashboard, Threats (table + filters), Models
│   └── vite.config.ts
├── dev-log/                   # Synthetic nginx traffic generator for testing
├── infra/                     # Dockerfiles, redis.conf, nginx.conf
├── compose.yml                # Production 5-service stack
├── dev.compose.yml            # Development stack with hot-reload
└── justfile                   # Task runner commands
```

## Next Steps

1. **Understand the concepts** - Read [01-CONCEPTS.md](./01-CONCEPTS.md) to learn anomaly detection, ensemble methods, and feature engineering for HTTP traffic
2. **Study the architecture** - Read [02-ARCHITECTURE.md](./02-ARCHITECTURE.md) to see how the 4-stage pipeline, Redis windowing, and ONNX inference fit together
3. **Walk through the code** - Read [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) for a detailed walkthrough of the ingestion pipeline, rule engine, ML training, and frontend
4. **Extend the project** - Read [04-CHALLENGES.md](./04-CHALLENGES.md) for ideas like adding new model types, integrating with SIEM tools, or building an active learning workflow

## Common Issues

**Backend fails to start with "database connection refused"**
```
sqlalchemy.exc.OperationalError: connection to server at "localhost" ... refused
```
Solution: Make sure PostgreSQL is running. If using Docker, check `just dev-ps` to verify the postgres container is healthy. The backend depends on `postgres:service_healthy`, so it will wait, but if postgres itself failed to start, check the logs with `just dev-logs postgres`.

**"onnxruntime not installed" warning at startup**
This is expected if you haven't installed the ML dependencies. The system falls back to rules-only mode automatically. To enable ML detection, run `cd backend && uv sync --group ml` and then train the models with `just vigil-train`.

**WebSocket alerts not appearing on the dashboard**
Check that Redis is running (`just dev-logs redis`). The WebSocket relay depends on Redis pub/sub. Also verify the backend is processing logs by hitting `http://localhost:8000/health` and checking the `stats` field in the response.

## Related Projects

If you found this interesting, check out:
- [SIEM Dashboard](../../intermediate/siem-dashboard/) - Build a Security Information and Event Management dashboard with Flask, MongoDB, and Redis Streams for log aggregation and correlation
- [Honeypot Network](../honeypot-network/) - Deploy deceptive services that generate the kind of attack traffic this project detects
- [API Security Scanner](../../intermediate/api-security-scanner/) - Active vulnerability scanning that complements this project's passive detection approach
