# AngelusVigil

> **Status: IN PROGRESS** — Phase 1 complete, Phase 2 (ML models) next

AI-powered threat detection engine that analyzes web server access logs using machine learning to classify HTTP traffic as benign or malicious in real-time.

Deploys as a Docker sidecar alongside any nginx-based infrastructure. Zero code changes to the monitored application.

## Progress

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 1 | Core pipeline, rule-based detection, API, Docker | Complete |
| Phase 2 | ML ensemble (autoencoder + RF + IF), ONNX inference | Next |
| Phase 3 | Production hardening, monitoring, retraining | Planned |
| Phase 4 | Dashboard, active learning, explainability | Planned |

## Tech Stack

| Layer | Technology |
|-------|-----------|
| API | FastAPI (async) |
| ML | PyTorch autoencoder + scikit-learn (RF + IF) |
| Inference | ONNX Runtime (CPU) |
| Database | PostgreSQL 18 |
| Cache | Redis 7.4 |
| GeoIP | MaxMind GeoLite2 |

## Quick Start

```bash
docker compose -f dev.compose.yml up -d
curl http://localhost:36969/health
```

## Architecture

3-model ensemble (autoencoder + Random Forest + Isolation Forest) scores each request through a weighted fusion producing a unified threat score [0.0, 1.0]:

- **HIGH** (0.7+): Store + alert + block recommendation
- **MEDIUM** (0.5-0.7): Store + monitor
- **LOW** (<0.5): Log only

Currently running rule-based detection (ModSecurity CRS patterns) as cold-start fallback until ML models are trained in Phase 2.

See `learn/` for detailed documentation.

## License

AGPLv3 - See [LICENSE](LICENSE)
