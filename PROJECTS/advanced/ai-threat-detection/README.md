```css
 █████╗ ███╗   ██╗ ██████╗ ███████╗██╗     ██╗   ██╗███████╗
██╔══██╗████╗  ██║██╔════╝ ██╔════╝██║     ██║   ██║██╔════╝
███████║██╔██╗ ██║██║  ███╗█████╗  ██║     ██║   ██║███████╗
██╔══██║██║╚██╗██║██║   ██║██╔══╝  ██║     ██║   ██║╚════██║
██║  ██║██║ ╚████║╚██████╔╝███████╗███████╗╚██████╔╝███████║
╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝ ╚═════╝ ╚══════╝
██╗   ██╗██╗ ██████╗ ██╗██╗
██║   ██║██║██╔════╝ ██║██║
██║   ██║██║██║  ███╗██║██║
╚██╗ ██╔╝██║██║   ██║██║██║
 ╚████╔╝ ██║╚██████╔╝██║███████╗
  ╚═══╝  ╚═╝ ╚═════╝ ╚═╝╚══════╝
```

[![Cybersecurity Projects](https://img.shields.io/badge/Cybersecurity--Projects-Project%20%2317-red?style=flat&logo=github)](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/advanced/ai-threat-detection)
[![Python](https://img.shields.io/badge/Python-3.14+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat&logo=react&logoColor=black)](https://react.dev)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat&logo=docker)](https://www.docker.com)
[![PyTorch](https://img.shields.io/badge/PyTorch-EE4C2C?style=flat&logo=pytorch&logoColor=white)](https://pytorch.org)

> AI-powered threat detection engine that analyzes nginx access logs using a 3-model ML ensemble to classify HTTP traffic as benign or malicious in real time.

*This is a quick overview — learn modules with security theory, architecture deep-dives, and full walkthroughs are coming soon.*

## What It Does

- 3-model ML ensemble (Autoencoder + Random Forest + Isolation Forest) exported to ONNX for fast CPU inference
- 4-stage async pipeline: parse raw logs, extract 35-dimensional feature vectors, score with rules + ML, dispatch alerts
- Rule engine with ModSecurity CRS-inspired patterns (SQLi, XSS, path traversal, command injection, Log4Shell, SSRF)
- Real-time WebSocket alert feed with live severity scoring and threat classification
- Auto-trains on first deploy with synthetic data, retrains from the dashboard using your actual stored events
- Deploys as a Docker sidecar alongside any nginx-based infrastructure with zero code changes

## Quick Start

```bash
git clone https://github.com/CarterPerez-dev/Cybersecurity-Projects.git
cd PROJECTS/advanced/ai-threat-detection
cp .env.example .env
docker compose -f dev.compose.yml up -d
```

First startup takes ~2 minutes while models train. After that, models persist to a volume and subsequent starts are instant.

Once healthy, visit `http://localhost:46969` for the dashboard.

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` to see all available commands.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## Simulate Attacks

A built-in dev-log application generates realistic nginx traffic for testing:

```bash
docker compose -f dev-log/compose.yml up -d
python dev-log/simulate.py mixed -n 100
```

Attack modes: `normal`, `sqli`, `xss`, `traversal`, `cmdi`, `log4shell`, `ssrf`, `scanner`, `flood`, `mixed`

## Stack

**Backend:** FastAPI (async), PostgreSQL 18, Redis 7.4, ONNX Runtime, PyTorch, scikit-learn, MLflow

**Frontend:** React 19, TypeScript, Vite, Sass, TanStack Query, Zustand

**Infra:** Docker Compose, multi-stage builds, auto-training entrypoint, shared volume log tailing

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        nginx logs                           │
│                     (shared volume)                         │
└──────────────────────────┬──────────────────────────────────┘
                           │
                    PollingObserver
                           │
                   ┌───────▼───────┐
                   │   Raw Queue   │
                   └───────┬───────┘
                           │
              ┌────────────▼────────────┐
              │     Stage 1: Parse      │
              │  nginx combined format  │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │   Stage 2: Features     │
              │  35-dim vector + GeoIP  │
              │  + windowed aggregates  │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │   Stage 3: Detection    │
              │  Rules + ML Ensemble    │
              │  AE(40%) RF(40%) IF(20%)│
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │   Stage 4: Dispatch     │
              │  PostgreSQL + Redis     │
              │  pub/sub → WebSocket    │
              └─────────────────────────┘
```

Threat scores range from 0.0 to 1.0:

- **HIGH** (0.7+): Stored, alerted via WebSocket, block recommendation
- **MEDIUM** (0.5-0.7): Stored, monitored
- **LOW** (<0.5): Logged for pattern analysis

## ML Pipeline

Models auto-train on first container startup using synthetic attack patterns (SQLi, XSS, path traversal, scanners, etc.) and are exported to ONNX. Validation gates enforce F1 >= 0.80 and PR-AUC >= 0.85 before deployment.

The retrain endpoint (`POST /models/retrain`) pulls real events from the database:
- **Reviewed events** use human-verified labels as ground truth
- **Unreviewed events** use score-based heuristics (high score = likely attack, low score = likely normal)
- If insufficient real data exists, synthetic samples fill the gap

## API

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `GET /stats` | Threat statistics and severity breakdown |
| `GET /threats` | Paginated threat events with filters |
| `GET /models/status` | Active models, detection mode, metrics |
| `POST /models/retrain` | Trigger retraining from stored events |
| `POST /ingest/batch` | Manual log line ingestion |
| `WS /ws/alerts` | Real-time threat alert stream |

All endpoints (except health and WebSocket) require `X-API-Key` header.

## Status

This project is fully functional and actively being polished. The core system (pipeline, ML ensemble, dashboard, real-time alerts, auto-training, attack simulation) is complete and working end to end.

Learn modules are coming soon and will cover:
- Security theory behind anomaly detection and ML-based WAFs
- Architecture deep-dive into the async pipeline and ensemble scoring
- Line-by-line implementation walkthrough
- Extension challenges (GeoIP blocking, custom rule authoring, active learning)

## License

AGPL 3.0
