# Encrypted P2P Chat

End-to-end encrypted P2P chat application with Signal Protocol (Double Ratchet + X3DH) and WebAuthn/Passkeys authentication.

## Tech Stack

### Backend
- **FastAPI** - Modern Python web framework
- **PostgreSQL + SQLModel** - User and credential storage
- **SurrealDB** - Real-time messaging with live queries
- **Redis** - Challenge storage and caching
- **Double Ratchet + X3DH** - Signal Protocol encryption
- **WebAuthn** - Passwordless authentication

### Frontend
- **SolidJS 1.9** - Fine-grained reactive UI
- **TypeScript** - Type safety
- **Vite 6** - Modern build tool
- **Tailwind CSS v4** - Utility-first CSS
- **@tanstack/solid-query** - Data fetching

### Infrastructure
- **Docker Compose** - Service orchestration
- **Nginx** - Reverse proxy
- **Makefile** - Development automation

## Quick Start

### Prerequisites

- Docker and Docker Compose
- **Node.js 20.19+ or 22.12+** (required for Vite 7)
- **Python 3.13+** (latest stable)
- **uv** (Python package manager) - `curl -LsSf https://astral.sh/uv/install.sh | sh`
- Make

### Setup

1. Clone the repository

2. Create environment files:
```bash
make env
```

This creates:
- `.env` (root) - Used by backend and docker-compose
- `frontend/.env` - Used by Vite frontend

3. Update `.env` files with your configuration

4. Run development environment:
```bash
make dev
```

The application will be available at:
- **Frontend**: http://localhost:3000 (Vite dev server)
- **Backend**: http://localhost:8000 (FastAPI)
- **Nginx**: http://localhost (proxies to frontend/backend)

### Development Commands

```bash
make help              # Show all commands
make setup             # Complete project setup
make dev               # Start development environment
make logs-dev          # Follow development logs
make down-dev          # Stop development environment
make test-backend      # Run backend tests
make clean             # Clean all artifacts
```

### Production Commands

```bash
make build-prod        # Build production images
make prod              # Start production environment
make logs-prod         # Follow production logs
make down-prod         # Stop production environment
```

## Project Structure

```
encrypted-p2p-chat/
├── backend/
│   ├── app/
│   │   ├── api/                    # API endpoints
│   │   │   ├── auth.py            # WebAuthn authentication
│   │   │   ├── encryption.py      # Prekey bundle endpoints
│   │   │   └── websocket.py       # WebSocket endpoint
│   │   ├── core/
│   │   │   ├── encryption/
│   │   │   │   ├── x3dh_manager.py      # X3DH key exchange
│   │   │   │   └── double_ratchet.py    # Double Ratchet engine
│   │   │   ├── passkey/
│   │   │   │   └── passkey_manager.py   # WebAuthn manager
│   │   │   ├── exceptions.py      # Custom exceptions
│   │   │   ├── redis_manager.py   # Redis client
│   │   │   ├── surreal_manager.py # SurrealDB client
│   │   │   └── websocket_manager.py # WebSocket connections
│   │   ├── models/                # SQLModel database models
│   │   ├── schemas/               # Pydantic schemas
│   │   ├── services/              # Business logic layer
│   │   ├── config.py              # Configuration and constants
│   │   ├── factory.py             # FastAPI app factory
│   │   └── main.py                # Entry point
│   ├── tests/                     # Pytest tests
│   ├── Dockerfile                 # Production
│   ├── Dockerfile.dev             # Development
│   └── pyproject.toml
├── frontend/
│   ├── src/
│   │   ├── pages/                 # SolidJS pages
│   │   ├── App.tsx                # Root component with routes
│   │   ├── index.tsx              # Entry point
│   │   ├── index.css              # Tailwind imports
│   │   └── config.ts              # Constants
│   ├── public/
│   │   └── index.html
│   ├── Dockerfile                 # Production
│   ├── Dockerfile.dev             # Development
│   ├── vite.config.ts
│   ├── tsconfig.json
│   └── package.json
├── nginx/
│   ├── nginx.dev.conf             # Development config
│   ├── nginx.prod.conf            # Production config
│   └── Dockerfile
├── docker-compose.yml             # Production
├── docker-compose.dev.yml         # Development
├── Makefile
└── .env.example

## Features

### Authentication
- Passwordless login with WebAuthn/Passkeys
- Discoverable credentials (device-based auth)
- Multi-device support
- Signature counter verification

### Encryption
- Double Ratchet protocol (Signal)
- X3DH key exchange for async messaging
- Forward secrecy
- Break-in recovery
- Out-of-order message handling

### Real-time Messaging
- WebSocket connections
- SurrealDB live queries
- Online/offline presence
- Typing indicators
- Read receipts
- Heartbeat keep-alive

## Development

### Backend Development

```bash
cd backend
uv venv ../.venv
uv pip install -e .[dev]
uv run pytest tests/ -v
```

### Frontend Development

```bash
cd frontend
npm install
npm run dev
npm run typecheck
npm run lint
```

## Testing

### Backend Tests

```bash
make test-backend
```

Or manually:

```bash
cd backend
uv run pytest tests/ -v
```

## Environment Variables

See `.env.example` files for all configuration options.

Required variables:
- `SECRET_KEY` - Application secret key
- `POSTGRES_PASSWORD` - PostgreSQL password
- `SURREAL_PASSWORD` - SurrealDB password

## Architecture

### Backend Architecture

```
API Endpoints (thin routes)
    ↓
Services (business logic)
    ↓
Models (database)
    ↓
PostgreSQL / SurrealDB / Redis
```

### Encryption Flow

```
X3DH Key Exchange
    ↓
Shared Secret
    ↓
Double Ratchet Initialization
    ↓
Per-Message Encryption (AES-256-GCM)
```

### WebSocket Flow

```
Client → WebSocket → Connection Manager → Service Layer → SurrealDB
                                                    ↓
                                            Live Queries → Broadcast
```

## License

MIT
