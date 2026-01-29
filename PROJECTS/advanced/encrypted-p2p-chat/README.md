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
├── Makefile
├── README.md
├── backend
│   ├── alembic
│   │   ├── README
│   │   ├── env.py
│   │   ├── script.py.mako
│   │   └── versions
│   ├── alembic.ini
│   ├── app
│   │   ├── api
│   │   │   ├── auth.py
│   │   │   ├── encryption.py
│   │   │   ├── rooms.py
│   │   │   └── websocket.py
│   │   ├── config.py
│   │   ├── core
│   │   │   ├── encryption
│   │   │   │   ├── double_ratchet.py
│   │   │   │   └── x3dh_manager.py
│   │   │   ├── enums.py
│   │   │   ├── exception_handlers.py
│   │   │   ├── exceptions.py
│   │   │   ├── passkey
│   │   │   │   └── passkey_manager.py
│   │   │   ├── redis_manager.py
│   │   │   ├── surreal_manager.py
│   │   │   └── websocket_manager.py
│   │   ├── factory.py
│   │   ├── main.py
│   │   ├── models
│   │   │   ├── Base.py
│   │   │   ├── Credential.py
│   │   │   ├── IdentityKey.py
│   │   │   ├── OneTimePrekey.py
│   │   │   ├── RatchetState.py
│   │   │   ├── SignedPrekey.py
│   │   │   ├── SkippedMessageKey.py
│   │   │   └── User.py
│   │   ├── schemas
│   │   │   ├── auth.py
│   │   │   ├── common.py
│   │   │   ├── rooms.py
│   │   │   ├── surreal.py
│   │   │   └── websocket.py
│   │   └── services
│   │       ├── auth_service.py
│   │       ├── message_service.py
│   │       ├── prekey_service.py
│   │       ├── presence_service.py
│   │       └── websocket_service.py
│   ├── encrypted_p2p_chat.egg-info
│   │   ├── PKG-INFO
│   │   ├── SOURCES.txt
│   │   ├── dependency_links.txt
│   │   ├── requires.txt
│   │   └── top_level.txt
│   ├── pyproject.toml
│   └── tests
│       ├── conftest.py
│       ├── test_auth_service.py
│       ├── test_encryption.py
│       ├── test_message_service.py
│       └── test_x3dh.py
├── conf
│   ├── docker
│   │   ├── dev
│   │   │   ├── fastapi.docker
│   │   │   └── vite.docker
│   │   └── prod
│   │       ├── fastapi.docker
│   │       └── vite.docker
│   └── nginx
│       ├── dev.nginx
│       ├── http.conf
│       └── prod.nginx
├── docker-compose.dev.yml
├── docker-compose.prod.yml
└── frontend
    ├── README.md
    ├── eslint.config.js
    ├── index.html
    ├── package-lock.json
    ├── package.json
    ├── public
    ├── src
    │   ├── App.tsx
    │   ├── components
    │   │   ├── Auth
    │   │   │   ├── AuthCard.tsx
    │   │   │   ├── AuthForm.tsx
    │   │   │   ├── PasskeyButton.tsx
    │   │   │   └── index.ts
    │   │   ├── Chat
    │   │   │   ├── ChatHeader.tsx
    │   │   │   ├── ChatInput.tsx
    │   │   │   ├── ConversationItem.tsx
    │   │   │   ├── ConversationList.tsx
    │   │   │   ├── EncryptionBadge.tsx
    │   │   │   ├── MessageBubble.tsx
    │   │   │   ├── MessageList.tsx
    │   │   │   ├── NewConversation.tsx
    │   │   │   ├── OnlineStatus.tsx
    │   │   │   ├── TypingIndicator.tsx
    │   │   │   ├── UserSearch.tsx
    │   │   │   └── index.ts
    │   │   ├── Layout
    │   │   │   ├── AppShell.tsx
    │   │   │   ├── Header.tsx
    │   │   │   ├── ProtectedRoute.tsx
    │   │   │   ├── Sidebar.tsx
    │   │   │   └── index.ts
    │   │   └── UI
    │   │       ├── Avatar.tsx
    │   │       ├── Badge.tsx
    │   │       ├── Button.tsx
    │   │       ├── Dropdown.tsx
    │   │       ├── IconButton.tsx
    │   │       ├── Input.tsx
    │   │       ├── Modal.tsx
    │   │       ├── Skeleton.tsx
    │   │       ├── Spinner.tsx
    │   │       ├── TextArea.tsx
    │   │       ├── Toast.tsx
    │   │       ├── Tooltip.tsx
    │   │       └── index.ts
    │   ├── config.ts
    │   ├── crypto
    │   │   ├── crypto-service.ts
    │   │   ├── double-ratchet.ts
    │   │   ├── index.ts
    │   │   ├── key-store.ts
    │   │   ├── primitives.ts
    │   │   └── x3dh.ts
    │   ├── index.css
    │   ├── index.tsx
    │   ├── lib
    │   │   ├── api-client.ts
    │   │   ├── base64.ts
    │   │   ├── date.ts
    │   │   ├── index.ts
    │   │   └── validators.ts
    │   ├── pages
    │   │   ├── Chat.tsx
    │   │   ├── Home.tsx
    │   │   ├── Login.tsx
    │   │   ├── NotFound.tsx
    │   │   └── Register.tsx
    │   ├── services
    │   │   ├── auth.service.ts
    │   │   └── index.ts
    │   ├── stores
    │   │   ├── auth.store.ts
    │   │   ├── index.ts
    │   │   ├── messages.store.ts
    │   │   ├── presence.store.ts
    │   │   ├── rooms.store.ts
    │   │   ├── session.store.ts
    │   │   ├── settings.store.ts
    │   │   ├── typing.store.ts
    │   │   └── ui.store.ts
    │   ├── styles
    │   ├── types
    │   │   ├── api.ts
    │   │   ├── auth.ts
    │   │   ├── chat.ts
    │   │   ├── components.ts
    │   │   ├── encryption.ts
    │   │   ├── guards.ts
    │   │   ├── index.ts
    │   │   └── websocket.ts
    │   ├── vite-env.d.ts
    │   └── websocket
    │       ├── index.ts
    │       ├── message-handlers.ts
    │       └── websocket-manager.ts
    ├── tsconfig.json
    └── vite.config.ts
```
## Features

### Authentication
- Passwordless login with WebAuthn/Passkeys
- Discoverable credentials (device based auth)
- Multi-device support
- Signature counter verification

### Encryption
- Double Ratchet protocol (Signal)
- X3DH key exchange for async messaging
- Forward secrecy
- Break-in recovery
- Out of order message handling

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
Per Message Encryption (AES-256-GCM)
```

### WebSocket Flow

```
Client → WebSocket → Connection Manager → Service Layer → SurrealDB
                                                    ↓
                                            Live Queries → Broadcast
```

## License

MIT
