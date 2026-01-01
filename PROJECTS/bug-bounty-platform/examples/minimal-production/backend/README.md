# Minimal FastAPI Template

A minimal production-ready FastAPI template with JWT authentication and PostgreSQL.

## Features

- FastAPI with async/await
- JWT access token authentication
- PostgreSQL with SQLAlchemy 2.0 (async)
- Alembic migrations
- Domain-driven structure
- Docker and docker-compose setup

## Quick Start

1. Copy `.env.example` to `.env` and update the values:
```bash
cp .env.example .env
```

2. Start the services:
```bash
docker-compose up -d
```

The API will be available at http://localhost:8000

API docs at http://localhost:8000/docs

## Project Structure

```
backend/
├── app/
│   ├── auth/              # Authentication domain
│   ├── core/              # Core utilities and shared code
│   ├── user/              # User domain
│   ├── config.py          # Application settings
│   ├── factory.py         # FastAPI app factory
│   └── __main__.py        # Entry point
├── alembic/               # Database migrations
├── pyproject.toml         # Dependencies
├── Dockerfile
└── .env.example
```

## Development

Install dependencies:
```bash
cd backend
pip install -e ".[dev]"
```

Run locally:
```bash
cd backend/app
python -m uvicorn __main__:app --reload
```

Create new migration:
```bash
cd backend
alembic revision --autogenerate -m "description"
```

Run migrations:
```bash
cd backend
alembic upgrade head
```

## API Endpoints

- `POST /v1/users` - Register new user
- `POST /v1/auth/login` - Login (returns access token)
- `GET /v1/auth/me` - Get current user
- `POST /v1/auth/logout` - Logout (placeholder)
- `POST /v1/users/change-password` - Change password
- `GET /health` - Health check
- `GET /health/detailed` - Detailed health check

## Extending

This is a minimal starting point. You can add:
- Refresh tokens
- Email verification
- Password reset
- User roles
- Rate limiting (add Redis + slowapi)
- Structured logging (add structlog)
- More domains following the same pattern
