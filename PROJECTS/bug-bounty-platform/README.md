# Bug Bounty Platform

A production-ready, enterprise-grade bug bounty platform built with modern web technologies. This platform enables companies to run coordinated vulnerability disclosure programs, allowing security researchers to submit findings and receive rewards.

**Live Demo:** [bugbounty.carterperez-dev.com](https://bugbounty.carterperez-dev.com)
**API Documentation:** [bugbounty.carterperez-dev.com/api/docs](https://bugbounty.carterperez-dev.com/api/docs)

---

## Overview

This project demonstrates enterprise-level software architecture with:
- Async-first FastAPI backend with strict type safety
- Modern React frontend with TypeScript
- Production-ready security (JWT with refresh token rotation, Argon2id hashing)
- Advanced design patterns (Dependency Injection, Repository Pattern, Layered Architecture)
- Docker containerization with multi-stage builds
- Database migrations with Alembic
- Comprehensive testing and linting infrastructure

**Part of:** [Cybersecurity-Projects Repository](https://github.com/CarterPerez-dev/Cybersecurity-Projects) (60+ security-focused projects)

---

## Features

### Security Researcher Features
- User registration and authentication
- Browse public bug bounty programs
- Submit vulnerability reports with markdown support
- Track report status and receive updates
- Earn reputation and rewards

### Company Features
- Create and manage bug bounty programs
- Define program scope (assets, reward tiers, SLA)
- Triage incoming vulnerability reports
- Assess severity using CVSS scoring
- Award bounties to researchers
- Communicate via comments and attachments

### Platform Features
- Role-based access control (Researcher, Company, Admin)
- JWT authentication with refresh token rotation
- Token versioning for instant session invalidation
- Multi-device session management
- Rate limiting on all endpoints
- Comprehensive audit logging
- OpenAPI/Swagger documentation

---

## Tech Stack

### Backend
- **FastAPI** 0.123.0+ - Modern async Python web framework
- **Python** 3.12+ - Strict typing with mypy
- **PostgreSQL** 18 - Primary database with asyncpg driver
- **Redis** 7 - Caching and session storage
- **SQLAlchemy** 2.0+ - Async ORM
- **Alembic** - Database migrations
- **Pydantic** v2 - Data validation and settings
- **JWT** - Token-based authentication with rotation
- **Argon2id** - Password hashing via pwdlib

### Frontend
- **React** 19.2+ - UI library
- **TypeScript** 5.9 - Static typing
- **Vite** 7 - Build tool with Rolldown
- **React Router** 7.1 - File-based routing
- **TanStack Query** v5 - Server state management
- **Zustand** - Client state management
- **Axios** - HTTP client
- **SASS** - CSS preprocessing

### Infrastructure
- **Docker** + **Docker Compose** - Containerization
- **Nginx** - Reverse proxy and static file serving
- **Cloudflare Tunnel** - Zero-config deployment (optional)
- **Gunicorn** + **Uvicorn** - Production ASGI server

### Development Tools
- **Ruff** - Python linting and formatting
- **Biome** - JavaScript/TypeScript linting
- **MyPy** - Static type checking
- **Pytest** - Testing framework
- **Just** - Task runner (30+ commands)
- **Pre-commit hooks** - Automated quality checks

---

## Getting Started

You have two options:

### Option 1: Use the Live API (Easiest)

The platform is already deployed and running! You can:
- Use the web interface: [bugbounty.carterperez-dev.com](https://bugbounty.carterperez-dev.com)
- Access the API directly: [bugbounty.carterperez-dev.com/api/](https://bugbounty.carterperez-dev.com/api/)
- View API documentation: [bugbounty.carterperez-dev.com/api/docs](https://bugbounty.carterperez-dev.com/api/docs)

You can build your own client application using the deployed API endpoints. See the OpenAPI documentation for available endpoints and schemas.

### Option 2: Run It Yourself

If you want to run the entire platform locally or deploy your own instance:

#### Prerequisites
- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/)
- [Just](https://github.com/casey/just) (task runner) - `cargo install just` or see [installation guide](https://github.com/casey/just#installation)
- Git

#### Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/CarterPerez-dev/Cybersecurity-Projects.git
   cd Cybersecurity-Projects/PROJECTS/bug-bounty-platform
   ```

2. **Configure environment variables:**
   ```bash
   cp .env.example .env
   ```

   Edit `.env` and update these critical values:
   - `SECRET_KEY` - Generate a secure random string (minimum 32 characters)
   - `POSTGRES_PASSWORD` - Set a strong database password
   - `ADMIN_EMAIL` - (Optional) First user with this email becomes admin
   - `CORS_ORIGINS` - Update if using different ports

3. **Start the platform (development mode with hot reload):**
   ```bash
   just dev-up
   ```

   Or in production mode:
   ```bash
   just up
   ```

4. **Access the platform:**
   - **Frontend:** http://localhost:8420
   - **API:** http://localhost:8420/api
   - **API Docs:** http://localhost:8420/api/docs
   - **Backend (direct):** http://localhost:5420
   - **Frontend Dev Server:** http://localhost:3420 (dev mode only)

5. **Apply database migrations:**
   ```bash
   just migrate head
   ```

6. **Create your first account:**
   - Navigate to http://localhost:8420
   - Click "Register"
   - If you set `ADMIN_EMAIL` in `.env`, registering with that email grants admin privileges

#### Common Commands

The `justfile` provides 30+ commands for development:

```bash
just                    # List all available commands

# Development
just dev-up             # Start in development mode (hot reload)
just dev-down           # Stop development containers
just dev-logs backend   # View backend logs
just dev-shell backend  # Open shell in backend container

# Production
just up                 # Start in production mode
just down               # Stop production containers
just build              # Build all containers
just rebuild            # Rebuild without cache

# Database
just migrate head       # Apply all migrations
just migration "message" # Create new migration
just rollback           # Rollback last migration
just db-current         # Show current migration

# Linting & Type Checking
just lint               # Run ruff + pylint
just ruff-fix           # Auto-fix linting issues
just mypy               # Type check with mypy
just biome-fix          # Fix frontend linting issues
just typecheck          # Run all type checks

# Testing
just test               # Run all tests
just test-cov           # Run tests with coverage report

# CI
just ci                 # Run full CI pipeline (lint + typecheck + test)
```

#### Project Structure

```
bug-bounty-platform/
├── backend/            # FastAPI backend (~7,000 lines)
│   ├── src/
│   │   ├── app/
│   │   │   ├── core/       # Base classes, database, security, constants and enums, etc.
│   │   │   ├── user/       # User domain
│   │   │   ├── auth/       # Authentication
│   │   │   ├── program/    # Bug bounty programs
│   │   │   ├── report/     # Vulnerability reports
│   │   │   └── admin/      # Admin functionality
│   │   └── config.py      # configuration values
│   │   └── factory.py      # essentially the 'main.py' file
│   │   └── __main__.py      # Where the run command lives
│   ├── alembic/        # Database migrations
│   ├── tests/          # Unit and integration tests
│   └── pyproject.toml  # Python dependencies
│
├── frontend/           # React + TypeScript frontend
│   ├── src/
│   │   ├── routes/         # Pages
│   │   ├── api/            # API client and hooks
│   │   ├── components/     # Reusable components
│   │   ├── styles/         # SCSS global values
│   │   └── core/           # App configuration, zustand stores (ui state management), api configuration
│   └── package.json
│
├── infra/              # Docker and Nginx configs
│   ├── nginx/
│   └── docker/
│
├── learn/              # Educational documentation (see below)
├── compose.yml         # Production Docker Compose
├── dev.compose.yml     # Development Docker Compose
├── justfile            # Task runner commands
└── .env.example        # Environment variables template
```

---

## Configuration

### Environment Variables

All configuration is done via `.env` file. Key variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `NGINX_HOST_PORT` | External port for Nginx | 8420 |
| `BACKEND_HOST_PORT` | External port for backend API | 5420 |
| `FRONTEND_HOST_PORT` | External port for frontend dev server | 3420 |
| `POSTGRES_HOST_PORT` | External port for PostgreSQL | 4420 |
| `REDIS_HOST_PORT` | External port for Redis | 6420 |
| `SECRET_KEY` | JWT signing key (min 32 chars) | **MUST CHANGE** |
| `POSTGRES_PASSWORD` | Database password | **MUST CHANGE** |
| `ADMIN_EMAIL` | Auto-promote this email to admin | (empty) |
| `ENVIRONMENT` | dev/staging/production | development |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | JWT access token lifetime | 15 |
| `REFRESH_TOKEN_EXPIRE_DAYS` | Refresh token lifetime | 7 |
| `CORS_ORIGINS` | Allowed origins for CORS | `["*"]` (all origins) |

See `.env.example` for all available options.

### Port Configuration

If the default ports conflict with other services, update these in `.env`:

```bash
NGINX_HOST_PORT=8420        # Change to any available port
BACKEND_HOST_PORT=5420      # Change to any available port
FRONTEND_HOST_PORT=3420     # Change to any available port
POSTGRES_HOST_PORT=4420     # Change to any available port
REDIS_HOST_PORT=6420        # Change to any available port
```

### CORS Configuration

The API is configured to accept requests from **all origins** by default:

```bash
CORS_ORIGINS=["*"]  # Allows all origins (public API)
```

If you need to restrict access to specific origins:

```bash
CORS_ORIGINS=["https://yourdomain.com","https://app.yourdomain.com"]
```

---

## Deployment

### Option 1: Cloudflare Tunnel (Recommended for beginners)

No port forwarding or reverse proxy configuration needed!

1. Create a Cloudflare account and add your domain
2. Go to Zero Trust Dashboard > Access > Tunnels
3. Create a new tunnel, name it, and copy the token
4. Add the token to `.env`:
   ```bash
   CLOUDFLARE_TUNNEL_TOKEN=your-token-here
   ```
5. Configure public hostname in Cloudflare:
   - Public hostname: `yourdomain.com`
   - Service: `http://nginx:80`
6. Start the platform:
   ```bash
   just up
   ```

Your platform is now live at `https://yourdomain.com`!

### Option 2: Traditional Hosting (VPS)

1. Rent a VPS (DigitalOcean, AWS, Linode, etc.)
2. Install Docker and Docker Compose
3. Clone the repository and configure `.env`
4. Point your domain's A record to your VPS IP
5. Configure SSL (Let's Encrypt with Certbot)
6. Start the platform:
   ```bash
   just up
   ```

### Option 3: Use the Existing Deployment

Just use the API at `bugbounty.carterperez-dev.com/api/` - no deployment needed!

---

## Learning Resources

This project includes comprehensive educational documentation in the `learn/` directory:

- **[ARCHITECTURE.md](learn/ARCHITECTURE.md)** - Deep dive into system architecture and design decisions
- **[PATTERNS.md](learn/PATTERNS.md)** - Explanation of design patterns used (DI, Repository, etc.)
- **[GETTING-STARTED.md](learn/GETTING-STARTED.md)** - Step-by-step tutorial for building similar applications
- **[DATABASE.md](learn/DATABASE.md)** - Database schema design and migration strategies
- **[SECURITY.md](learn/SECURITY.md)** - Security features and best practices explained

These documents are designed to help you understand not just *what* the code does, but *why* it's architected this way and *how* you can apply these patterns to your own projects.

---

## API Documentation

### Interactive Documentation

When running locally, access interactive API docs at:
- **Swagger UI:** http://localhost:8420/api/docs
- **ReDoc:** http://localhost:8420/api/redoc

For the live deployment:
- **Swagger UI:** [bugbounty.carterperez-dev.com/api/docs](https://bugbounty.carterperez-dev.com/api/docs)

### Key Endpoints

**Authentication:**
- `POST /api/v1/auth/register` - Create new account
- `POST /api/v1/auth/login` - Login (returns access + refresh tokens)
- `POST /api/v1/auth/refresh` - Refresh access token
- `POST /api/v1/auth/logout` - Logout (invalidates refresh token)
- `POST /api/v1/auth/logout-all` - Logout from all devices

**Users:**
- `GET /api/v1/users/me` - Get current user profile
- `PATCH /api/v1/users/me` - Update profile
- `GET /api/v1/users/{id}` - Get public user profile

**Programs:**
- `GET /api/v1/programs` - List all programs (paginated)
- `GET /api/v1/programs/{slug}` - Get program details
- `POST /api/v1/programs` - Create program (company only)
- `PATCH /api/v1/programs/{slug}` - Update program (owner only)
- `DELETE /api/v1/programs/{slug}` - Delete program (owner only)

**Reports:**
- `GET /api/v1/reports` - List your reports
- `GET /api/v1/reports/{id}` - Get report details
- `POST /api/v1/reports` - Submit vulnerability report
- `PATCH /api/v1/reports/{id}` - Update report (various endpoints for status changes)

**Admin:**
- `GET /api/v1/admin/stats` - Platform statistics
- `GET /api/v1/admin/users` - Manage users
- `GET /api/v1/admin/programs` - Manage programs
- `GET /api/v1/admin/reports` - Manage reports

All endpoints return JSON and use standard HTTP status codes.

---

## Development

### Running Tests

```bash
just test                # Run all tests
just test-cov            # Run with coverage report
```

### Type Checking

```bash
just mypy                # Check backend types
just tsc                 # Check frontend types
just typecheck           # Check all types
```

### Linting

```bash
just lint                # Backend: ruff + pylint
just ruff-fix            # Auto-fix backend linting issues
just biome-fix           # Auto-fix frontend linting issues
just stylelint-fix       # Auto-fix SCSS linting issues
```

### Database Migrations

```bash
just migration "Add user reputation field"  # Create new migration
just migrate head                          # Apply all migrations
just rollback                              # Rollback last migration
just db-history                            # View migration history
```

### Docker Management

```bash
just dev-shell backend   # Open shell in backend container
just dev-shell db        # Open psql in database container
just dev-logs nginx      # View nginx logs
just ps                  # List running containers
```

---

## Architecture Highlights

### Dependency Injection

FastAPI's dependency injection system is used extensively:

```python
from fastapi import Depends
from typing import Annotated

CurrentUser = Annotated[User, Depends(get_current_user)]

@router.get("/me")
async def get_me(user: CurrentUser) -> UserSchema:
    return user
```

### Repository Pattern

All database operations go through repositories:

```python
class UserRepository(BaseRepository[User]):
    async def find_by_email(self, email: str) -> User | None:
        stmt = select(User).where(User.email == email)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

# Usage in service layer
async def authenticate_user(email: str, password: str) -> User:
    user = await user_repo.find_by_email(email)
    if not user or not verify_password(password, user.password_hash):
        raise InvalidCredentialsError()
    return user
```

### Type Safety

Strict type checking with mypy and TypeScript:

```python
from typing import Generic, TypeVar

ModelT = TypeVar("ModelT", bound=Base)

class BaseRepository(Generic[ModelT]):
    def __init__(self, session: AsyncSession, model: type[ModelT]) -> None:
        self.session = session
        self.model = model
```

### Security

Multiple layers of security:
- JWT tokens with HS256 algorithm
- Token versioning (instant invalidation on password change)
- Refresh token rotation (prevents replay attacks)
- Argon2id password hashing
- Rate limiting (100 req/min default, 20 req/min for auth)
- CORS protection
- Input validation with Pydantic

See [learn/SECURITY.md](learn/SECURITY.md) for detailed explanations.

---

## Contributing

This is an educational project demonstrating production-level architecture. Feel free to:
- Fork the repository and build upon it
- Use it as a reference for your own projects
- Submit issues if you find bugs
- Share feedback and suggestions

---

## License

This project is part of the [Cybersecurity-Projects](https://github.com/CarterPerez-dev/Cybersecurity-Projects) repository.

© AngelaMos | 2026

---

## Links

- **Live Platform:** [bugbounty.carterperez-dev.com](https://bugbounty.carterperez-dev.com)
- **API Docs:** [bugbounty.carterperez-dev.com/api/docs](https://bugbounty.carterperez-dev.com/api/docs)
- **Parent Repository:** [Cybersecurity-Projects](https://github.com/CarterPerez-dev/Cybersecurity-Projects)

---

## Support

For questions, issues, or discussions:
1. Check the [learn/](learn/) directory for detailed documentation
2. Review the API documentation at `/api/docs`
3. Open an issue in the parent repository
4. Email: [contact information if applicable]

---

**Happy Hacking! 🔒**
