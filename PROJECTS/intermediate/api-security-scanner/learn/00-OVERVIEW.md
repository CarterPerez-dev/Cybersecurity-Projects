# 00-OVERVIEW.md

# API Security Scanner

## What This Is

A full-stack web application that tests APIs for common security vulnerabilities. Point it at any API endpoint and it'll check for rate limiting weaknesses, authentication bypasses, SQL injection holes, and authorization flaws. Built with FastAPI and React, it's designed to teach you how attackers probe APIs and how to defend against them.

## Why This Matters

APIs are everywhere. Your mobile app talks to an API. Your web dashboard pulls from an API. That third party integration you added last week? API. And they're constantly under attack. In 2023, API attacks increased 400% year over year according to Salt Security's research. The Optus breach in 2022 exposed 10 million customer records through an unauthenticated API endpoint. T-Mobile's API breach the same year leaked data on 37 million customers.

Most of these breaches come down to a handful of problems that show up repeatedly. Missing rate limits let attackers hammer endpoints. Broken authentication accepts invalid tokens. SQL injection still works because developers concatenate user input into queries. IDOR vulnerabilities let users access each other's data by just changing an ID in the URL.

This project teaches you to find these issues before attackers do.

**Real world scenarios where this applies:**
- Security teams scanning their own APIs before releases
- Bug bounty hunters looking for vulnerabilities in public APIs
- DevOps engineers validating that rate limiting actually works
- Penetration testers checking if JWT validation can be bypassed
- Developers learning what attacks their code needs to defend against

## What You'll Learn

This project teaches you how API security testing works under the hood. By building it yourself, you'll understand:

**Security Concepts:**
- OWASP API Security Top 10 2023 - not just the list, but what each vulnerability looks like in real code and how to detect it automatically
- Rate limiting bypass techniques - how attackers rotate IPs, spoof headers, and manipulate endpoints to evade limits
- JWT vulnerabilities - why the "none" algorithm attack works, what happens when signatures aren't verified, and how to test for weak secrets
- SQL injection detection - error-based, boolean blind, and time-based blind techniques with statistical analysis to reduce false positives
- IDOR/BOLA testing - finding authorization gaps that let users access objects they shouldn't

**Technical Skills:**
- Building security scanners with request throttling, retry logic, and baseline timing analysis (see `backend/scanners/base_scanner.py:40-90`)
- Implementing layered architecture with repositories, services, and route handlers that keep business logic separate from data access
- JWT authentication flows from password hashing through token creation to validation on protected endpoints
- Rate limiting implementation and detection using both response analysis and header inspection
- Handling concurrent HTTP requests with proper connection pooling, timeouts, and error recovery

**Tools and Techniques:**
- FastAPI with async/await for handling multiple scans concurrently without blocking
- SQLAlchemy with Alembic for database migrations and relationship management
- Docker multi-stage builds that separate dev (hot reload) from production (optimized, multi-worker)
- React with TanStack Query for managing server state, automatic refetching, and optimistic updates
- Nginx reverse proxy configuration for routing /api to backend and serving static frontend files

## Prerequisites

Before starting, you should understand:

**Required knowledge:**
- Python basics - functions, classes, async/await. You'll be reading code like `async def make_request(self, method: str, endpoint: str, **kwargs: Any)` and need to understand what's happening
- HTTP fundamentals - what GET/POST mean, how headers work, what status codes indicate. The scanners analyze responses to detect vulnerabilities
- SQL basics - SELECT, WHERE clauses, what a JOIN does. You'll see how SQL injection payloads try to manipulate queries
- REST API concepts - endpoints, request/response, authentication. The whole project revolves around testing APIs

**Tools you'll need:**
- Docker and Docker Compose - the entire stack runs in containers
- Python 3.11+ - backend code uses modern type hints and pattern matching
- Node.js 20+ - frontend build requires recent npm
- PostgreSQL knowledge helpful - data is stored in Postgres with relationships between users, scans, and test results

**Helpful but not required:**
- React and TypeScript - frontend is fully implemented but understanding it helps
- Previous security testing experience - we'll teach the concepts but prior exposure to tools like Burp Suite or OWASP ZAP provides context
- FastAPI familiarity - we use dependency injection and Pydantic validation heavily

## Quick Start

Get the project running locally:

```bash
# Clone and navigate (assuming you're already in PROJECTS/intermediate)
cd api-security-scanner

# Copy environment template
cp .env.example .env

# CRITICAL: Edit .env and change SECRET_KEY to something random
# In production this must be a cryptographically secure random string

# Start development environment (includes hot reload)
docker compose -f dev.compose.yml up --build

# Wait for all services to be healthy, then visit:
# - Frontend: http://localhost (or http://localhost:80)
# - Backend API docs: http://localhost:8000/docs
# - Direct API: http://localhost:8000
```

Expected output: You should see the login page. Create an account, then you can start scanning. Try scanning `https://httpbin.org/get` with all four tests enabled. You'll see safe results because httpbin is designed for testing.

## Project Structure

```
api-security-scanner/
├── backend/
│   ├── config.py              # All environment variables and constants
│   ├── core/                  # Infrastructure (database, security, dependencies)
│   ├── models/                # SQLAlchemy models (User, Scan, TestResult)
│   ├── repositories/          # Data access layer, queries isolated here
│   ├── routes/                # FastAPI endpoints (auth, scans)
│   ├── scanners/              # Security testing logic (SQLi, auth, etc)
│   ├── schemas/               # Pydantic validation schemas
│   └── services/              # Business logic layer
├── frontend/
│   └── src/
│       ├── components/        # React UI components
│       ├── hooks/             # TanStack Query hooks for API calls
│       ├── services/          # API client functions
│       └── store/             # Zustand state management
├── conf/
│   ├── docker/                # Dockerfiles for dev and prod
│   └── nginx/                 # Nginx reverse proxy configs
└── compose.yml                # Production Docker Compose
└── dev.compose.yml            # Development with volume mounts
```

## Next Steps

1. **Understand the concepts** - Read [01-CONCEPTS.md](./01-CONCEPTS.md) to learn the security fundamentals behind rate limiting, authentication, SQL injection, and IDOR
2. **Study the architecture** - Read [02-ARCHITECTURE.md](./02-ARCHITECTURE.md) to see how the scanner system is designed, why we use the repository pattern, and how data flows through the layers
3. **Walk through the code** - Read [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) for detailed explanation of how each scanner works, with line-by-line breakdowns of the actual code
4. **Extend the project** - Read [04-CHALLENGES.md](./04-CHALLENGES.md) for ideas to build on, from adding XSS detection to implementing custom scanner plugins

## Common Issues

**Docker containers fail to start**
```
Error: port is already allocated
```
Solution: Another service is using port 80, 5432, or 8000. Check `docker ps` and stop conflicting containers, or edit `.env` to change `HOST_NGINX_PORT`, `HOST_DB_PORT`, or `HOST_BACKEND_PORT`

**Frontend can't reach backend**
```
Network Error / Failed to fetch
```
Solution: Check `VITE_API_URL` in `.env`. For Docker setup, it should be `http://localhost/api`. If running backend directly (not in Docker), use `http://localhost:8000`

**Database migrations fail**
```
sqlalchemy.exc.OperationalError: could not connect to server
```
Solution: Database container isn't ready yet. Wait 10 seconds and try again. The healthcheck in `dev.compose.yml:13-17` ensures Postgres is accepting connections before backend starts

**Scans timeout on every test**
```
All tests return ERROR status
```
Solution: The target URL might be blocking requests. Try `https://httpbin.org/get` first to verify the scanner works. Check `SCANNER_CONNECTION_TIMEOUT` in `config.py:51` - default is 180 seconds

## Related Projects

If you found this interesting, check out:
- **network-traffic-analyzer** [network-traffic-analyzere](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/beginner/network-traffic-analyzer) - Goes deeper into packet analysis and protocol dissection, complements this by showing what's happening at the network layer
- **docker-security-audit** [docker-security-audit](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/intermediate/docker-security-audit) - Focuses on container security, teaches you to scan Docker images and configurations for vulnerabilities
- **bug-bounty-platform** [bug-bounty-platform](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/advanced/bug-bounty-platform) - Full platform for managing security findings, shows how professional security teams track and remediate issues

