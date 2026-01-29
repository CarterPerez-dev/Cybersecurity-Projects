# Architecture Deep Dive

This document provides an in-depth explanation of the Bug Bounty Platform's architecture, design decisions, and the reasoning behind technical choices.

---

## Table of Contents

1. [Overview](#overview)
2. [High-Level Architecture](#high-level-architecture)
3. [Backend Architecture](#backend-architecture)
4. [Frontend Architecture](#frontend-architecture)
5. [Database Design](#database-design)
6. [Security Architecture](#security-architecture)
7. [Infrastructure](#infrastructure)
8. [Design Decisions](#design-decisions)

---

## Overview

This platform is built using a modern, production-ready architecture that emphasizes:

1. **Separation of Concerns** - Clear boundaries between layers
2. **Type Safety** - Compile-time guarantees in both backend and frontend
3. **Async-First** - Scalable concurrent operations
4. **Security by Design** - Multiple defense layers
5. **Developer Experience** - Hot reload, linting, type checking
6. **Production Ready** - Containerized, migrated, monitored

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Client Browser                        │
│                  (React + TypeScript SPA)                    │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTPS
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                       Nginx (Reverse Proxy)                  │
│  - Serves static React build                                 │
│  - Proxies /api/* to FastAPI backend                         │
│  - Gzip compression + security headers                       │
└────────────────────────┬────────────────────────────────────┘
                         │
        ┌────────────────┴────────────────┐
        │                                 │
        ▼                                 ▼
┌────────────────────┐          ┌────────────────────┐
│  FastAPI Backend   │◄────────►│  Redis (Cache)     │
│  (Python 3.12+)    │          │  - Sessions        │
│  - REST API        │          │  - Rate limiting   │
│  - JWT Auth        │          └────────────────────┘
│  - Business Logic  │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│  PostgreSQL 18     │
│  - Primary data    │
│  - UUID v7 PKs     │
│  - ACID guarantees │
└────────────────────┘
```

### Why This Architecture?

**Traditional Monolith vs. Microservices:**
- This is a **modular monolith** - easier to develop, deploy, and debug than microservices
- Services can be extracted into microservices later if needed
- Single database = ACID transactions across all entities

**Why Nginx?**
- Production-grade reverse proxy
- Static file serving for React build
- Gzip compression reduces bandwidth
- SSL/TLS termination
- Load balancing (if scaled horizontally)

**Why Redis?**
- Fast in-memory cache for session data
- Rate limiting without hitting PostgreSQL
- Can be used for pub/sub (WebSockets) if needed later

---

## Backend Architecture

### Layered Architecture

The backend follows a **strict layered architecture**:

```
┌──────────────────────────────────────────────────────────┐
│                    Routes (API Layer)                     │
│  - HTTP request/response handling                         │
│  - Input validation (Pydantic schemas)                    │
│  - Dependency injection                                   │
│  - OpenAPI documentation                                  │
└────────────────────────┬─────────────────────────────────┘
                         │ calls
                         ▼
┌──────────────────────────────────────────────────────────┐
│                  Services (Business Logic)                │
│  - Core business rules                                    │
│  - Orchestrates multiple repositories                     │
│  - Transaction management                                 │
│  - Domain logic                                           │
└────────────────────────┬─────────────────────────────────┘
                         │ calls
                         ▼
┌──────────────────────────────────────────────────────────┐
│               Repositories (Data Access)                  │
│  - CRUD operations                                        │
│  - Query building                                         │
│  - Database interaction                                   │
│  - No business logic                                      │
└────────────────────────┬─────────────────────────────────┘
                         │ operates on
                         ▼
┌──────────────────────────────────────────────────────────┐
│                  Models (Database Entities)               │
│  - SQLAlchemy ORM models                                  │
│  - Relationships                                          │
│  - Database schema definition                             │
└──────────────────────────────────────────────────────────┘
```

### Example: User Login Flow

Let's trace a login request through the layers:

```python
# 1. Route Layer (backend/app/auth/routes.py)
@router.post("/login")
async def login(
    credentials: LoginRequest,
    session: DatabaseSession,
) -> TokenResponse:
    access_token, refresh_token = await authenticate_user(
        session=session,
        email=credentials.email,
        password=credentials.password,
        device_info=credentials.device_info,
    )
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
    )
```

The route handler:
- Receives HTTP POST request at `/api/v1/auth/login`
- Validates input using `LoginRequest` Pydantic model
- Injects database session via FastAPI's `Depends()`
- Calls service function `authenticate_user()`
- Returns response as `TokenResponse` Pydantic model

```python
# 2. Service Layer (backend/app/auth/service.py)
async def authenticate_user(
    session: AsyncSession,
    email: str,
    password: str,
    device_info: str | None,
) -> tuple[str, str]:
    user_repo = UserRepository(session)

    # Find user by email
    user = await user_repo.find_by_email(email)
    if not user:
        raise InvalidCredentialsError()

    # Verify password (timing-safe comparison)
    if not security.verify_password(password, user.password_hash):
        raise InvalidCredentialsError()

    # Create tokens
    access_token = security.create_access_token(user)
    refresh_token = security.create_refresh_token()

    # Store refresh token in database
    token_repo = RefreshTokenRepository(session)
    await token_repo.create_refresh_token(
        user_id=user.id,
        token=refresh_token,
        device_info=device_info,
    )

    await session.commit()

    return access_token, refresh_token
```

The service layer:
- Implements business logic (authentication rules)
- Coordinates multiple repositories (User + RefreshToken)
- Handles password verification securely
- Creates JWT tokens
- Manages transactions (commit)
- Throws domain exceptions (`InvalidCredentialsError`)

```python
# 3. Repository Layer (backend/app/user/repository.py)
class UserRepository(BaseRepository[User]):
    async def find_by_email(self, email: str) -> User | None:
        stmt = select(User).where(User.email == email)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
```

The repository:
- Builds SQL query using SQLAlchemy
- Executes query against database
- Returns ORM model or None
- No business logic - pure data access

```python
# 4. Model Layer (backend/app/user/models.py)
class User(Base):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    full_name: Mapped[str] = mapped_column(String(255))
    role: Mapped[UserRole] = mapped_column(Enum(UserRole))

    # Relationships
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )
```

The model:
- Defines database schema
- Maps Python classes to database tables
- Declares relationships between entities
- Provides type hints for all fields

### Why Layers?

**Separation of Concerns:**
- Routes don't know about database queries
- Services don't know about HTTP
- Repositories don't implement business rules
- Models are pure data structures

**Testability:**
- Mock repositories to test services
- Mock services to test routes
- Unit test each layer independently

**Maintainability:**
- Change database? Update repositories only
- Change business logic? Update services only
- Change API format? Update routes and schemas only

**Type Safety:**
- Each layer has strict type annotations
- MyPy verifies types at compile time
- Refactoring is safe and predictable

---

## Module Structure

### Domain-Driven Design (DDD)

Each domain module is self-contained:

```
backend/src/app/user/
├── __init__.py
├── models.py          # User database model
├── repository.py      # UserRepository
├── schemas.py         # Pydantic request/response models
├── routes.py          # API endpoints
├── service.py         # Business logic functions
└── exceptions.py      # Domain-specific exceptions
```

**Why this structure?**
- All user-related code is in one place
- Easy to find relevant files
- Can be extracted to a separate service later
- Clear ownership and boundaries

### Core Module

```
backend/src/app/core/
├── Base.py                # Base model classes (UUIDMixin, etc.)
├── base_repository.py     # Generic repository with CRUD
├── database.py            # Database session management
├── security.py            # Password hashing, JWT creation
├── dependencies.py        # FastAPI dependencies (auth, etc.)
├── exceptions.py          # Base exception classes
├── enums.py               # SafeEnum pattern
├── logging.py             # Structured logging
├── rate_limit.py          # Rate limiting configuration
└── constants.py           # String length constraints
```

The core module provides:
- Reusable base classes
- Shared utilities
- Database connection management
- Security primitives

---

## Frontend Architecture

### Component-Based Architecture

React's component model enables:
- **Reusability:** UI elements as self-contained components
- **Composability:** Complex UIs from simple pieces
- **Maintainability:** Change one component without breaking others

```
frontend/src/
├── routes/                    # File-based routing
│   ├── landing/              # Public landing page
│   ├── login/                # Authentication
│   ├── dashboard/            # User dashboard
│   ├── programs/             # Browse programs
│   │   └── [slug]/          # Dynamic route for program detail
│   ├── company/              # Company dashboard (nested routes)
│   │   ├── programs/        # Manage programs
│   │   ├── inbox/           # Incoming reports
│   │   └── reports/         # Report triage
│   └── admin/                # Admin panel
│
├── components/                # Reusable UI components
│   ├── common/               # Shared components (Button, Card, etc.)
│   ├── forms/                # Form components
│   └── layouts/              # Layout components (Shell, etc.)
│
├── api/                       # Backend integration
│   ├── hooks/                # React Query hooks (useAuth, usePrograms)
│   ├── types/                # TypeScript interfaces
│   └── index.ts              # Axios client configuration
│
├── stores/                    # State management (Zustand)
│   ├── auth.store.ts         # Authentication state
│   ├── shell.ui.store.ts     # UI state (sidebar, modals)
│   └── *.form.store.ts       # Form state
│
└── core/                      # App configuration
    ├── app/                  # App setup (router, providers)
    ├── styles/               # Global styles
    └── config.ts             # Constants and configuration
```

### State Management Strategy

The frontend uses a **hybrid state management approach**:

```
┌─────────────────────────────────────────────────────────┐
│              Server State (TanStack Query)               │
│  - API data (users, programs, reports)                   │
│  - Automatic caching and revalidation                    │
│  - Loading/error states                                  │
│  - Optimistic updates                                    │
└─────────────────────────────────────────────────────────┘
                         +
┌─────────────────────────────────────────────────────────┐
│              Client State (Zustand)                      │
│  - UI state (sidebar open/closed, modals)                │
│  - Form state (program creation, report submission)      │
│  - Authentication tokens (persisted to localStorage)     │
└─────────────────────────────────────────────────────────┘
```

**Why two state management libraries?**

1. **TanStack Query for server state:**
   - Automatic caching (no need to manually cache API responses)
   - Background refetching (keeps data fresh)
   - Loading and error states out of the box
   - Optimistic updates for better UX
   - Pagination and infinite scroll support

2. **Zustand for client state:**
   - Simple API (less boilerplate than Redux)
   - TypeScript-first design
   - Persistence support (auth tokens)
   - No provider wrapper needed
   - Minimal re-renders

**Example: Fetching programs with TanStack Query**

```typescript
// api/hooks/usePrograms.ts
export const usePrograms = (params?: ProgramQueryParams) => {
  return useQuery({
    queryKey: ["programs", params],
    queryFn: () => api.get<ProgramListResponse>("/programs", { params }),
    staleTime: 5 * 60 * 1000, // 5 minutes
  });
};

// In component
function ProgramList() {
  const { data, isLoading, error } = usePrograms({ page: 1, limit: 20 });

  if (isLoading) return <LoadingSpinner />;
  if (error) return <ErrorMessage error={error} />;

  return (
    <div>
      {data.items.map(program => (
        <ProgramCard key={program.id} program={program} />
      ))}
    </div>
  );
}
```

TanStack Query automatically:
- Caches the response (keyed by `["programs", params]`)
- Shows loading state while fetching
- Refetches on window focus (configurable)
- Deduplicates concurrent requests
- Provides error handling

**Example: UI state with Zustand**

```typescript
// stores/shell.ui.store.ts
interface ShellUIStore {
  sidebarOpen: boolean;
  toggleSidebar: () => void;
}

export const useShellUIStore = create<ShellUIStore>((set) => ({
  sidebarOpen: true,
  toggleSidebar: () => set((state) => ({
    sidebarOpen: !state.sidebarOpen
  })),
}));

// In component
function Sidebar() {
  const { sidebarOpen, toggleSidebar } = useShellUIStore();

  return (
    <aside className={sidebarOpen ? "open" : "closed"}>
      <button onClick={toggleSidebar}>Toggle</button>
    </aside>
  );
}
```

Zustand provides:
- Simple hook-based API
- No provider wrapper
- TypeScript support
- Minimal re-renders (only components using the changed state)

### File-Based Routing

Using React Router 7's file-based routing:

```
routes/
├── landing/
│   └── page.tsx               # → /
├── login/
│   └── page.tsx               # → /login
├── programs/
│   ├── page.tsx               # → /programs
│   └── [slug]/
│       └── page.tsx           # → /programs/:slug
└── company/
    ├── layout.tsx             # Shared layout for /company/*
    ├── programs/
    │   ├── page.tsx           # → /company/programs
    │   └── [id]/
    │       └── page.tsx       # → /company/programs/:id
    └── inbox/
        └── page.tsx           # → /company/inbox
```

**Benefits:**
- Route structure mirrors file structure
- Automatic code splitting (each route is a separate chunk)
- Nested layouts (company routes share a layout)
- Dynamic routes with `[param]` syntax

---

## Database Design

### Schema Overview

```
┌──────────────┐
│    users     │
│──────────────│
│ id (UUID v7) │◄───┐
│ email        │    │
│ password     │    │
│ role         │    │
└──────────────┘    │
                    │
      ┌─────────────┴──────────────┬────────────────┐
      │                            │                │
      ▼                            ▼                ▼
┌───────────────┐          ┌─────────────┐  ┌────────────┐
│refresh_tokens │          │  programs   │  │  reports   │
│───────────────│          │─────────────│  │────────────│
│ id            │          │ id          │  │ id         │
│ user_id (FK)  │          │ owner_id FK │  │ author_id  │
│ token_hash    │          │ name        │  │ program_id │
│ device_info   │          │ slug        │  │ title      │
│ family_id     │          │ status      │  │ severity   │
└───────────────┘          └─────────────┘  └────────────┘
                                  │
                      ┌───────────┴───────────┐
                      ▼                       ▼
                ┌──────────┐          ┌──────────────┐
                │  assets  │          │ reward_tiers │
                │──────────│          │──────────────│
                │ id       │          │ id           │
                │ program  │          │ program_id   │
                │ type     │          │ severity     │
                │ target   │          │ amount       │
                └──────────┘          └──────────────┘
```

### UUID v7 Primary Keys

Traditional auto-increment IDs have problems:
- Predictable (security risk - enumerate all records)
- Not globally unique (can't merge databases)
- Require database round-trip to generate

UUIDs solve this but have their own issues:
- UUID v4 is random (bad for database indexing)
- Not time-sortable (can't ORDER BY id to get chronological order)

**UUID v7 is the best of both worlds:**
- Time-sortable (first 48 bits are Unix timestamp in milliseconds)
- Globally unique (no collisions even across databases)
- Good for database indexes (lexicographic order = chronological order)
- Secure (remaining bits are random)

```python
import uuid_utils as uuid

# Generate UUID v7
user_id = uuid.uuid7()  # → 018d3f54-8c3a-7000-a234-56789abcdef0
                        #    ^^^^^^^^^^^^^^^^ ← timestamp
                        #                     ^^^^^^^^^^^^^^^^^^^ ← random
```

### SafeEnum Pattern

Traditional enums in SQLAlchemy store the enum name:

```python
class Status(enum.Enum):
    ACTIVE = "active"
    PAUSED = "paused"

# Database stores: "ACTIVE" (the Python name)
```

**Problem:** If you rename the Python enum, the database breaks:

```python
class Status(enum.Enum):
    RUNNING = "active"  # Renamed ACTIVE → RUNNING
    PAUSED = "paused"

# Database still has "ACTIVE", but Python doesn't recognize it!
```

**SafeEnum solution:** Store the value, not the name:

```python
class Status(SafeEnum):
    ACTIVE = "active"
    PAUSED = "paused"

# Database stores: "active" (the value)
```

Now you can safely rename:

```python
class Status(SafeEnum):
    RUNNING = "active"  # Value is still "active"
    PAUSED = "paused"

# Database has "active", Python maps it to Status.RUNNING ✓
```

### Soft Deletes vs Hard Deletes

Some models use **soft deletes** (set `deleted_at` timestamp instead of removing row):

```python
class SoftDeleteMixin:
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
    )
```

**When to use soft deletes:**
- User accounts (compliance requirements - keep audit trail)
- Financial records (never truly delete)
- Reports (preserve history even if program is deleted)

**When to use hard deletes:**
- Session tokens (no need to keep after logout)
- Temporary data (caches, OTPs)
- GDPR deletion requests (must truly delete)

---

## Security Architecture

### Multi-Layer Defense

Security is implemented at multiple layers:

```
┌──────────────────────────────────────────────────────┐
│  1. Input Validation (Pydantic)                       │
│     - Type checking                                   │
│     - String length limits                            │
│     - Email/URL format validation                     │
└────────────────────────┬─────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────┐
│  2. Authentication (JWT)                              │
│     - Token-based auth                                │
│     - Short-lived access tokens (15 min)              │
│     - Long-lived refresh tokens (7 days)              │
│     - Token versioning                                │
└────────────────────────┬─────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────┐
│  3. Authorization (RBAC)                              │
│     - Role-based access control                       │
│     - Resource ownership checks                       │
│     - Admin-only endpoints                            │
└────────────────────────┬─────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────┐
│  4. Rate Limiting                                     │
│     - 100 req/min default                             │
│     - 20 req/min for auth endpoints                   │
│     - Per-IP tracking                                 │
└────────────────────────┬─────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────┐
│  5. Secure Storage                                    │
│     - Argon2id password hashing                       │
│     - Hashed refresh tokens (not plaintext)           │
│     - Encrypted secrets in env vars                   │
└──────────────────────────────────────────────────────┘
```

### JWT Token Flow

```
User Login
   │
   ▼
┌──────────────────────────────────────┐
│  1. POST /api/v1/auth/login          │
│     { email, password }              │
└────────────┬─────────────────────────┘
             │
             ▼
┌──────────────────────────────────────┐
│  2. Verify password (Argon2id)       │
│     - Timing-safe comparison         │
└────────────┬─────────────────────────┘
             │
             ▼
┌──────────────────────────────────────┐
│  3. Generate tokens                  │
│     - access_token (15 min)          │
│     - refresh_token (7 days)         │
└────────────┬─────────────────────────┘
             │
             ▼
┌──────────────────────────────────────┐
│  4. Store refresh token in DB        │
│     - Hashed (not plaintext)         │
│     - With device info and IP        │
│     - Family ID for replay detection │
└────────────┬─────────────────────────┘
             │
             ▼
┌──────────────────────────────────────┐
│  5. Return tokens to client          │
│     { access_token, refresh_token }  │
└──────────────────────────────────────┘
```

**Access token payload:**
```json
{
  "sub": "018d3f54-8c3a-7000-a234-56789abcdef0",  // user_id
  "role": "USER",
  "token_version": 1,
  "exp": 1704123456,  // expires in 15 minutes
  "iat": 1704122556
}
```

**Why short-lived access tokens?**
- If stolen, attacker only has 15 minutes
- No way to revoke access tokens (they're stateless)
- Must use refresh token to get new access token

**Refresh token flow:**

```
Access token expires (15 min)
   │
   ▼
┌──────────────────────────────────────┐
│  1. POST /api/v1/auth/refresh        │
│     { refresh_token }                │
└────────────┬─────────────────────────┘
             │
             ▼
┌──────────────────────────────────────┐
│  2. Verify refresh token in DB       │
│     - Check hash matches             │
│     - Check not expired              │
│     - Check not revoked              │
└────────────┬─────────────────────────┘
             │
             ▼
┌──────────────────────────────────────┐
│  3. Token rotation                   │
│     - Delete old refresh token       │
│     - Generate new refresh token     │
│     - Store new token in DB          │
└────────────┬─────────────────────────┘
             │
             ▼
┌──────────────────────────────────────┐
│  4. Generate new access token        │
│     - Same user_id                   │
│     - Incremented token_version      │
└────────────┬─────────────────────────┘
             │
             ▼
┌──────────────────────────────────────┐
│  5. Return new tokens                │
│     { access_token, refresh_token }  │
└──────────────────────────────────────┘
```

**Token rotation prevents replay attacks:**
- Each refresh token is single-use
- If an attacker steals a refresh token, it becomes invalid after one use
- If a refresh token is reused, we detect it (family ID mismatch) and revoke all tokens for that user

### Token Versioning

Token versioning allows instant invalidation:

```python
class User(Base):
    token_version: Mapped[int] = mapped_column(Integer, default=1)

# When user changes password:
user.token_version += 1
await session.commit()
```

Now all existing access tokens become invalid:
- Old tokens have `token_version: 1`
- User's current `token_version` is `2`
- Token verification fails: `1 != 2`

No need to maintain a token blacklist!

---

## Infrastructure

### Docker Compose Architecture

**Production (`compose.yml`):**

```yaml
services:
  nginx:
    build: ./infra/nginx
    ports:
      - "${NGINX_HOST_PORT}:80"
    depends_on:
      - backend

  backend:
    build: ./backend
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - REDIS_URL=${REDIS_URL}
      - SECRET_KEY=${SECRET_KEY}
    depends_on:
      - db
      - redis

  db:
    image: postgres:18-alpine
    volumes:
      - postgres_data:/var/lib/postgresql/data
    environment:
      - POSTGRES_USER=${POSTGRES_USER}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
      - POSTGRES_DB=${POSTGRES_DB}

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
```

**Why this structure?**
- **nginx depends on backend:** Nginx can't start until backend is ready
- **backend depends on db + redis:** Backend needs database and cache
- **Volumes for data persistence:** Database and Redis data survives container restarts

### Multi-Stage Docker Builds

**Backend Dockerfile:**

```dockerfile
# Stage 1: Build dependencies
FROM python:3.12-slim as builder
WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

# Stage 2: Production image
FROM python:3.12-slim
WORKDIR /app
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY ./src ./src
CMD ["gunicorn", "main:app"]
```

**Benefits:**
- Smaller final image (no build tools)
- Faster builds (dependencies cached in builder stage)
- More secure (no build dependencies in production)

**Frontend Dockerfile (Nginx):**

```dockerfile
# Stage 1: Build React app
FROM node:22-alpine as builder
WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN pnpm install
COPY . .
RUN pnpm build

# Stage 2: Serve with Nginx
FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/nginx.conf
```

**Benefits:**
- No Node.js in production image
- Nginx is optimized for serving static files
- Smaller final image (~50MB vs ~500MB)

---

## Design Decisions

### Why FastAPI?

**Compared to Flask:**
- Async/await support (FastAPI wins)
- Automatic OpenAPI docs (FastAPI wins)
- Data validation built-in with Pydantic (FastAPI wins)
- Type hints for IDE autocomplete (FastAPI wins)

**Compared to Django:**
- Async ORM support (tie - Django 4.1+ has it)
- Flexibility (FastAPI wins - Django is opinionated)
- Admin panel (Django wins)
- Batteries included (Django wins - has auth, admin, etc.)

**Decision:** FastAPI for its async-first design and modern Python features.

### Why PostgreSQL?

**Compared to MySQL:**
- JSON support (tie)
- Full-text search (PostgreSQL wins)
- ACID compliance (tie)
- JSON indexes (PostgreSQL wins)

**Compared to MongoDB:**
- ACID transactions (PostgreSQL wins)
- Schema validation (tie - Postgres has JSON schema)
- Joins (PostgreSQL wins)
- Flexibility (MongoDB wins for unstructured data)

**Decision:** PostgreSQL for ACID guarantees and relational data modeling.

### Why React + TypeScript?

**Compared to Vue:**
- Ecosystem size (React wins)
- TypeScript support (tie)
- Learning curve (Vue wins - easier)
- Corporate backing (tie - React by Meta, Vue independent)

**Compared to Svelte:**
- Maturity (React wins)
- Job market (React wins)
- Bundle size (Svelte wins)
- Learning curve (Svelte wins)

**Decision:** React + TypeScript for its mature ecosystem and industry adoption.

### Why Zustand?

**Compared to Redux:**
- Boilerplate (Zustand wins - much simpler)
- DevTools (Redux wins - more mature)
- Middleware (tie)
- Bundle size (Zustand wins)

**Compared to Context API:**
- Performance (Zustand wins - no unnecessary re-renders)
- Persistence (Zustand wins - built-in)
- DX (Zustand wins - simpler API)

**Decision:** Zustand for its simplicity and performance.

### Why TanStack Query?

**Compared to Redux Toolkit Query:**
- Flexibility (TanStack wins - not tied to Redux)
- Cache management (tie)
- Bundle size (TanStack wins)
- Learning curve (tie)

**Compared to SWR:**
- Features (TanStack wins - more complete)
- Bundle size (SWR wins)
- Pagination (TanStack wins)
- Community (tie)

**Decision:** TanStack Query for its comprehensive feature set and framework-agnostic design.

---

## Performance Considerations

### Database Indexing

Indexes are created for frequently queried columns:

```python
class User(Base):
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True  # ← Index for fast lookups
    )
```

**Trade-off:**
- Faster reads (queries using email are fast)
- Slower writes (index must be updated on insert/update)
- More disk space (index is stored separately)

### Connection Pooling

Database connections are expensive to create. Connection pooling reuses connections:

```python
DB_POOL_SIZE=20          # Max connections in pool
DB_MAX_OVERFLOW=10       # Extra connections when pool is full
DB_POOL_TIMEOUT=30       # Wait 30s for available connection
DB_POOL_RECYCLE=1800     # Recycle connections after 30min
```

**How it works:**
1. Request arrives
2. Backend grabs connection from pool
3. Executes query
4. Returns connection to pool (doesn't close it)
5. Next request reuses same connection

**Benefits:**
- Faster request handling (no connection overhead)
- Reduced database load (fewer connection negotiations)
- Better scalability (handle more concurrent requests)

### Redis Caching

Redis is used for frequently accessed data:

```python
# Without cache
user = await user_repo.find_by_id(user_id)  # Database query every time

# With cache
user = await redis.get(f"user:{user_id}")
if not user:
    user = await user_repo.find_by_id(user_id)
    await redis.set(f"user:{user_id}", user, ex=300)  # Cache for 5 min
```

**Cache invalidation strategies:**
1. Time-based (TTL) - expire after N seconds
2. Event-based - invalidate on update/delete
3. LRU (Least Recently Used) - Redis automatically evicts old keys

### Frontend Code Splitting

Vite automatically splits code by route:

```typescript
// routes/dashboard/page.tsx is lazy-loaded
const Dashboard = lazy(() => import('./routes/dashboard/page'));
```

**Benefits:**
- Faster initial page load (only load landing page)
- Subsequent navigation is fast (chunks are cached)
- Better bandwidth usage (don't load admin panel for regular users)

---

## Conclusion

This architecture prioritizes:
1. **Developer Experience** - Hot reload, type safety, linting
2. **Security** - Multiple defense layers, modern auth patterns
3. **Scalability** - Async operations, connection pooling, caching
4. **Maintainability** - Clear layer separation, domain-driven design
5. **Production Readiness** - Containerization, migrations, monitoring

Every design decision has trade-offs. This architecture favors correctness, security, and maintainability over raw performance (which can be optimized later if needed).

For more details on specific topics:
- Design patterns: [PATTERNS.md](./PATTERNS.md)
- Database schema: [DATABASE.md](./DATABASE.md)
- Security implementation: [SECURITY.md](./SECURITY.md)
- Step-by-step tutorial: [GETTING-STARTED.md](./GETTING-STARTED.md)
