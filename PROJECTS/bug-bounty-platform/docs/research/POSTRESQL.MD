# Production FastAPI + SQLAlchemy + PostgreSQL Template Guide (2025)

Modern Python web development in 2025 demands async-first patterns with SQLAlchemy 2.0's native async syntax, PostgreSQL-specific optimizations, and tooling like **uv** and **Ruff** that have become the new standard. This guide covers production-ready configurations, senior-level patterns, and critical anti-patterns to avoid—focusing on what's changed in 2025 rather than rehashing tutorials.

---

## SQLAlchemy 2.0+ async patterns have fundamentally changed

The transition from SQLAlchemy 1.4 to 2.0+ introduced breaking changes that remain misunderstood. **Use `async_sessionmaker` directly**—not the legacy `sessionmaker(class_=AsyncSession)` pattern still found in older tutorials.

```python
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    async_sessionmaker,
    AsyncSession,
    AsyncAttrs,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Single engine per service, created once at startup
engine = create_async_engine(
    "postgresql+asyncpg://user:pass@host/db",
    pool_size=25,
    max_overflow=15,
    pool_timeout=30,
    pool_pre_ping=True,  # Critical for production
    connect_args={
        "command_timeout": 30,
        "statement_cache_size": 200,
    },
)

# Create sessionmaker factory
SessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,  # CRITICAL: prevents MissingGreenlet errors
    autoflush=False,
)
```

The **`expire_on_commit=False`** setting is non-negotiable for async—without it, accessing any attribute after commit triggers implicit I/O, causing `MissingGreenlet` errors that crash your application.

### Model definition uses typed syntax exclusively

The old `Column(Integer)` style is deprecated. SQLAlchemy 2.0+ infers types from Python annotations:

```python
class Base(AsyncAttrs, DeclarativeBase):
    """Include AsyncAttrs for awaitable_attrs access."""
    pass

class User(Base):
    __tablename__ = "users"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True)
    nickname: Mapped[str | None] = mapped_column(String(50))  # Optional = nullable
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    
    # Relationships with proper async loading
    posts: Mapped[list["Post"]] = relationship(
        back_populates="author",
        lazy="selectin",  # NOT "select" which triggers implicit I/O
    )
```

**Key anti-pattern to avoid**: Using `lazy="select"` (the default) or `lazy="dynamic"` with async sessions. Both trigger implicit I/O. Use `lazy="selectin"` for collections or `lazy="raise"` to enforce explicit loading.

### Relationship loading requires upfront decisions

For async contexts, you must explicitly load relationships—there's no safe lazy loading:

```python
from sqlalchemy.orm import selectinload, joinedload

# Collections: use selectinload (emits SELECT with IN clause)
stmt = select(User).options(selectinload(User.posts))

# Scalar relationships: use joinedload
stmt = select(Post).options(joinedload(Post.author))

# Chaining for nested relationships
stmt = select(User).options(
    selectinload(User.posts).joinedload(Post.category)
)
```

When you need on-demand loading, use the `AsyncAttrs` mixin and `awaitable_attrs`:

```python
async with session:
    user = await session.get(User, user_id)
    posts = await user.awaitable_attrs.posts  # Explicit async load
```

---

## PostgreSQL configuration for async workloads

### Connection pool sizing follows a formula

PostgreSQL's wiki recommends: **connections ≈ (CPU cores × 2) + effective_spindle_count**. For async FastAPI with 100+ concurrent users:

| Scale | pool_size | max_overflow | Total Max |
|-------|-----------|--------------|-----------|
| Medium (100-500 users) | 20-25 | 10-15 | 40 |
| Large (500+ users) | 25-50 | 20-30 | 80 |

**Critical consideration**: Total connections across all workers must not exceed PostgreSQL's `max_connections`. With 4 uvicorn workers at `pool_size=25`, you're consuming 100 connections before overflow.

```python
engine = create_async_engine(
    DATABASE_URL,
    pool_size=25,
    max_overflow=15,
    pool_timeout=30,
    pool_recycle=1800,  # Recycle every 30 minutes
    pool_pre_ping=True,  # Test connections before use
    connect_args={
        "command_timeout": 30,  # Query timeout in seconds
        "statement_cache_size": 200,
        "ssl": "require",
    },
)
```

### PgBouncer requires special configuration

When using PgBouncer in transaction mode, disable asyncpg's prepared statement cache:

```python
from sqlalchemy.pool import NullPool

engine = create_async_engine(
    DATABASE_URL,
    poolclass=NullPool,  # Let PgBouncer handle pooling
    connect_args={
        "statement_cache_size": 0,  # Disable prepared statements
    },
)
```

### UUID v7 is now the recommended primary key strategy

PostgreSQL 18 (September 2025) added native `uuidv7()` function. UUID v7 stores a timestamp in the first 48 bits, providing:
- **Sequential ordering**: Optimal for B-tree indexes (unlike UUID v4's random fragmentation)
- **Distributed generation**: No database coordination required
- **Time-sortable**: Natural chronological ordering

```python
from sqlalchemy.dialects.postgresql import UUID

class Entity(Base):
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("uuidv7()"),  # PostgreSQL 18+
    )
```

For PostgreSQL < 18, use the `uuid6` Python library:

```python
import uuid6
id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid6.uuid7)
```

### PostgreSQL-specific indexes you should know

**GIN indexes** for JSONB containment queries:
```python
Index('ix_metadata_gin', 'metadata', postgresql_using='gin')
```

**Partial indexes** for frequently filtered subsets:
```python
Index('ix_active_users', 'email', postgresql_where=(User.is_active == True))
```

**BRIN indexes** for large, naturally-ordered tables (logs, time-series):
```python
Index('ix_created_at_brin', 'created_at', postgresql_using='brin')
```

---

## FastAPI architecture for scalable applications

### Domain-driven project structure scales better

The 2025 consensus favors **module-based organization** over file-type organization, inspired by Netflix's Dispatch project:

```
src/
├── auth/
│   ├── router.py
│   ├── schemas.py
│   ├── models.py
│   ├── service.py
│   └── dependencies.py
├── posts/
│   ├── router.py
│   ├── schemas.py
│   ├── models.py
│   ├── service.py
│   └── dependencies.py
├── config.py          # Global configuration
├── database.py        # Connection setup
└── main.py
```

Each domain package owns its complete vertical slice. Cross-domain imports use explicit module references to prevent circular imports:

```python
from src.auth import constants as auth_constants
from src.posts.service import PostService
```

### Modern dependency injection uses Annotated types

FastAPI's documentation now emphasizes `Annotated` for cleaner, reusable dependencies:

```python
from typing import Annotated, AsyncIterator
from fastapi import Depends

async def get_session() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise

# Reusable type alias
SessionDep = Annotated[AsyncSession, Depends(get_session)]

# Usage is clean
@router.post("/users")
async def create_user(data: UserCreate, session: SessionDep):
    user = User(**data.model_dump())
    session.add(user)
    return user
```

### Lifespan context manager replaces startup/shutdown events

The `@app.on_event("startup")` decorator is deprecated. Use the lifespan context manager:

```python
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # STARTUP
    app.state.db_engine = create_async_engine(DATABASE_URL)
    app.state.session_factory = async_sessionmaker(
        app.state.db_engine, expire_on_commit=False
    )
    
    # Warm the connection pool
    async with app.state.db_engine.begin() as conn:
        await conn.execute(text("SELECT 1"))
    
    yield  # Application runs
    
    # SHUTDOWN
    await app.state.db_engine.dispose()

app = FastAPI(lifespan=lifespan)
```

### Repository pattern versus direct ORM is contextual

The 2025 senior developer consensus:

**Use repository pattern when:**
- Complex business logic requiring transaction coordination
- Multiple data sources or potential database migrations
- Large teams needing clear boundaries
- Comprehensive unit testing requirements

**Direct ORM is acceptable when:**
- Simple CRUD operations
- Rapid prototyping or small services
- Using SQLModel where DTO/DAO are unified

A pragmatic repository implementation:

```python
from typing import Generic, TypeVar

T = TypeVar("T", bound=Base)

class BaseRepository(Generic[T]):
    def __init__(self, model: type[T], session: AsyncSession):
        self.model = model
        self.session = session
    
    async def get(self, id: int) -> T | None:
        return await self.session.get(self.model, id)
    
    async def create(self, data: dict) -> T:
        obj = self.model(**data)
        self.session.add(obj)
        await self.session.flush()
        await self.session.refresh(obj)
        return obj
```

### Background tasks need their own sessions

A critical anti-pattern: **never pass a database session to BackgroundTasks**. The session closes when the request completes, before the background task runs:

```python
# WRONG - session will be closed
@router.post("/")
async def endpoint(session: SessionDep, tasks: BackgroundTasks):
    tasks.add_task(some_task, session)  # ❌ Session already closed!

# CORRECT - create new session inside task
def background_db_task(user_id: int):
    with SessionLocal() as session:
        user = session.get(User, user_id)
        # Process...
        session.commit()

@router.post("/")
async def endpoint(user_id: int, tasks: BackgroundTasks):
    tasks.add_task(background_db_task, user_id)  # ✅ Pass data, not session
```

For heavy workloads, use **ARQ** (async Redis queue) or **Celery**—both create their own sessions.

---

## Alembic migrations for async environments

### Initialize with the async template

```bash
alembic init -t async migrations
```

The `env.py` requires careful configuration for SQLAlchemy 2.0+:

```python
# alembic/env.py
from sqlalchemy.ext.asyncio import async_engine_from_config
from sqlalchemy import pool
from app.db import Base
from app.models import *  # Import ALL models for autogenerate

target_metadata = Base.metadata

def do_run_migrations(connection):
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,  # Detect column type changes
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()

async def run_async_migrations():
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()
```

### Naming conventions prevent migration headaches

Define naming conventions in your Base class—this ensures consistent, predictable constraint names that Alembic can track:

```python
from sqlalchemy import MetaData

naming_convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=naming_convention)
```

### Zero-downtime migrations use expand-contract pattern

**Phase 1 (Expand)**: Add new columns as nullable, deploy application that writes to both
**Phase 2 (Migrate)**: Backfill data in batches
**Phase 3 (Contract)**: Add constraints, remove old columns

```python
# Phase 1: Add nullable column with server_default
def upgrade():
    op.add_column('users',
        sa.Column('email_verified', sa.Boolean(), 
                  server_default='false', nullable=False)
    )
```

Using `server_default` avoids table locks on large tables.

---

## Docker containerization for production

### Multi-stage builds reduce image size by 70%+

```dockerfile
# Stage 1: Builder
FROM python:3.12-slim AS builder
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Stage 2: Production
FROM python:3.12-slim AS production

RUN groupadd -r appuser && useradd -r -g appuser appuser
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 curl && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

COPY --chown=appuser:appuser ./app ./app
USER appuser

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["gunicorn", "app.main:app", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "-b", "0.0.0.0:8000"]
```

### Docker Compose with proper health checks

```yaml
services:
  api:
    build:
      context: .
      target: production
    depends_on:
      db:
        condition: service_healthy
    environment:
      - DATABASE_URL=postgresql+asyncpg://postgres:postgres@db:5432/app

  db:
    image: postgres:16-alpine
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s

  migrate:
    build: .
    command: ["alembic", "upgrade", "head"]
    depends_on:
      db:
        condition: service_healthy
    profiles: ["migrate"]
```

Run migrations separately: `docker compose --profile migrate up migrate`

---

## Authentication uses PyJWT and Argon2 in 2025

### python-jose is deprecated—use PyJWT

FastAPI's official documentation has switched to **PyJWT**. The `python-jose` library had Python 3.10+ compatibility issues and hasn't been updated since 2021:

```python
import jwt
from datetime import datetime, timedelta, timezone

SECRET_KEY = "your-256-bit-secret"  # openssl rand -hex 32
ALGORITHM = "HS256"

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
```

### Argon2id replaces bcrypt for password hashing

OWASP and the Password Hashing Competition recommend **Argon2id**. FastAPI's docs now use `pwdlib[argon2]`:

```python
from pwdlib import PasswordHash

password_hash = PasswordHash.recommended()  # Uses Argon2id

def verify_password(plain: str, hashed: str) -> bool:
    return password_hash.verify(plain, hashed)

def hash_password(password: str) -> str:
    return password_hash.hash(password)
```

Argon2id is memory-hard and GPU-resistant—bcrypt uses a fixed 4KB of memory, making it more vulnerable to parallel attacks.

### Token patterns for production

```python
# Access tokens: short-lived (15-30 min), stateless
# Refresh tokens: long-lived (7-30 days), stored in DB for revocation

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    token_hash: Mapped[str]  # Store hashed, never plain
    expires_at: Mapped[datetime]
    revoked: Mapped[bool] = mapped_column(default=False)
```

Implement **token rotation**: issue a new refresh token on each use and invalidate the old one.

---

## Python tooling has consolidated around uv and Ruff

### uv is replacing pip, Poetry, and pyenv

The Astral team's **uv** tool is 10-100x faster than alternatives and handles package management, virtual environments, and Python version management:

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create project
uv init my-project
uv add fastapi uvicorn sqlalchemy

# Sync dependencies
uv sync
```

### Modern pyproject.toml configuration

```toml
[project]
name = "my-fastapi-app"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "fastapi>=0.115.0",
    "uvicorn[standard]>=0.32.0",
    "sqlalchemy>=2.0.0",
    "asyncpg>=0.30.0",
    "pydantic-settings>=2.6.0",
    "pyjwt>=2.9.0",
    "pwdlib[argon2]>=0.2.0",
]

[dependency-groups]
dev = ["pytest>=8.0", "ruff>=0.8.0", "mypy>=1.13.0", "pre-commit>=4.0"]

[tool.ruff]
target-version = "py312"
line-length = 88

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B", "SIM", "C4", "DTZ", "T20", "RUF"]
```

### Ruff replaces Flake8, Black, and isort

A single tool for linting and formatting:

```bash
ruff check --fix .  # Lint with auto-fix
ruff format .       # Format code
```

### Pydantic Settings v2 for configuration

```python
from pydantic import SecretStr, PostgresDsn
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_nested_delimiter="__",
        secrets_dir="/run/secrets",  # Docker secrets
    )
    
    database_url: PostgresDsn
    secret_key: SecretStr
    debug: bool = False

settings = Settings()
```

---

## Critical anti-patterns to avoid

**Never share AsyncSession between concurrent tasks**:
```python
# WRONG
await asyncio.gather(process(session, a), process(session, b))

# CORRECT - each task gets its own session
async def process_item(item):
    async with SessionLocal() as session:
        ...
await asyncio.gather(process_item(a), process_item(b))
```

**Don't use legacy Query API**:
```python
# DEPRECATED
session.query(User).filter(User.id == 1).first()

# CORRECT
await session.execute(select(User).where(User.id == 1))
result.scalars().first()
```

**Always dispose engine on shutdown**:
```python
await engine.dispose()  # In lifespan shutdown
```

**Don't forget pool_pre_ping in production**—without it, your app will crash when PostgreSQL restarts and connections go stale.

## Conclusion

Building production FastAPI applications in 2025 requires embracing SQLAlchemy 2.0's typed, async-native syntax while avoiding legacy patterns that still pollute many tutorials. The tooling landscape has consolidated: **uv** for package management, **Ruff** for linting, **PyJWT** for tokens, and **Argon2id** for passwords.

The most impactful changes are architectural: using domain-driven project structure, implementing proper connection pool sizing for your scale, and understanding that async sessions cannot be shared or lazily loaded. UUID v7's addition to PostgreSQL 18 finally makes distributed primary keys performant, and the expand-contract migration pattern enables zero-downtime deployments.

Focus on these production fundamentals rather than chasing every new library—the core stack of FastAPI, SQLAlchemy 2.0+, asyncpg, and PostgreSQL is mature and battle-tested.
