# Production-Grade FastAPI Boilerplate: 2025 Best Practices

**The 2025 FastAPI ecosystem has matured significantly**, with clear conventions emerging around async-first patterns, Pydantic v2, SQLAlchemy 2.0+, and modern tooling like uv and Ruff. This guide synthesizes the latest practices for building production-grade FastAPI applications following a layered architecture: Models → Repositories → Services → Routes.

## Project structure for medium-large applications

The **feature-based (domain-driven) organization** pattern, popularized by Netflix's Dispatch project, is now the recommended approach for medium-large applications—scaling better than traditional file-type organization.

```
fastapi-project/
├── alembic/                          # Database migrations
│   ├── versions/
│   └── env.py
├── src/
│   ├── __init__.py
│   ├── main.py                       # FastAPI app, lifespan events
│   ├── core/                         # Shared infrastructure
│   │   ├── __init__.py
│   │   ├── config.py                 # Pydantic Settings
│   │   ├── database.py               # Async session manager
│   │   ├── security.py               # Auth utilities
│   │   ├── exceptions.py             # Global exception classes
│   │   └── dependencies.py           # Shared dependencies
│   ├── auth/                         # Feature module
│   │   ├── __init__.py
│   │   ├── router.py                 # Thin routes
│   │   ├── schemas.py                # Pydantic request/response
│   │   ├── models.py                 # SQLAlchemy models
│   │   ├── repository.py             # DB operations (static methods)
│   │   ├── service.py                # Business logic
│   │   ├── dependencies.py           # Module-specific deps
│   │   ├── constants.py              # Error codes, enums
│   │   └── exceptions.py             # Module exceptions
│   ├── users/
│   │   ├── router.py
│   │   ├── schemas.py
│   │   ├── models.py
│   │   ├── repository.py
│   │   └── service.py
│   └── posts/
│       └── ...
├── tests/
│   ├── conftest.py
│   ├── factories/                    # Test data factories
│   ├── unit/
│   │   ├── services/
│   │   └── repositories/
│   └── integration/
│       └── api/
├── pyproject.toml
├── Dockerfile
├── docker-compose.yml
├── nginx/nginx.conf
└── .pre-commit-config.yaml
```

**Key architectural principles** include using explicit module imports to prevent circular dependencies (`from src.auth import constants as auth_constants`), keeping routes thin by delegating all business logic to services, and ensuring repositories handle only database operations without business logic.

## Modern pyproject.toml configuration

**uv** has emerged as the preferred package manager in 2025, developed by Astral (creators of Ruff), offering dramatically faster dependency resolution than Poetry or pip.

```toml
[project]
name = "fastapi-app"
version = "1.0.0"
description = "Production FastAPI Application"
requires-python = ">=3.12"

dependencies = [
    "fastapi[standard]>=0.115.0,<1.0.0",
    "pydantic>=2.9.0,<3.0.0",
    "pydantic-settings>=2.6.0,<3.0.0",
    "sqlalchemy>=2.0.0,<3.0.0",
    "alembic>=1.13.0,<2.0.0",
    "asyncpg>=0.29.0,<1.0.0",
    "python-multipart>=0.0.9",
    "pyjwt>=2.9.0",
    "pwdlib[argon2]>=0.2.0",
    "slowapi>=0.1.9",
    "redis>=5.0.0",
    "structlog>=24.0.0",
    "gunicorn>=22.0.0",
    "uvicorn[standard]>=0.30.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0.0",
    "pytest-asyncio>=0.24.0",
    "pytest-cov>=5.0.0",
    "httpx>=0.27.0",
    "factory-boy>=3.3.0",
    "asgi-lifespan>=2.1.0",
    "mypy>=1.13.0",
    "ruff>=0.8.0",
    "pre-commit>=4.0.0",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.ruff]
target-version = "py312"
line-length = 88
src = ["src"]

[tool.ruff.lint]
select = [
    "E", "W", "F", "I", "B", "C4", "UP", "ARG", 
    "SIM", "TCH", "PTH", "RUF", "ASYNC", "S", "N"
]
ignore = ["E501", "B008", "PLR0913", "S101"]

[tool.ruff.lint.isort]
known-first-party = ["src"]

[tool.mypy]
python_version = "3.12"
strict = true
plugins = ["pydantic.mypy"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
asyncio_default_fixture_loop_scope = "function"
testpaths = ["tests"]
addopts = "-ra -q --cov=src --cov-report=term-missing"
```

The version pinning strategy uses **compatible release ranges** (`>=2.0.0,<3.0.0`) in pyproject.toml while letting lock files (`uv.lock`) handle exact versions.

## Pydantic Settings v2 for configuration management

```python
# src/core/config.py
from functools import lru_cache
from typing import Literal
from pydantic import Field, PostgresDsn, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    APP_NAME: str = "FastAPI App"
    ENVIRONMENT: Literal["development", "staging", "production"] = "development"
    DEBUG: bool = False

    # Database
    DATABASE_URL: PostgresDsn
    DB_POOL_SIZE: int = 5
    DB_MAX_OVERFLOW: int = 10

    # Security
    SECRET_KEY: str = Field(..., min_length=32)
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    ALGORITHM: str = "HS256"

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]

    @model_validator(mode="after")
    def validate_production_settings(self) -> "Settings":
        if self.ENVIRONMENT == "production" and self.DEBUG:
            raise ValueError("DEBUG must be False in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()

settings = get_settings()
```

**Module-specific settings** can use `env_prefix` to namespace environment variables:

```python
# src/auth/config.py
from pydantic_settings import BaseSettings, SettingsConfigDict

class AuthConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AUTH_", env_file=".env")
    
    JWT_SECRET: str
    JWT_ALG: str = "HS256"
    JWT_EXP: int = 30  # minutes
```

## Async SQLAlchemy 2.0+ with session management

The **DatabaseSessionManager pattern** provides clean lifecycle management for async database connections:

```python
# src/core/database.py
import contextlib
from typing import AsyncIterator
from sqlalchemy.ext.asyncio import (
    AsyncConnection, AsyncSession, async_sessionmaker, create_async_engine
)
from sqlalchemy.pool import AsyncAdaptedQueuePool


class DatabaseSessionManager:
    def __init__(self, url: str, **engine_kwargs):
        self._engine = create_async_engine(
            url,
            poolclass=AsyncAdaptedQueuePool,
            pool_size=5,
            max_overflow=10,
            pool_pre_ping=True,
            echo=False,
            **engine_kwargs
        )
        self._sessionmaker = async_sessionmaker(
            autocommit=False,
            autoflush=False,
            expire_on_commit=False,
            bind=self._engine,
            class_=AsyncSession
        )

    async def close(self):
        await self._engine.dispose()

    @contextlib.asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        session = self._sessionmaker()
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


sessionmanager = DatabaseSessionManager(str(settings.DATABASE_URL))


async def get_db_session() -> AsyncIterator[AsyncSession]:
    async with sessionmanager.session() as session:
        yield session
```

**SQLAlchemy 2.0 models** use `Mapped` type hints with `lazy="raise"` to prevent implicit lazy loading in async contexts:

```python
# src/users/models.py
from typing import List, Optional
from sqlalchemy import String, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship, DeclarativeBase


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(default=True)
    full_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    
    posts: Mapped[List["Post"]] = relationship(
        back_populates="author", 
        lazy="raise",  # Prevents N+1 queries
        cascade="all, delete-orphan"
    )
```

For relationship loading: use **`selectinload`** for collections (one-to-many) and **`joinedload`** for single objects (many-to-one).

## Repository pattern with static methods

```python
# src/users/repository.py
from typing import Optional, Sequence
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from .models import User
from .schemas import UserCreate, UserUpdate


class UserRepository:
    @staticmethod
    async def get_by_id(session: AsyncSession, user_id: int) -> Optional[User]:
        result = await session.execute(select(User).where(User.id == user_id))
        return result.scalars().first()

    @staticmethod
    async def get_by_email(session: AsyncSession, email: str) -> Optional[User]:
        result = await session.execute(select(User).where(User.email == email))
        return result.scalars().first()

    @staticmethod
    async def get_with_posts(session: AsyncSession, user_id: int) -> Optional[User]:
        result = await session.execute(
            select(User)
            .where(User.id == user_id)
            .options(selectinload(User.posts))
        )
        return result.scalars().first()

    @staticmethod
    async def get_multi(
        session: AsyncSession,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> Sequence[User]:
        result = await session.execute(
            select(User).offset(skip).limit(limit)
        )
        return result.scalars().all()

    @staticmethod
    async def create(session: AsyncSession, user_in: UserCreate, hashed_password: str) -> User:
        user = User(
            email=user_in.email,
            hashed_password=hashed_password,
            full_name=user_in.full_name
        )
        session.add(user)
        await session.flush()
        await session.refresh(user)
        return user

    @staticmethod
    async def update(
        session: AsyncSession, user: User, user_in: UserUpdate
    ) -> User:
        update_data = user_in.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(user, field, value)
        await session.flush()
        await session.refresh(user)
        return user
```

## Service layer with business logic

```python
# src/users/service.py
from sqlalchemy.ext.asyncio import AsyncSession
from .repository import UserRepository
from .schemas import UserCreate, UserUpdate, UserResponse
from .exceptions import UserNotFound, EmailAlreadyExists
from src.core.security import get_password_hash


class UserService:
    @staticmethod
    async def create_user(session: AsyncSession, user_in: UserCreate) -> UserResponse:
        existing = await UserRepository.get_by_email(session, user_in.email)
        if existing:
            raise EmailAlreadyExists(user_in.email)
        
        hashed_password = get_password_hash(user_in.password)
        user = await UserRepository.create(session, user_in, hashed_password)
        await session.commit()
        return UserResponse.model_validate(user)

    @staticmethod
    async def get_user(session: AsyncSession, user_id: int) -> UserResponse:
        user = await UserRepository.get_by_id(session, user_id)
        if not user:
            raise UserNotFound(user_id)
        return UserResponse.model_validate(user)

    @staticmethod
    async def update_user(
        session: AsyncSession, user_id: int, user_in: UserUpdate
    ) -> UserResponse:
        user = await UserRepository.get_by_id(session, user_id)
        if not user:
            raise UserNotFound(user_id)
        
        updated = await UserRepository.update(session, user, user_in)
        await session.commit()
        return UserResponse.model_validate(updated)
```

## Pydantic v2 schemas with validation

```python
# src/users/schemas.py
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, EmailStr, field_validator


class UserBase(BaseModel):
    email: EmailStr
    full_name: str | None = None


class UserCreate(UserBase):
    password: str = Field(..., min_length=8)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    full_name: str | None = None
    is_active: bool | None = None


class UserResponse(UserBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    is_active: bool
    created_at: datetime
```

Key Pydantic v2 changes: `ConfigDict` replaces `class Config`, `from_attributes=True` replaces `orm_mode`, and validators use `@field_validator` with `@classmethod`.

## Dependency injection patterns

```python
# src/core/dependencies.py
from typing import Annotated
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from .database import get_db_session

# Type alias for cleaner injection
DBSession = Annotated[AsyncSession, Depends(get_db_session)]


# src/auth/dependencies.py
from typing import Annotated
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import jwt
from src.core.config import settings
from src.core.dependencies import DBSession
from src.users.repository import UserRepository
from src.users.models import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: DBSession
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except jwt.InvalidTokenError:
        raise credentials_exception
    
    user = await UserRepository.get_by_id(db, user_id)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
) -> User:
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


CurrentUser = Annotated[User, Depends(get_current_active_user)]
```

## Exception handling with global handlers

```python
# src/core/exceptions.py
class BaseAppException(Exception):
    def __init__(self, message: str, status_code: int = 500):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class ResourceNotFound(BaseAppException):
    def __init__(self, resource: str, identifier: str | int):
        super().__init__(f"{resource} {identifier} not found", status_code=404)


class ConflictError(BaseAppException):
    def __init__(self, message: str):
        super().__init__(message, status_code=409)


# src/users/exceptions.py
from src.core.exceptions import ResourceNotFound, ConflictError

class UserNotFound(ResourceNotFound):
    def __init__(self, user_id: int):
        super().__init__("User", user_id)

class EmailAlreadyExists(ConflictError):
    def __init__(self, email: str):
        super().__init__(f"Email {email} already registered")
```

```python
# src/main.py - Exception handlers
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from src.core.exceptions import BaseAppException

app = FastAPI()


@app.exception_handler(BaseAppException)
async def app_exception_handler(request: Request, exc: BaseAppException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message, "type": exc.__class__.__name__}
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"detail": "Validation Error", "errors": exc.errors()}
    )
```

## JWT authentication with PyJWT and Argon2

**PyJWT** is now the recommended library over python-jose, and **pwdlib with Argon2** is the modern choice for password hashing:

```python
# src/core/security.py
from datetime import datetime, timedelta, timezone
import jwt
from pwdlib import PasswordHash
from src.core.config import settings

password_hash = PasswordHash.recommended()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_hash.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return password_hash.hash(password)


def create_access_token(subject: int | str, expires_delta: timedelta | None = None) -> str:
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode = {"sub": str(subject), "exp": expire}
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(subject: int | str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=30)
    to_encode = {"sub": str(subject), "exp": expire, "type": "refresh"}
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
```

## SlowAPI rate limiting integration

```python
# src/core/rate_limit.py
from slowapi import Limiter
from slowapi.util import get_remote_address
from src.core.config import settings


def get_user_identifier(request) -> str:
    """Rate limit by user ID if authenticated, otherwise by IP."""
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        try:
            import jwt
            token = auth_header.split(" ")[1]
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            return f"user:{payload.get('sub')}"
        except Exception:
            pass
    return get_remote_address(request)


limiter = Limiter(
    key_func=get_user_identifier,
    storage_uri=str(settings.REDIS_URL) if settings.REDIS_URL else None,
    default_limits=["100/hour", "10/minute"],
    headers_enabled=True,
    in_memory_fallback_enabled=True,
)
```

```python
# src/auth/router.py
from fastapi import APIRouter, Request
from src.core.rate_limit import limiter

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/token")
@limiter.limit("5/minute")  # Stricter limit for auth endpoints
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    ...
```

## Thin routes calling services

```python
# src/users/router.py
from fastapi import APIRouter, status
from src.core.dependencies import DBSession
from src.auth.dependencies import CurrentUser
from .service import UserService
from .schemas import UserCreate, UserUpdate, UserResponse

router = APIRouter(prefix="/users", tags=["users"])


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(user_in: UserCreate, db: DBSession):
    return await UserService.create_user(db, user_in)


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: CurrentUser):
    return UserResponse.model_validate(current_user)


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(user_id: int, db: DBSession, current_user: CurrentUser):
    return await UserService.get_user(db, user_id)


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(user_id: int, user_in: UserUpdate, db: DBSession, current_user: CurrentUser):
    return await UserService.update_user(db, user_id, user_in)
```

## Main application assembly

```python
# src/main.py
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from src.core.config import settings
from src.core.database import sessionmanager
from src.core.rate_limit import limiter
from src.users.router import router as users_router
from src.auth.router import router as auth_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    yield
    # Shutdown
    await sessionmanager.close()


app_config = {"title": settings.APP_NAME, "version": "1.0.0"}
if settings.ENVIRONMENT == "production":
    app_config["openapi_url"] = None  # Hide docs in production

app = FastAPI(**app_config, lifespan=lifespan)

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Routers
app.include_router(auth_router, prefix="/api/v1")
app.include_router(users_router, prefix="/api/v1")


@app.get("/health")
async def health_check():
    return {"status": "healthy"}
```

## Multi-stage Dockerfile for production

```dockerfile
# Build stage
FROM python:3.12-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y gcc && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade -r requirements.txt

# Runtime stage
FROM python:3.12-slim
WORKDIR /app

RUN useradd --create-home --shell /bin/bash app && chown -R app:app /app

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --chown=app:app ./src /app/src

USER app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH="/app"

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["gunicorn", "src.main:app", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000"]
```

## Docker Compose configuration

```yaml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "8000:8000"
    env_file: .env.production
    environment:
      - DATABASE_URL=postgresql+asyncpg://user:password@db:5432/myapp
      - REDIS_URL=redis://:redis_pass@redis:6379
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy
    restart: unless-stopped
    networks:
      - backend

  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: myapp
      POSTGRES_USER: user
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U user -d myapp"]
      interval: 5s
      timeout: 5s
      retries: 5
    networks:
      - backend

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes --requirepass redis_pass
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "-a", "redis_pass", "ping"]
      interval: 5s
      timeout: 5s
      retries: 5
    networks:
      - backend

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - app
    networks:
      - backend

volumes:
  postgres_data:
  redis_data:

networks:
  backend:
```

## Nginx reverse proxy configuration

```nginx
upstream fastapi_backend {
    least_conn;
    server app:8000 max_fails=3 fail_timeout=30s;
    keepalive 32;
}

limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=auth:10m rate=1r/s;

server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header Strict-Transport-Security "max-age=63072000" always;

    client_max_body_size 10M;

    location /api/ {
        limit_req zone=api burst=20 nodelay;
        
        proxy_pass http://fastapi_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
    }

    location /api/auth/ {
        limit_req zone=auth burst=5 nodelay;
        proxy_pass http://fastapi_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /health {
        proxy_pass http://fastapi_backend;
    }
}
```

## Pytest configuration and fixtures

```python
# tests/conftest.py
import pytest
from typing import AsyncGenerator, Generator
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from src.main import app
from src.core.database import get_db_session
from src.core.security import create_access_token
from src.users.models import Base
from tests.factories.user import UserFactory

SQLALCHEMY_TEST_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_TEST_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db() -> Generator[Session, None, None]:
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    
    yield session
    
    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db: Session) -> Generator:
    def override_get_db():
        yield db

    app.dependency_overrides[get_db_session] = override_get_db
    
    with TestClient(app) as test_client:
        yield test_client
    
    app.dependency_overrides.clear()


@pytest.fixture
async def async_client(db: Session) -> AsyncGenerator[AsyncClient, None]:
    def override_get_db():
        yield db

    app.dependency_overrides[get_db_session] = override_get_db
    
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as ac:
        yield ac
    
    app.dependency_overrides.clear()


@pytest.fixture
def test_user(db: Session):
    return UserFactory()


@pytest.fixture
def authenticated_client(client, test_user):
    token = create_access_token(test_user.id)
    client.headers.update({"Authorization": f"Bearer {token}"})
    yield client
    client.headers.clear()
```

## GitHub Actions CI/CD workflow

```yaml
name: CI/CD

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  lint-and-test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_USER: test
          POSTGRES_PASSWORD: test
          POSTGRES_DB: test_db
        ports:
          - 5432:5432
        options: --health-cmd pg_isready --health-interval 10s --health-timeout 5s --health-retries 5

    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip
      
      - name: Install dependencies
        run: |
          pip install --upgrade pip
          pip install -r requirements.txt
          pip install -r requirements-dev.txt
      
      - name: Run Ruff
        run: |
          ruff check --output-format=github .
          ruff format --check .
      
      - name: Run MyPy
        run: mypy src/
      
      - name: Run tests
        env:
          DATABASE_URL: postgresql://test:test@localhost:5432/test_db
        run: pytest --cov=src --cov-report=xml
      
      - name: Upload coverage
        uses: codecov/codecov-action@v4
        with:
          files: coverage.xml

  build-and-push:
    needs: lint-and-test
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write

    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3
      
      - name: Login to GHCR
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Build and push
        uses: docker/build-push-action@v5
        with:
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.sha }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
```

## Pre-commit hooks configuration

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: check-yaml
      - id: check-toml
      - id: end-of-file-fixer
      - id: trailing-whitespace
      - id: check-merge-conflict
      - id: detect-private-key

  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.8.6
    hooks:
      - id: ruff-check
        args: [--fix, --exit-non-zero-on-fix]
      - id: ruff-format

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.13.0
    hooks:
      - id: mypy
        additional_dependencies: [pydantic>=2.0, types-python-dateutil]
        args: [--config-file=pyproject.toml]
        exclude: ^tests/

  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.22.1
    hooks:
      - id: gitleaks
```

## Structured logging with correlation IDs

```python
# src/core/logging.py
import structlog
import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

shared_processors = [
    structlog.contextvars.merge_contextvars,
    structlog.stdlib.add_log_level,
    structlog.processors.TimeStamper(fmt="iso"),
    structlog.processors.StackInfoRenderer(),
]


def configure_logging(environment: str):
    if environment == "production":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=shared_processors + [renderer],
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
        
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            correlation_id=correlation_id,
            method=request.method,
            path=request.url.path,
        )
        
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        return response
```

## Conclusion

The 2025 FastAPI ecosystem emphasizes **async-first patterns** with SQLAlchemy 2.0+'s mature async support and proper relationship loading strategies. **Ruff has consolidated** the linting ecosystem, replacing black, isort, and flake8 with a single, faster tool. **uv** offers significantly faster dependency management than pip or Poetry.

Key architectural takeaways include maintaining thin routes that delegate to services, repositories that handle only database operations without business logic, and leveraging FastAPI's dependency injection with `Annotated` types for cleaner code. For security, **PyJWT and Argon2** (via pwdlib) are the current recommended choices.

Production deployments benefit from multi-stage Docker builds with non-root users, Nginx as a reverse proxy with rate limiting at multiple layers, and structured logging with correlation IDs for distributed tracing. The testing stack centers on pytest-asyncio with `asyncio_mode="auto"` and httpx's `AsyncClient` with `ASGITransport` for async endpoint testing.
