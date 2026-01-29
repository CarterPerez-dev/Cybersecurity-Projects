# Getting Started: Build Your Own Bug Bounty Platform

This guide walks you through building a similar platform from scratch, explaining each step and the reasoning behind design decisions.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Project Setup](#project-setup)
3. [Backend Development](#backend-development)
4. [Frontend Development](#frontend-development)
5. [Database Design](#database-design)
6. [Authentication](#authentication)
7. [API Development](#api-development)
8. [Testing](#testing)
9. [Deployment](#deployment)

---

## Prerequisites

Before starting, you should understand:

**Python:**
- Async/await (`async def`, `await`)
- Type hints (`def func(x: int) -> str`)
- Context managers (`async with`)
- Decorators (`@router.get()`)

**TypeScript/JavaScript:**
- Promises and async/await
- React hooks (`useState`, `useEffect`)
- TypeScript types and interfaces
- ES6+ syntax (arrow functions, destructuring)

**Database:**
- SQL basics (SELECT, INSERT, UPDATE, DELETE)
- Relationships (one-to-many, many-to-many)
- Indexes and foreign keys

**Tools:**
- Git (version control)
- Docker (containerization)
- Command line basics

---

## Project Setup

### Step 1: Create Project Structure

```bash
mkdir bug-bounty-platform
cd bug-bounty-platform

mkdir -p backend/src/app
mkdir -p frontend/src
mkdir -p infra/nginx
mkdir -p infra/docker
```

### Step 2: Initialize Backend (Python)

```bash
cd backend

touch pyproject.toml
```

**pyproject.toml:**

```toml
[project]
name = "bug-bounty-backend"
version = "1.0.0"
requires-python = ">=3.12"

dependencies = [
    "fastapi>=0.123.0",
    "uvicorn[standard]>=0.40.0",
    "sqlalchemy>=2.0.0",
    "asyncpg>=0.30.0",
    "alembic>=1.15.0",
    "pydantic>=2.0.0",
    "pydantic-settings>=2.7.0",
    "pyjwt>=2.10.0",
    "pwdlib[argon2]>=0.2.0",
    "uuid-utils>=0.10.0",
    "python-multipart>=0.0.20",
]

[project.optional-dependencies]
dev = [
    "ruff>=0.9.0",
    "mypy>=1.15.0",
    "pytest>=8.0.0",
    "pytest-asyncio>=0.25.0",
]

[build-system]
requires = ["setuptools>=75.0.0"]
build-backend = "setuptools.build_meta"
```

**Why these dependencies?**
- `fastapi` - Modern async web framework
- `sqlalchemy` - ORM for database operations
- `asyncpg` - Fast async PostgreSQL driver
- `alembic` - Database migrations
- `pydantic` - Data validation
- `pyjwt` - JWT token handling
- `pwdlib[argon2]` - Secure password hashing
- `uuid-utils` - UUID v7 support

### Step 3: Initialize Frontend (React + TypeScript)

```bash
cd ../frontend

pnpm create vite@latest . --template react-ts
pnpm install
```

**Install additional dependencies:**

```bash
pnpm add react-router-dom @tanstack/react-query zustand axios zod
pnpm add -D sass stylelint @biomejs/biome
```

**Why these dependencies?**
- `react-router-dom` - File-based routing
- `@tanstack/react-query` - Server state management
- `zustand` - Client state management
- `axios` - HTTP client
- `zod` - Runtime validation
- `sass` - CSS preprocessing
- `biome` - Linting and formatting

---

## Backend Development

### Step 1: Create Base Configuration

**backend/src/config.py:**

```python
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )

    APP_NAME: str = "Bug Bounty Platform"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    DATABASE_URL: str
    SECRET_KEY: str

    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    CORS_ORIGINS: list[str] = ["http://localhost:3000"]

settings = Settings()
```

**Why Pydantic Settings?**
- Type validation (DATABASE_URL must be a string)
- Environment variable loading (reads from .env)
- Default values
- IDE autocomplete

### Step 2: Set Up Database

**backend/src/app/core/database.py:**

```python
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncSession,
    async_sessionmaker,
)
from typing import AsyncGenerator

class DatabaseSessionManager:
    def __init__(self):
        self._engine = None
        self._sessionmaker = None

    def init(self, database_url: str):
        self._engine = create_async_engine(
            database_url,
            echo=True,  # Log SQL queries (disable in production)
            pool_size=20,
            max_overflow=10,
        )
        self._sessionmaker = async_sessionmaker(
            self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        if self._sessionmaker is None:
            raise RuntimeError("Database not initialized")

        async with self._sessionmaker() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

db_manager = DatabaseSessionManager()
```

**Key concepts:**
- `AsyncSession` - Async database session
- `async_sessionmaker` - Factory for creating sessions
- Context manager (`async with`) - Automatically commits/rolls back
- Connection pooling - Reuse connections

### Step 3: Create Base Models

**backend/src/app/core/Base.py:**

```python
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import DateTime, func
from uuid import UUID
from datetime import datetime
import uuid_utils as uuid

class Base(DeclarativeBase):
    pass

class UUIDMixin:
    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid7,
    )

class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )
```

**Why mixins?**
- DRY (Don't Repeat Yourself)
- Every model gets `id`, `created_at`, `updated_at` automatically
- Can add more mixins (SoftDeleteMixin, etc.)

### Step 4: Create User Model

**backend/src/app/user/models.py:**

```python
from sqlalchemy import String, Enum
from sqlalchemy.orm import Mapped, mapped_column
from app.core.Base import Base, UUIDMixin, TimestampMixin
from enum import StrEnum

class UserRole(StrEnum):
    USER = "user"
    COMPANY = "company"
    ADMIN = "admin"

class User(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
    )
    password_hash: Mapped[str] = mapped_column(String(255))
    full_name: Mapped[str] = mapped_column(String(255))
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, values_callable=lambda obj: [e.value for e in obj]),
        default=UserRole.USER,
    )
```

**Key points:**
- `Mapped[str]` - Type hint for SQLAlchemy
- `unique=True, index=True` - Fast lookups, prevent duplicates
- `Enum` with values_callable - Store enum value, not name (SafeEnum pattern)

### Step 5: Create User Repository

**backend/src/app/user/repository.py:**

```python
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.user.models import User
from uuid import UUID

class UserRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_by_id(self, user_id: UUID) -> User | None:
        stmt = select(User).where(User.id == user_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> User | None:
        stmt = select(User).where(User.email == email)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def create(
        self,
        email: str,
        password_hash: str,
        full_name: str,
        role: str = "user",
    ) -> User:
        user = User(
            email=email,
            password_hash=password_hash,
            full_name=full_name,
            role=role,
        )
        self.session.add(user)
        await self.session.flush()
        await self.session.refresh(user)
        return user
```

**Why repositories?**
- Separate data access from business logic
- Reusable queries
- Easy to test (mock repository)

### Step 6: Create User Schemas

**backend/src/app/user/schemas.py:**

```python
from pydantic import BaseModel, EmailStr, Field
from uuid import UUID
from datetime import datetime

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: str = Field(..., min_length=1, max_length=255)

class UserResponse(BaseModel):
    id: UUID
    email: str
    full_name: str
    role: str
    created_at: datetime

    model_config = {"from_attributes": True}
```

**Why Pydantic schemas?**
- Input validation (email format, password length)
- Automatic OpenAPI docs
- Type safety
- Serialization (ORM model → JSON)

### Step 7: Create User Routes

**backend/src/app/user/routes.py:**

```python
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import db_manager
from app.user.schemas import UserResponse
from app.user.repository import UserRepository
from app.core.dependencies import get_current_user
from typing import Annotated

router = APIRouter()

DatabaseSession = Annotated[
    AsyncSession,
    Depends(db_manager.session)
]
CurrentUser = Annotated[User, Depends(get_current_user)]

@router.get("/me", response_model=UserResponse)
async def get_me(user: CurrentUser) -> UserResponse:
    return UserResponse.from_orm(user)
```

**Key concepts:**
- `Annotated` - Type alias with dependency
- `Depends()` - Dependency injection
- `response_model` - Automatic serialization
- Route handler returns Python object, FastAPI converts to JSON

---

## Authentication

### Step 1: Password Hashing

**backend/src/app/core/security.py:**

```python
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher

password_hash = PasswordHash((Argon2Hasher(),))

def hash_password(password: str) -> str:
    return password_hash.hash(password)

def verify_password(password: str, hash: str) -> bool:
    try:
        return password_hash.verify(password, hash)
    except Exception:
        return False
```

**Why Argon2?**
- Winner of Password Hashing Competition (2015)
- Resistant to GPU cracking
- Memory-hard (expensive to parallelize)

### Step 2: JWT Token Creation

**backend/src/app/core/security.py (continued):**

```python
import jwt
from datetime import datetime, timedelta
from uuid import UUID
from config import settings

def create_access_token(user: User) -> str:
    payload = {
        "sub": str(user.id),
        "role": user.role,
        "token_version": user.token_version,
        "exp": datetime.utcnow() + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        ),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )

def decode_access_token(token: str) -> dict:
    try:
        return jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
    except jwt.ExpiredSignatureError:
        raise UnauthorizedError("Token expired")
    except jwt.InvalidTokenError:
        raise UnauthorizedError("Invalid token")
```

**JWT payload:**
- `sub` (subject) - User ID
- `role` - User role (for authorization)
- `token_version` - For instant invalidation
- `exp` (expiration) - Token expires in 15 minutes
- `iat` (issued at) - Timestamp of creation

### Step 3: Authentication Dependency

**backend/src/app/core/dependencies.py:**

```python
from fastapi import Header, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.security import decode_access_token
from app.user.repository import UserRepository
from app.user.models import User
from uuid import UUID

async def get_current_user(
    authorization: str = Header(...),
    session: AsyncSession = Depends(db_manager.session),
) -> User:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid token")

    token = authorization.replace("Bearer ", "")

    try:
        payload = decode_access_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = UUID(payload["sub"])
    repo = UserRepository(session)
    user = await repo.get_by_id(user_id)

    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    if user.token_version != payload["token_version"]:
        raise HTTPException(status_code=401, detail="Token invalidated")

    return user
```

**How it works:**
1. Extract `Authorization: Bearer <token>` header
2. Decode JWT token
3. Get user ID from token payload
4. Query database for user
5. Verify token version matches (for instant invalidation)
6. Return authenticated user

---

## Frontend Development

### Step 1: Create API Client

**frontend/src/api/index.ts:**

```typescript
import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      const refreshToken = localStorage.getItem('refresh_token');
      if (refreshToken) {
        try {
          const { data } = await axios.post('/api/auth/refresh', {
            refresh_token: refreshToken,
          });
          localStorage.setItem('access_token', data.access_token);
          localStorage.setItem('refresh_token', data.refresh_token);

          error.config.headers.Authorization = `Bearer ${data.access_token}`;
          return axios(error.config);
        } catch {
          localStorage.removeItem('access_token');
          localStorage.removeItem('refresh_token');
          window.location.href = '/login';
        }
      }
    }
    return Promise.reject(error);
  }
);

export default api;
```

**What this does:**
- Automatically adds `Authorization` header to all requests
- Automatically refreshes expired access tokens
- Redirects to login if refresh fails

### Step 2: Create Auth Store (Zustand)

**frontend/src/stores/auth.store.ts:**

```typescript
import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface AuthStore {
  accessToken: string | null;
  refreshToken: string | null;
  user: User | null;

  setTokens: (access: string, refresh: string) => void;
  setUser: (user: User) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthStore>()(
  persist(
    (set) => ({
      accessToken: null,
      refreshToken: null,
      user: null,

      setTokens: (access, refresh) => set({
        accessToken: access,
        refreshToken: refresh,
      }),

      setUser: (user) => set({ user }),

      logout: () => set({
        accessToken: null,
        refreshToken: null,
        user: null,
      }),
    }),
    {
      name: 'auth-storage',
    }
  )
);
```

**Why Zustand?**
- Simple API (no boilerplate)
- Built-in persistence (saves to localStorage)
- TypeScript support
- No provider wrapper needed

### Step 3: Create React Query Hook

**frontend/src/api/hooks/useAuth.ts:**

```typescript
import { useMutation } from '@tanstack/react-query';
import api from '../index';
import { useAuthStore } from '../../stores/auth.store';

interface LoginRequest {
  email: string;
  password: string;
}

interface LoginResponse {
  access_token: string;
  refresh_token: string;
}

export const useLogin = () => {
  const setTokens = useAuthStore((state) => state.setTokens);

  return useMutation({
    mutationFn: async (data: LoginRequest) => {
      const response = await api.post<LoginResponse>('/auth/login', data);
      return response.data;
    },
    onSuccess: (data) => {
      setTokens(data.access_token, data.refresh_token);
      localStorage.setItem('access_token', data.access_token);
      localStorage.setItem('refresh_token', data.refresh_token);
    },
  });
};
```

**Usage in component:**

```typescript
function LoginForm() {
  const login = useLogin();

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    login.mutate({
      email: 'user@example.com',
      password: 'password123',
    });
  };

  return (
    <form onSubmit={handleSubmit}>
      {/* ... */}
      <button disabled={login.isPending}>
        {login.isPending ? 'Logging in...' : 'Login'}
      </button>
      {login.isError && <p>Login failed</p>}
    </form>
  );
}
```

**Why TanStack Query?**
- Automatic loading/error states (`isPending`, `isError`)
- Optimistic updates
- Retry logic
- Cache management

---

## Testing

### Backend Testing

**backend/tests/test_user.py:**

```python
import pytest
from httpx import AsyncClient
from app.factory import create_app

@pytest.fixture
async def client():
    app = create_app()
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client

@pytest.mark.asyncio
async def test_register_user(client: AsyncClient):
    response = await client.post("/api/auth/register", json={
        "email": "test@example.com",
        "password": "password123",
        "full_name": "Test User",
    })

    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "test@example.com"
    assert "id" in data
```

**Run tests:**

```bash
pytest backend/tests/
```

### Frontend Testing

**frontend/src/components/LoginForm.test.tsx:**

```typescript
import { render, screen, fireEvent } from '@testing-library/react';
import { LoginForm } from './LoginForm';

test('renders login form', () => {
  render(<LoginForm />);

  expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
  expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /login/i })).toBeInTheDocument();
});

test('submits form with credentials', () => {
  const onSubmit = jest.fn();
  render(<LoginForm onSubmit={onSubmit} />);

  fireEvent.change(screen.getByLabelText(/email/i), {
    target: { value: 'test@example.com' },
  });
  fireEvent.change(screen.getByLabelText(/password/i), {
    target: { value: 'password123' },
  });
  fireEvent.click(screen.getByRole('button', { name: /login/i }));

  expect(onSubmit).toHaveBeenCalledWith({
    email: 'test@example.com',
    password: 'password123',
  });
});
```

---

## Deployment

### Step 1: Create Docker Compose

**compose.yml:**

```yaml
version: '3.8'

services:
  nginx:
    build: ./infra/nginx
    ports:
      - "8420:80"
    depends_on:
      - backend

  backend:
    build: ./backend
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - SECRET_KEY=${SECRET_KEY}
    depends_on:
      - db

  db:
    image: postgres:18-alpine
    environment:
      - POSTGRES_USER=${POSTGRES_USER}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
      - POSTGRES_DB=${POSTGRES_DB}
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

### Step 2: Deploy

```bash
cp .env.example .env
just up
```

---

## Next Steps

Now that you understand the basics:

1. **Read the architecture docs:** [ARCHITECTURE.md](./ARCHITECTURE.md)
2. **Learn design patterns:** [PATTERNS.md](./PATTERNS.md)
3. **Understand the database:** [DATABASE.md](./DATABASE.md)
4. **Study security features:** [SECURITY.md](./SECURITY.md)

---

## Common Pitfalls

**1. Not using async/await properly:**

```python
async def bad():
    user_repo.get_by_id(user_id)  # Missing await!

async def good():
    user = await user_repo.get_by_id(user_id)
```

**2. Mixing sync and async code:**

```python
async def bad():
    users = session.query(User).all()  # Sync query in async function

async def good():
    stmt = select(User)
    result = await session.execute(stmt)
    users = result.scalars().all()
```

**3. Not handling errors:**

```python
def bad():
    user = await repo.get_by_id(user_id)
    return user.email  # What if user is None?

def good():
    user = await repo.get_by_id(user_id)
    if not user:
        raise UserNotFoundError()
    return user.email
```

**4. Storing passwords in plaintext:**

```python
def bad():
    user = User(email=email, password=password)  # Plaintext password!

def good():
    user = User(email=email, password_hash=hash_password(password))
```

---

## Resources

**Official Documentation:**
- [FastAPI](https://fastapi.tiangolo.com/)
- [SQLAlchemy](https://docs.sqlalchemy.org/)
- [React](https://react.dev/)
- [TanStack Query](https://tanstack.com/query/latest)

**Books:**
- "Clean Architecture" by Robert C. Martin
- "Domain-Driven Design" by Eric Evans
- "Designing Data-Intensive Applications" by Martin Kleppmann

**This Codebase:**
- Explore the code in `/backend/src/app/`
- Read the other learning docs in `/learn/`
- Experiment by modifying the code

---

Good luck building your own platform!
