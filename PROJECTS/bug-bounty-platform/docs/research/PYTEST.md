# Pytest Production Patterns for FastAPI + Async SQLAlchemy (2025)

**The definitive testing architecture for async-first Python applications combines session-scoped database engines, transaction-based isolation via SQLAlchemy 2.0's `join_transaction_mode`, Polyfactory for type-safe data generation, and pytest-asyncio in auto mode.** This approach delivers sub-second test isolation without recreating tables, handles explicit commits in application code gracefully, and scales to parallel execution with pytest-xdist. The key insight: structure fixtures as a hierarchy where expensive resources (engines, containers) live at session scope while per-test sessions use savepoint rollbacks for isolation.

---

## Pytest 9.x arrives with native TOML and strict mode

Pytest 9.0 (November 2025) introduces significant improvements over the 8.x series. The headline feature is **native TOML configuration** via `[tool.pytest]` instead of the legacy `[tool.pytest.ini_options]` INI-compatibility mode. This enables proper TOML arrays and typed configuration:

```toml
# pyproject.toml (pytest 9.0+)
[tool.pytest]
minversion = "9.0"
testpaths = ["tests"]
addopts = ["-ra", "--strict-markers", "--import-mode=importlib"]
asyncio_mode = "auto"
asyncio_default_fixture_loop_scope = "function"
markers = [
    "slow: marks tests as slow",
    "integration: integration tests requiring database",
]
strict = true  # Enables all strictness options
```

The new **`strict = true`** option activates `strict_config`, `strict_markers`, `strict_parametrization_ids`, and `strict_xfail` simultaneously—essential for catching configuration errors in CI. Pytest 9.0 also adds **built-in subtests** (`pytest.Subtests`) for dynamic test generation when values aren't known at collection time, and **`pytest.RaisesGroup`** for testing Python 3.11+ `ExceptionGroup` exceptions.

Breaking changes to note: Python **3.9 support dropped** in 9.0 (3.8 was dropped in 8.4), and test functions returning non-None or containing `yield` now fail explicitly rather than warning. The async behavior changed in 8.4—async tests without a plugin now fail immediately instead of being silently skipped.

---

## pytest-asyncio configuration requires matching loop scopes

The pytest-asyncio ecosystem underwent a major API revision from 0.23 through 1.0 (May 2025). The critical configuration decision is **asyncio_mode**: use `"auto"` for asyncio-only projects to avoid decorating every test and fixture; use `"strict"` only when coexisting with other async frameworks like trio.

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
asyncio_default_fixture_loop_scope = "function"
asyncio_default_test_loop_scope = "function"
```

The most common pitfall involves **scope mismatches**. Session-scoped async fixtures require session-scoped event loops:

```python
# ❌ WRONG: Session fixture with function-scoped loop
@pytest_asyncio.fixture(scope="session")
async def db_engine():  # Will fail with "attached to different loop"
    pass

# ✅ CORRECT: Matching scopes
@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def db_engine():
    engine = create_async_engine(DB_URL, poolclass=NullPool)
    yield engine
    await engine.dispose()
```

Note that **pytest-asyncio 1.0 removed the `event_loop` fixture entirely**—use `loop_scope` parameters instead. For fixtures, choose between `@pytest.fixture` (works in auto mode) and `@pytest_asyncio.fixture` (required in strict mode, explicit in either). Always use `NullPool` for async engines in tests to prevent connection leakage between tests.

---

## Conftest architecture balances DRY principles with navigability

The "fat conftest" approach works well when organized thoughtfully. **Root conftest.py should contain cross-cutting fixtures** (database engine, async client, authentication tokens) while **directory-specific conftest files handle overrides and specialized fixtures**.

```
tests/
├── conftest.py              # Root: engine, base client, auth fixtures
├── fixtures/
│   ├── database.py          # Complex DB setup logic
│   └── factories.py         # Polyfactory definitions
├── unit/
│   ├── conftest.py          # Mocked DB, isolated fixtures
│   └── test_services.py
└── integration/
    ├── conftest.py          # Real DB session override
    └── test_api.py
```

Import shared fixture modules via `pytest_plugins` for explicit control:

```python
# tests/conftest.py
pytest_plugins = [
    "tests.fixtures.database",
    "tests.fixtures.factories",
]
```

**Fixture scopes should follow a clear hierarchy**: session scope for expensive resources (engines, Docker containers), function scope for test isolation. The key pattern is **session-scoped engine with function-scoped transactional sessions**:

```python
@pytest.fixture(scope="session")
async def db_engine():
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()

@pytest.fixture(scope="function")
async def db_session(db_engine):
    async with db_engine.connect() as conn:
        async with conn.begin() as trans:
            session = AsyncSession(
                bind=conn,
                expire_on_commit=False,
                join_transaction_mode="create_savepoint"  # Critical!
            )
            yield session
            await session.close()
        await trans.rollback()
```

The **`join_transaction_mode="create_savepoint"`** setting is the SQLAlchemy 2.0 solution for handling tested code that calls `session.commit()`—commits become savepoints within the outer transaction, which rolls back completely after the test.

---

## Polyfactory outperforms Factory Boy for async stacks

For FastAPI + async SQLAlchemy + Pydantic v2, **Polyfactory is the clear winner**. It provides native async support, automatic Pydantic constraint validation, and type-safe generics. Factory Boy requires third-party extensions (`async-factory-boy`) and manual workarounds for async operations.

```python
from polyfactory.factories.sqlalchemy_factory import SQLAlchemyFactory

class UserFactory(SQLAlchemyFactory[User]):
    __model__ = User
    __set_relationships__ = True
    __async_session__ = None  # Injected via fixture

# Pydantic schema factory (respects constraints automatically)
from polyfactory.factories.pydantic_factory import ModelFactory

class UserCreateFactory(ModelFactory[UserCreate]):
    __model__ = UserCreate
    __random_seed__ = 12345  # Deterministic output
```

Configure factories via a fixture to inject the async session:

```python
@pytest.fixture(autouse=True)
def configure_factories(db_session):
    UserFactory.__async_session__ = db_session
    PostFactory.__async_session__ = db_session

# Usage in tests
async def test_create_user(db_session):
    user = await UserFactory.create_async()
    assert user.id is not None
    
    # Batch creation
    users = await UserFactory.create_batch_async(10)
```

For maximum performance with large datasets, bypass ORM and use SQLAlchemy Core:

```python
from sqlalchemy import insert

async def bulk_create_users(session: AsyncSession, count: int):
    users_data = [UserFactory.build() for _ in range(count)]
    values = [{"name": u.name, "email": u.email} for u in users_data]
    await session.execute(insert(User), values)
    await session.commit()
```

**Seed Faker for reproducible tests**—non-deterministic test data causes flaky tests:

```python
@pytest.fixture(scope="session", autouse=True)
def faker_seed():
    return 12345
```

---

## Database isolation through transactions beats recreation

The production-ready pattern uses **testcontainers for ephemeral PostgreSQL** and **transaction rollback for per-test isolation**. Never use SQLite as a PostgreSQL substitute—JSONB operators, array types, and savepoint semantics differ fundamentally.

```python
from testcontainers.postgres import PostgresContainer

@pytest.fixture(scope="session")
def postgres_container():
    container = PostgresContainer("postgres:16-alpine")
    container.start()
    yield container
    container.stop()

@pytest.fixture(scope="session")
async def async_engine(postgres_container):
    url = postgres_container.get_connection_url()
    async_url = url.replace("postgresql://", "postgresql+asyncpg://")
    
    engine = create_async_engine(async_url, poolclass=NullPool)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()
```

For **Alembic migration testing**, use pytest-alembic with dedicated tests rather than running migrations for every test:

```python
# conftest.py
@pytest.fixture
def alembic_config():
    return {"script_location": "alembic"}

# Unit tests: use create_all() for speed
# Migration tests: use pytest-alembic's built-in tests
# - test_single_head_revision
# - test_upgrade (base→head)
# - test_up_down_consistency
```

---

## FastAPI testing combines async clients with dependency overrides

Use `httpx.AsyncClient` with `ASGITransport` for async endpoint testing:

```python
from httpx import ASGITransport, AsyncClient

@pytest_asyncio.fixture
async def async_client(db_session):
    def get_db_override():
        yield db_session
    
    app.dependency_overrides[get_db] = get_db_override
    
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        yield client
    
    app.dependency_overrides.clear()
```

**Authentication fixtures** should cover valid, expired, and invalid tokens:

```python
@pytest.fixture
def access_token(test_user):
    return create_access_token(user_id=test_user.id, expires_delta=timedelta(hours=1))

@pytest.fixture
def expired_token(test_user):
    return create_access_token(user_id=test_user.id, expires_delta=timedelta(seconds=-1))

@pytest.fixture
def authenticated_client(async_client, access_token):
    async_client.headers["Authorization"] = f"Bearer {access_token}"
    return async_client
```

---

## Essential plugins and parallel execution strategy

The 2025 production stack requires these versions:

```toml
[project.optional-dependencies]
test = [
    "pytest>=9.0.0",
    "pytest-asyncio>=1.0.0",
    "pytest-cov>=7.0.0",
    "pytest-xdist>=3.8.0",
    "pytest-mock>=3.12.0",
    "httpx>=0.27.0",
    "polyfactory>=2.0.0",
    "testcontainers>=4.0.0",
]
```

For **parallel execution with pytest-xdist**, use the `worksteal` scheduler for tests with varying durations:

```bash
pytest -n auto --dist=worksteal
```

When running parallel tests against databases, each worker needs isolation. With testcontainers, **create separate containers per worker**:

```python
@pytest.fixture(scope="session")
def database_url(worker_id):
    if worker_id == "master":
        return create_single_container()
    return create_container_for_worker(worker_id)
```

---

## Complete conftest.py reference implementation

```python
# tests/conftest.py
import asyncio
import pytest
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import NullPool
from httpx import ASGITransport, AsyncClient
from testcontainers.postgres import PostgresContainer

from app.main import app
from app.database import Base, get_db

pytest_plugins = ["tests.fixtures.factories"]

# Event loop (session-scoped for session fixtures)
@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

# PostgreSQL container
@pytest.fixture(scope="session")
def postgres_container():
    container = PostgresContainer("postgres:16-alpine")
    container.start()
    yield container
    container.stop()

# Async engine (session-scoped)
@pytest.fixture(scope="session")
async def async_engine(postgres_container):
    url = postgres_container.get_connection_url()
    async_url = url.replace("postgresql://", "postgresql+asyncpg://")
    async_url = async_url.replace("psycopg2", "asyncpg")
    
    engine = create_async_engine(async_url, poolclass=NullPool, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()

# Per-test session with transaction rollback
@pytest.fixture(scope="function")
async def db_session(async_engine):
    async with async_engine.connect() as conn:
        async with conn.begin() as trans:
            session = AsyncSession(
                bind=conn,
                expire_on_commit=False,
                join_transaction_mode="create_savepoint"
            )
            yield session
            await session.close()
        await trans.rollback()

# Async test client
@pytest.fixture
async def async_client(db_session):
    def get_db_override():
        yield db_session
    
    app.dependency_overrides[get_db] = get_db_override
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        yield client
    app.dependency_overrides.clear()

# Factory configuration
@pytest.fixture(autouse=True)
def configure_factories(db_session):
    from tests.fixtures.factories import UserFactory, PostFactory
    UserFactory.__async_session__ = db_session
    PostFactory.__async_session__ = db_session

# Faker seed for reproducibility
@pytest.fixture(scope="session", autouse=True)
def faker_seed():
    return 12345
```

---

## Conclusion

The modern pytest architecture for async FastAPI applications centers on **three key patterns**: transactional isolation via `join_transaction_mode="create_savepoint"`, Polyfactory for type-safe async data generation, and testcontainers for production-parity database testing. Configure pytest-asyncio in auto mode with matching loop scopes, structure fixtures hierarchically (session engine → function session), and embrace pytest 9.0's strict mode for early error detection. This architecture scales from single-threaded development to parallel CI execution while maintaining sub-second test isolation—the foundation for a productive TDD workflow with FastAPI.
