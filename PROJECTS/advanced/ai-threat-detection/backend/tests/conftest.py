"""
©AngelaMos | 2026
conftest.py

Shared pytest fixtures for in-memory SQLite database and
HTTPX async test client setup

test_settings overrides Settings for the test environment
with an in-memory SQLite URL and dummy paths. db_engine
creates a StaticPool aiosqlite engine with all tables via
SQLModel.metadata.create_all. db_session yields an
AsyncSession bound to the shared engine. db_client builds
a full HTTPX AsyncClient with ASGITransport wrapping the
FastAPI app, overriding get_session to use the in-memory
database with auto-commit

Connects to:
  app/config   - Settings override
  app/factory  - create_app for ASGI transport
  app/api/deps - get_session dependency override
"""

from collections.abc import AsyncIterator

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel

from app.api.deps import get_session
from app.config import Settings
from app.factory import create_app


@pytest.fixture
def test_settings() -> Settings:
    """
    Override settings for test environment.
    """
    return Settings(
        env="testing",
        debug=False,
        database_url="sqlite+aiosqlite://",
        redis_url="redis://localhost:6379/1",
        nginx_log_path="/tmp/test-access.log",
        geoip_db_path="/tmp/nonexistent.mmdb",
    )


@pytest.fixture
async def db_engine():
    """
    In-memory SQLite engine shared across all sessions via StaticPool.
    """
    from app.models.threat_event import ThreatEvent  # noqa: F401

    engine = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def db_session(db_engine) -> AsyncIterator[AsyncSession]:
    """
    Async session bound to the shared in-memory DB.
    """
    factory = async_sessionmaker(
        db_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    async with factory() as session:
        yield session


@pytest.fixture
async def db_client(db_engine) -> AsyncIterator[AsyncClient]:
    """
    HTTPX async client with DB dependency overridden to use in-memory SQLite.
    """
    factory = async_sessionmaker(
        db_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    test_app = create_app()

    async def override_get_session() -> AsyncIterator[AsyncSession]:
        async with factory() as session:
            yield session
            await session.commit()

    test_app.dependency_overrides[get_session] = override_get_session
    test_app.state.session_factory = factory

    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport,
                           base_url="http://test") as client:
        yield client
