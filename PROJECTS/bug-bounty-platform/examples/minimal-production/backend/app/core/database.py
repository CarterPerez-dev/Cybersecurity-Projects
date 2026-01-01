"""
ⒸAngelaMos | 2025
database.py
"""

import contextlib
from collections.abc import (
    AsyncIterator,
    Iterator,
)

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.engine.url import make_url
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    AsyncConnection,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import Session, sessionmaker

from config import settings


class DatabaseSessionManager:
    """
    Manages database connections and sessions for both sync and async contexts
    """
    def __init__(self) -> None:
        self._async_engine: AsyncEngine | None = None
        self._sync_engine: Engine | None = None
        self._async_sessionmaker: async_sessionmaker[AsyncSession
                                                     ] | None = None
        self._sync_sessionmaker: sessionmaker[Session] | None = None

    def init(self, database_url: str) -> None:
        """
        Initialize database engines and session factories
        """
        base_url = make_url(database_url)

        async_url = base_url.set(drivername = "postgresql+asyncpg")
        self._async_engine = create_async_engine(
            async_url,
            pool_size = settings.DB_POOL_SIZE,
            max_overflow = settings.DB_MAX_OVERFLOW,
            pool_timeout = settings.DB_POOL_TIMEOUT,
            pool_recycle = settings.DB_POOL_RECYCLE,
            pool_pre_ping = True,
            echo = settings.DEBUG,
        )
        self._async_sessionmaker = async_sessionmaker(
            bind = self._async_engine,
            class_ = AsyncSession,
            autocommit = False,
            autoflush = False,
            expire_on_commit = False,
        )

        sync_url = base_url.set(drivername = "postgresql+psycopg2")
        self._sync_engine = create_engine(
            sync_url,
            pool_size = settings.DB_POOL_SIZE,
            max_overflow = settings.DB_MAX_OVERFLOW,
            pool_timeout = settings.DB_POOL_TIMEOUT,
            pool_recycle = settings.DB_POOL_RECYCLE,
            pool_pre_ping = True,
            echo = settings.DEBUG,
        )
        self._sync_sessionmaker = sessionmaker(
            bind = self._sync_engine,
            autocommit = False,
            autoflush = False,
            expire_on_commit = False,
        )

    async def close(self) -> None:
        """
        Dispose of all database connections
        """
        if self._async_engine:
            await self._async_engine.dispose()
            self._async_engine = None
            self._async_sessionmaker = None

        if self._sync_engine:
            self._sync_engine.dispose()
            self._sync_engine = None
            self._sync_sessionmaker = None

    @contextlib.asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """
        Async context manager for database sessions

        Handles commit on success, rollback on exception
        """
        if self._async_sessionmaker is None:
            raise RuntimeError("DatabaseSessionManager is not initialized")

        session = self._async_sessionmaker()
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

    @contextlib.asynccontextmanager
    async def connect(self) -> AsyncIterator[AsyncConnection]:
        """
        Async context manager for raw database connections
        """
        if self._async_engine is None:
            raise RuntimeError("DatabaseSessionManager is not initialized")

        async with self._async_engine.begin() as connection:
            yield connection

    @property
    def sync_engine(self) -> Engine:
        """
        Sync engine for Alembic migrations
        """
        if self._sync_engine is None:
            raise RuntimeError("DatabaseSessionManager is not initialized")
        return self._sync_engine

    @contextlib.contextmanager
    def sync_session(self) -> Iterator[Session]:
        """
        Sync context manager for migrations and CLI tools
        """
        if self._sync_sessionmaker is None:
            raise RuntimeError("DatabaseSessionManager is not initialized")

        session = self._sync_sessionmaker()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()


sessionmanager = DatabaseSessionManager()


async def get_db_session() -> AsyncIterator[AsyncSession]:
    """
    FastAPI dependency for database sessions
    """
    async with sessionmanager.session() as session:
        yield session
