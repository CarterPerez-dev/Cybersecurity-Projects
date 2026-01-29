"""
ⒸAngelaMos | 2025
Base SQLModel class with async PostgreSQL engine setup
"""

from datetime import UTC, datetime
from collections.abc import AsyncGenerator

from sqlalchemy import DateTime
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    create_async_engine,
)
from sqlmodel import Field, SQLModel
from sqlalchemy.orm import sessionmaker

from app.config import settings


class BaseDBModel(SQLModel):
    """
    Base model with common timestamp fields
    """
    created_at: datetime = Field(
        default_factory = lambda: datetime.now(UTC),
        nullable = False,
        sa_type = DateTime(timezone = True),
    )
    updated_at: datetime = Field(
        default_factory = lambda: datetime.now(UTC),
        nullable = False,
        sa_type = DateTime(timezone = True),
        sa_column_kwargs = {"onupdate": lambda: datetime.now(UTC)},
    )


# Create async engine for PostgreSQL
engine = create_async_engine(
    str(settings.DATABASE_URL),
    echo = settings.DEBUG,
    pool_size = settings.DB_POOL_SIZE,
    max_overflow = settings.DB_MAX_OVERFLOW,
    pool_pre_ping = True,
)

# Create async session factory
async_session_maker = sessionmaker(  # type: ignore[call-overload]
    bind = engine,
    class_ = AsyncSession,
    expire_on_commit = False,
)


async def get_session() -> AsyncGenerator[AsyncSession]:
    """
    Dependency for getting database sessions
    """
    async with async_session_maker() as session:
        yield session


async def init_db() -> None:
    """
    Initialize database tables
    """
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
