"""
©AngelaMos | 2026
env.py

Alembic migration environment with async PostgreSQL engine
support

Configures SQLModel.metadata as the target for autogenerate,
imports model registrations (ModelMetadata, ThreatEvent) to
ensure table definitions are available. run_migrations_
offline generates SQL scripts without a connection. run_
migrations_online creates an async engine with NullPool and
executes migrations via run_sync. Mode is selected based on
context.is_offline_mode()

Connects to:
  app/config              - settings.database_url
  app/models              - SQLModel table registrations
"""

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel import SQLModel

from app.config import settings
from app.models import ModelMetadata, ThreatEvent

_ = (ModelMetadata, ThreatEvent)

target_metadata = SQLModel.metadata
config = context.config
fileConfig(config.config_file_name)


def run_migrations_offline() -> None:
    """
    Run migrations in offline mode for SQL script generation.
    """
    context.configure(
        url=settings.database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection) -> None:
    """
    Execute migrations against a synchronous connection.
    """
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """
    Run migrations in online mode using an async engine.
    """
    engine = create_async_engine(
        settings.database_url,
        poolclass=pool.NullPool,
    )

    async with engine.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
