"""
ⒸAngelaMos | 2025
env.py
"""
import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from config import settings
from core.Base import Base
from core.enums import SafeEnum
from user.User import User
from auth.RefreshToken import RefreshToken


config = context.config


def render_item(type_, obj, autogen_context):
    """
    Custom renderer for alembic autogenerate.
    Converts SafeEnum to standard sa.Enum and ensures DateTime uses timezone.
    """
    import sqlalchemy as sa

    if isinstance(obj, SafeEnum):
        enum_class = obj.enum_class
        values = [e.value for e in enum_class]
        return f"sa.Enum({', '.join(repr(v) for v in values)}, name='{obj.name}')"

    if isinstance(obj, sa.DateTime):
        return "sa.DateTime(timezone=True)"

    return False


if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_url() -> str:
    """
    Get database URL from settings
    """
    return str(settings.DATABASE_URL)


def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode
    """
    url = get_url()
    context.configure(
        url = url,
        target_metadata = target_metadata,
        literal_binds = True,
        dialect_opts = {"paramstyle": "named"},
        compare_type = True,
        compare_server_default = True,
        render_item = render_item,
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """
    Run migrations with connection
    """
    context.configure(
        connection = connection,
        target_metadata = target_metadata,
        compare_type = True,
        compare_server_default = True,
        render_item = render_item,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """
    Run migrations in async mode
    """
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = get_url()

    connectable = async_engine_from_config(
        configuration,
        prefix = "sqlalchemy.",
        poolclass = pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """
    Run migrations in 'online' mode
    """
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
