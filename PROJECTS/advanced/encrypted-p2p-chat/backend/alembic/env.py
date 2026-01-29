"""
ⒸAngelaMos | 2025
Alembic environment configuration for SQLModel migrations
"""

from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from sqlmodel import SQLModel

from alembic import context
from app.config import settings

# Import all models so they're registered with SQLModel metadata
from app.models.User import User  # noqa: F401
from app.models.Credential import Credential  # noqa: F401
from app.models.IdentityKey import IdentityKey  # noqa: F401
from app.models.SignedPrekey import SignedPrekey  # noqa: F401
from app.models.OneTimePrekey import OneTimePrekey  # noqa: F401
from app.models.RatchetState import RatchetState  # noqa: F401
from app.models.SkippedMessageKey import SkippedMessageKey  # noqa: F401


config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = SQLModel.metadata

config.set_main_option("sqlalchemy.url", str(settings.DATABASE_URL))


def run_migrations_offline() -> None:
    """
    Run migrations in offline mode
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url = url,
        target_metadata = target_metadata,
        literal_binds = True,
        dialect_opts = {"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """
    Run migrations in online mode
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix = "sqlalchemy.",
        poolclass = pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection = connection,
            target_metadata = target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
