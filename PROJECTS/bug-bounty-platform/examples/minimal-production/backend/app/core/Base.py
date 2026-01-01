"""
ⒸAngelaMos | 2025
Base.py
"""

from uuid import UUID
from datetime import UTC, datetime

import uuid6
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
    DeclarativeBase,
)
from sqlalchemy import (
    DateTime,
    MetaData,
    func,
)
from sqlalchemy.ext.asyncio import AsyncAttrs


NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(AsyncAttrs, DeclarativeBase):
    """
    Base class for all SQLAlchemy models
    """
    metadata = MetaData(naming_convention = NAMING_CONVENTION)


class UUIDMixin:
    """
    Mixin for UUID v7 primary key
    """
    id: Mapped[UUID] = mapped_column(
        primary_key = True,
        default = uuid6.uuid7,
    )


class TimestampMixin:
    """
    Mixin for created_at and updated_at timestamps
    """
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone = True),
        default = lambda: datetime.now(UTC),
        server_default = func.now(),
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone = True),
        default = None,
        onupdate = lambda: datetime.now(UTC),
        server_onupdate = func.now(),
    )
