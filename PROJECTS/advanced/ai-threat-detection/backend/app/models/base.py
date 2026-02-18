"""
©AngelaMos | 2026
base.py
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, text
from sqlmodel import Field, SQLModel


class TimestampedModel(SQLModel):
    """
    Abstract base providing UUID primary key and timezone-aware created_at.
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    created_at: datetime = Field(  # type: ignore[call-overload]
        sa_type=DateTime(timezone=True),
        sa_column_kwargs={"server_default": text("CURRENT_TIMESTAMP")},
        nullable=False,
    )
