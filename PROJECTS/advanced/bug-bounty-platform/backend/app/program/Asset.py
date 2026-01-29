"""
ⒸAngelaMos | 2025
Asset.py
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
    relationship,
)

from config import (
    ASSET_IDENTIFIER_MAX_LENGTH,
    AssetType,
    SafeEnum,
)
from core.Base import (
    Base,
    TimestampMixin,
    UUIDMixin,
)

if TYPE_CHECKING:
    from program.Program import Program


class Asset(Base, UUIDMixin, TimestampMixin):
    """
    Target asset within a bug bounty program scope
    """
    __tablename__ = "assets"

    program_id: Mapped[UUID] = mapped_column(
        ForeignKey("programs.id",
                   ondelete = "CASCADE"),
        index = True,
    )

    asset_type: Mapped[AssetType] = mapped_column(
        SafeEnum(AssetType),
        default = AssetType.DOMAIN,
    )

    identifier: Mapped[str] = mapped_column(
        String(ASSET_IDENTIFIER_MAX_LENGTH),
    )

    in_scope: Mapped[bool] = mapped_column(default = True)

    description: Mapped[str | None] = mapped_column(
        Text,
        default = None,
    )

    program: Mapped[Program] = relationship(
        back_populates = "assets",
        lazy = "raise",
    )
