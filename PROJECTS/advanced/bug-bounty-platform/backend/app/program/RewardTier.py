"""
ⒸAngelaMos | 2025
RewardTier.py
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
    relationship,
)

from config import (
    CURRENCY_MAX_LENGTH,
    SafeEnum,
    Severity,
)
from core.Base import (
    Base,
    TimestampMixin,
    UUIDMixin,
)

if TYPE_CHECKING:
    from program.Program import Program


class RewardTier(Base, UUIDMixin, TimestampMixin):
    """
    Bounty reward tier by severity for a program
    """
    __tablename__ = "reward_tiers"

    program_id: Mapped[UUID] = mapped_column(
        ForeignKey("programs.id",
                   ondelete = "CASCADE"),
        index = True,
    )

    severity: Mapped[Severity] = mapped_column(
        SafeEnum(Severity),
    )

    min_bounty: Mapped[int] = mapped_column(default = 0)
    max_bounty: Mapped[int] = mapped_column(default = 0)

    currency: Mapped[str] = mapped_column(
        String(CURRENCY_MAX_LENGTH),
        default = "USD",
    )

    program: Mapped[Program] = relationship(
        back_populates = "reward_tiers",
        lazy = "raise",
    )
