"""
ⒸAngelaMos | 2025
Program.py
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
    PROGRAM_NAME_MAX_LENGTH,
    PROGRAM_SLUG_MAX_LENGTH,
    ProgramStatus,
    ProgramVisibility,
    SafeEnum,
)
from core.Base import (
    Base,
    TimestampMixin,
    UUIDMixin,
)

if TYPE_CHECKING:
    from program.Asset import Asset
    from program.RewardTier import RewardTier
    from report.Report import Report
    from user.User import User


class Program(Base, UUIDMixin, TimestampMixin):
    """
    Bug bounty program hosted by a company or individual
    """
    __tablename__ = "programs"

    company_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id",
                   ondelete = "CASCADE"),
        index = True,
    )

    name: Mapped[str] = mapped_column(
        String(PROGRAM_NAME_MAX_LENGTH),
    )
    slug: Mapped[str] = mapped_column(
        String(PROGRAM_SLUG_MAX_LENGTH),
        unique = True,
        index = True,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        default = None,
    )
    rules: Mapped[str | None] = mapped_column(
        Text,
        default = None,
    )

    response_sla_hours: Mapped[int] = mapped_column(default = 72)

    status: Mapped[ProgramStatus] = mapped_column(
        SafeEnum(ProgramStatus),
        default = ProgramStatus.DRAFT,
        index = True,
    )
    visibility: Mapped[ProgramVisibility] = mapped_column(
        SafeEnum(ProgramVisibility),
        default = ProgramVisibility.PUBLIC,
    )

    company: Mapped[User] = relationship(
        back_populates = "programs",
        lazy = "raise",
    )

    assets: Mapped[list[Asset]] = relationship(
        back_populates = "program",
        cascade = "all, delete-orphan",
        lazy = "raise",
    )

    reward_tiers: Mapped[list[RewardTier]] = relationship(
        back_populates = "program",
        cascade = "all, delete-orphan",
        lazy = "raise",
    )

    reports: Mapped[list[Report]] = relationship(
        back_populates = "program",
        cascade = "all, delete-orphan",
        lazy = "raise",
    )

    @property
    def is_active(self) -> bool:
        """
        Check if program is accepting submissions
        """
        return self.status == ProgramStatus.ACTIVE

    @property
    def is_public(self) -> bool:
        """
        Check if program is publicly visible
        """
        return self.visibility == ProgramVisibility.PUBLIC
