"""
ⒸAngelaMos | 2025
User.py
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import String, Text
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
    relationship,
)

from config import (
    COMPANY_NAME_MAX_LENGTH,
    EMAIL_MAX_LENGTH,
    FULL_NAME_MAX_LENGTH,
    PASSWORD_HASH_MAX_LENGTH,
    SafeEnum,
    UserRole,
    WEBSITE_MAX_LENGTH,
)
from core.Base import (
    Base,
    TimestampMixin,
    UUIDMixin,
)

if TYPE_CHECKING:
    from auth.RefreshToken import RefreshToken
    from program.Program import Program
    from report.Report import Report


class User(Base, UUIDMixin, TimestampMixin):
    """
    User account model supporting both researchers and companies
    """
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(
        String(EMAIL_MAX_LENGTH),
        unique = True,
        index = True,
    )
    hashed_password: Mapped[str] = mapped_column(
        String(PASSWORD_HASH_MAX_LENGTH)
    )

    full_name: Mapped[str | None] = mapped_column(
        String(FULL_NAME_MAX_LENGTH),
        default = None,
    )

    is_active: Mapped[bool] = mapped_column(default = True)
    is_verified: Mapped[bool] = mapped_column(default = False)

    role: Mapped[UserRole] = mapped_column(
        SafeEnum(UserRole,
                 unknown_value = UserRole.UNKNOWN),
        default = UserRole.USER,
    )

    token_version: Mapped[int] = mapped_column(default = 0)

    company_name: Mapped[str | None] = mapped_column(
        String(COMPANY_NAME_MAX_LENGTH),
        default = None,
    )
    bio: Mapped[str | None] = mapped_column(
        Text,
        default = None,
    )
    website: Mapped[str | None] = mapped_column(
        String(WEBSITE_MAX_LENGTH),
        default = None,
    )
    reputation_score: Mapped[int] = mapped_column(default = 0)

    refresh_tokens: Mapped[list[RefreshToken]] = relationship(
        back_populates = "user",
        cascade = "all, delete-orphan",
        lazy = "raise",
    )

    programs: Mapped[list[Program]] = relationship(
        back_populates = "company",
        cascade = "all, delete-orphan",
        lazy = "raise",
    )

    reports: Mapped[list[Report]] = relationship(
        back_populates = "researcher",
        cascade = "all, delete-orphan",
        lazy = "raise",
    )

    def increment_token_version(self) -> None:
        """
        Invalidate all existing tokens for this user
        """
        self.token_version += 1

    @property
    def is_verified_company(self) -> bool:
        """
        Check if user is a verified organization (optional upgrade)
        """
        return self.role == UserRole.COMPANY

    @property
    def can_submit_reports(self) -> bool:
        """
        Any authenticated user can submit reports
        """
        return self.role != UserRole.UNKNOWN

    @property
    def can_create_program(self) -> bool:
        """
        Any authenticated user can create a program
        """
        return self.role != UserRole.UNKNOWN
