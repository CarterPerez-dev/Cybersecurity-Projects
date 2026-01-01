"""
ⒸAngelaMos | 2025
User.py
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import String
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
    relationship,
)

from config import (
    EMAIL_MAX_LENGTH,
    FULL_NAME_MAX_LENGTH,
    PASSWORD_HASH_MAX_LENGTH,
    SafeEnum,
    UserRole,
)
from core.Base import (
    Base,
    TimestampMixin,
    UUIDMixin,
)

if TYPE_CHECKING:
    from auth.RefreshToken import RefreshToken


class User(Base, UUIDMixin, TimestampMixin):
    """
    User account model
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

    refresh_tokens: Mapped[list[RefreshToken]] = relationship(
        back_populates = "user",
        cascade = "all, delete-orphan",
        lazy = "raise",
    )

    def increment_token_version(self) -> None:
        """
        Invalidate all existing tokens for this user
        """
        self.token_version += 1
