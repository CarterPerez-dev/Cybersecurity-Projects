"""
ⒸAngelaMos | 2025
RefreshToken.py
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

import uuid6
from sqlalchemy import (
    DateTime,
    ForeignKey,
    String,
)
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
    relationship,
)

from config import (
    DEVICE_ID_MAX_LENGTH,
    DEVICE_NAME_MAX_LENGTH,
    IP_ADDRESS_MAX_LENGTH,
    TOKEN_HASH_LENGTH,
)
from core.Base import (
    Base,
    TimestampMixin,
    UUIDMixin,
)

if TYPE_CHECKING:
    from user.User import User


class RefreshToken(Base, UUIDMixin, TimestampMixin):
    """
    Refresh token for JWT authentication

    Tokens are stored as SHA 256 hashes, never raw
    Family ID enables detection of token reuse attacks
    """
    __tablename__ = "refresh_tokens"

    token_hash: Mapped[str] = mapped_column(
        String(TOKEN_HASH_LENGTH),
        unique = True,
        index = True,
    )

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id",
                   ondelete = "CASCADE"),
        index = True,
    )

    family_id: Mapped[UUID] = mapped_column(
        default = uuid6.uuid7,
        index = True,
    )

    device_id: Mapped[str | None] = mapped_column(
        String(DEVICE_ID_MAX_LENGTH),
        default = None,
    )
    device_name: Mapped[str | None] = mapped_column(
        String(DEVICE_NAME_MAX_LENGTH),
        default = None,
    )
    ip_address: Mapped[str | None] = mapped_column(
        String(IP_ADDRESS_MAX_LENGTH),
        default = None,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone = True),
        index = True,
    )

    is_revoked: Mapped[bool] = mapped_column(default = False)
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone = True),
        default = None,
    )

    user: Mapped[User] = relationship(back_populates = "refresh_tokens")

    def revoke(self) -> None:
        """
        Revoke this token
        """
        self.is_revoked = True
        self.revoked_at = datetime.now(UTC)

    @property
    def is_expired(self) -> bool:
        """
        Check if token has expired

        Handles both timezone aware and naive datetimes for SQLite compatibility
        """
        now = datetime.now(UTC)
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo = UTC)
        return now > expires

    @property
    def is_valid(self) -> bool:
        """
        Check if token is usable
        """
        return not self.is_revoked and not self.is_expired
