"""
ⒸAngelaMos | 2025
User.py
"""

from sqlalchemy import String
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
)

from config import (
    EMAIL_MAX_LENGTH,
    PASSWORD_HASH_MAX_LENGTH,
)
from core.Base import (
    Base,
    TimestampMixin,
    UUIDMixin,
)


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
    is_active: Mapped[bool] = mapped_column(default = True)
