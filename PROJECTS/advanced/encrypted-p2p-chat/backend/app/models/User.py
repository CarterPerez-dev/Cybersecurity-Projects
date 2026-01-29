"""
ⒸAngelaMos | 2025
User model for authentication stored in PostgreSQL
"""

from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlmodel import (
    Field,
    Relationship,
)
from app.config import (
    DISPLAY_NAME_MAX_LENGTH,
    PREKEY_MAX_LENGTH,
    USERNAME_MAX_LENGTH,
)
from app.models.Base import BaseDBModel

if TYPE_CHECKING:
    from app.models.Credential import Credential


class User(BaseDBModel, table = True):
    """
    User account with WebAuthn passkey authentication
    """
    __tablename__ = "users"

    id: UUID = Field(
        default_factory = uuid4,
        primary_key = True,
        nullable = False
    )
    username: str = Field(
        unique = True,
        index = True,
        nullable = False,
        max_length = USERNAME_MAX_LENGTH
    )
    display_name: str = Field(
        nullable = False,
        max_length = DISPLAY_NAME_MAX_LENGTH
    )
    is_active: bool = Field(default = True, nullable = False)
    is_verified: bool = Field(default = False, nullable = False)

    credentials: list["Credential"] = Relationship(back_populates = "user")

    identity_key: str | None = Field(
        default = None,
        max_length = PREKEY_MAX_LENGTH
    )
    signed_prekey: str | None = Field(
        default = None,
        max_length = PREKEY_MAX_LENGTH
    )
    signed_prekey_signature: str | None = Field(
        default = None,
        max_length = PREKEY_MAX_LENGTH
    )
    one_time_prekeys: str | None = Field(default = None)

    def __repr__(self) -> str:
        """
        String representation of User
        """
        return f"<User {self.username}>"
