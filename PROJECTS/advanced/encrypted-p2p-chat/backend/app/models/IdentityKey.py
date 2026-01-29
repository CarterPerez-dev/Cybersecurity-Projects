"""
ⒸAngelaMos | 2025
X3DH identity key model for long term user identification
"""

from typing import TYPE_CHECKING
from uuid import UUID

from sqlmodel import Field

from app.config import IDENTITY_KEY_LENGTH
from app.models.Base import BaseDBModel

if TYPE_CHECKING:
    pass


class IdentityKey(BaseDBModel, table = True):
    """
    Long term X25519 identity key for X3DH protocol
    """
    __tablename__ = "identity_keys"

    id: int = Field(default = None, primary_key = True)
    user_id: UUID = Field(
        foreign_key = "users.id",
        nullable = False,
        unique = True,
        index = True
    )

    public_key: str = Field(nullable = False, max_length = IDENTITY_KEY_LENGTH)
    private_key: str = Field(nullable = False, max_length = IDENTITY_KEY_LENGTH)

    public_key_ed25519: str = Field(
        nullable = False,
        max_length = IDENTITY_KEY_LENGTH
    )
    private_key_ed25519: str = Field(
        nullable = False,
        max_length = IDENTITY_KEY_LENGTH
    )

    def __repr__(self) -> str:
        """
        String representation of IdentityKey
        """
        return f"<IdentityKey user_id={self.user_id}>"
