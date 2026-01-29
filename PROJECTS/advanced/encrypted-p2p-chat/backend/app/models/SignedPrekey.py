"""
ⒸAngelaMos | 2025
X3DH signed prekey model for medium term key rotation
"""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import DateTime
from sqlmodel import Field

from app.config import SIGNATURE_LENGTH, SIGNED_PREKEY_LENGTH
from app.models.Base import BaseDBModel

if TYPE_CHECKING:
    pass


class SignedPrekey(BaseDBModel, table = True):
    """
    X25519 signed prekey rotated every 48 hours for X3DH protocol
    """
    __tablename__ = "signed_prekeys"

    id: int = Field(default = None, primary_key = True)
    user_id: UUID = Field(
        foreign_key = "users.id",
        nullable = False,
        index = True
    )

    key_id: int = Field(nullable = False, index = True)

    public_key: str = Field(nullable = False, max_length = SIGNED_PREKEY_LENGTH)
    private_key: str = Field(nullable = False, max_length = SIGNED_PREKEY_LENGTH)

    signature: str = Field(nullable = False, max_length = SIGNATURE_LENGTH)

    is_active: bool = Field(default = True, nullable = False)
    expires_at: datetime | None = Field(
        default = None,
        sa_type = DateTime(timezone = True),
    )

    def __repr__(self) -> str:
        """
        String representation of SignedPrekey
        """
        return f"<SignedPrekey user_id={self.user_id} key_id={self.key_id}>"
