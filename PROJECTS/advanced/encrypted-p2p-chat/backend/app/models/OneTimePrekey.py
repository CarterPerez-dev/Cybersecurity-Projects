"""
ⒸAngelaMos | 2025
X3DH one time prekey model for single use key exchange
"""

from typing import TYPE_CHECKING
from uuid import UUID

from sqlmodel import Field

from app.config import ONE_TIME_PREKEY_LENGTH
from app.models.Base import BaseDBModel

if TYPE_CHECKING:
    pass


class OneTimePrekey(BaseDBModel, table = True):
    """
    X25519 one time prekey consumed after single use for X3DH protocol
    """
    __tablename__ = "one_time_prekeys"

    id: int = Field(default = None, primary_key = True)
    user_id: UUID = Field(
        foreign_key = "users.id",
        nullable = False,
        index = True
    )

    key_id: int = Field(nullable = False, index = True)

    public_key: str = Field(nullable = False, max_length = ONE_TIME_PREKEY_LENGTH)
    private_key: str = Field(
        nullable = False,
        max_length = ONE_TIME_PREKEY_LENGTH
    )

    is_used: bool = Field(default = False, nullable = False, index = True)

    def __repr__(self) -> str:
        """
        String representation of OneTimePrekey
        """
        return f"<OneTimePrekey user_id={self.user_id} key_id={self.key_id}>"
