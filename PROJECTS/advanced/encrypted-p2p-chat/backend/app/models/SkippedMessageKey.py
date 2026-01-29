"""
ⒸAngelaMos | 2025
Skipped message key storage for out of order Double Ratchet messages
"""

from typing import TYPE_CHECKING

from sqlmodel import Field

from app.models.Base import BaseDBModel
from app.config import RATCHET_STATE_MAX_LENGTH

if TYPE_CHECKING:
    pass


class SkippedMessageKey(BaseDBModel, table = True):
    """
    Stores message keys for out of order messages in Double Ratchet
    """
    __tablename__ = "skipped_message_keys"

    id: int = Field(default = None, primary_key = True)

    ratchet_state_id: int = Field(
        foreign_key = "ratchet_states.id",
        nullable = False,
        index = True
    )

    dh_public_key: str = Field(
        nullable = False,
        max_length = RATCHET_STATE_MAX_LENGTH,
        index = True
    )
    message_number: int = Field(nullable = False, index = True)

    message_key: str = Field(
        nullable = False,
        max_length = RATCHET_STATE_MAX_LENGTH
    )

    def __repr__(self) -> str:
        """
        String representation of SkippedMessageKey
        """
        return (
            f"<SkippedMessageKey "
            f"ratchet_id={self.ratchet_state_id} "
            f"msg_num={self.message_number}>"
        )
