"""
ⒸAngelaMos | 2025
Double Ratchet state model for per conversation encryption state
"""

from typing import TYPE_CHECKING
from uuid import UUID

from sqlmodel import Field

from app.config import RATCHET_STATE_MAX_LENGTH
from app.models.Base import BaseDBModel

if TYPE_CHECKING:
    pass


class RatchetState(BaseDBModel, table = True):
    """
    Double Ratchet algorithm state for a conversation between two users
    """
    __tablename__ = "ratchet_states"

    id: int = Field(default = None, primary_key = True)

    user_id: UUID = Field(
        foreign_key = "users.id",
        nullable = False,
        index = True
    )
    peer_user_id: UUID = Field(
        foreign_key = "users.id",
        nullable = False,
        index = True
    )

    dh_private_key: str | None = Field(
        default = None,
        max_length = RATCHET_STATE_MAX_LENGTH
    )
    dh_public_key: str | None = Field(
        default = None,
        max_length = RATCHET_STATE_MAX_LENGTH
    )
    dh_peer_public_key: str | None = Field(
        default = None,
        max_length = RATCHET_STATE_MAX_LENGTH
    )

    root_key: str = Field(nullable = False, max_length = RATCHET_STATE_MAX_LENGTH)
    sending_chain_key: str = Field(
        nullable = False,
        max_length = RATCHET_STATE_MAX_LENGTH
    )
    receiving_chain_key: str = Field(
        nullable = False,
        max_length = RATCHET_STATE_MAX_LENGTH
    )

    sending_message_number: int = Field(default = 0, nullable = False)
    receiving_message_number: int = Field(default = 0, nullable = False)
    previous_sending_chain_length: int = Field(default = 0, nullable = False)

    def __repr__(self) -> str:
        """
        String representation of RatchetState
        """
        return f"<RatchetState user_id={self.user_id} peer={self.peer_user_id}>"
