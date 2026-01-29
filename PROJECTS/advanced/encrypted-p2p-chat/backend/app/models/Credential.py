"""
ⒸAngelaMos | 2025
WebAuthn credential model for passkey storage
"""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import DateTime
from sqlmodel import Field, Relationship

from app.config import (
    AAGUID_MAX_LENGTH,
    ATTESTATION_TYPE_MAX_LENGTH,
    CREDENTIAL_ID_MAX_LENGTH,
    DISPLAY_NAME_MAX_LENGTH,
    PUBLIC_KEY_MAX_LENGTH,
    TRANSPORT_MAX_LENGTH,
)
from app.models.Base import BaseDBModel

if TYPE_CHECKING:
    from app.models.User import User


class Credential(BaseDBModel, table = True):
    """
    WebAuthn/FIDO2 passkey credential
    """
    __tablename__ = "credentials"

    id: int = Field(default = None, primary_key = True)
    credential_id: str = Field(
        unique = True,
        index = True,
        nullable = False,
        max_length = CREDENTIAL_ID_MAX_LENGTH
    )
    public_key: str = Field(nullable = False, max_length = PUBLIC_KEY_MAX_LENGTH)
    sign_count: int = Field(default = 0, nullable = False)
    aaguid: str | None = Field(default = None, max_length = AAGUID_MAX_LENGTH)

    # WebAuthn Level 3 fields
    backup_eligible: bool = Field(default = False, nullable = False)
    backup_state: bool = Field(default = False, nullable = False)
    attestation_type: str | None = Field(
        default = None,
        max_length = ATTESTATION_TYPE_MAX_LENGTH
    )
    transports: str | None = Field(
        default = None,
        max_length = TRANSPORT_MAX_LENGTH
    )

    # User relationship
    user_id: UUID = Field(
        foreign_key = "users.id",
        nullable = False,
        index = True
    )
    user: "User" = Relationship(back_populates = "credentials")

    # Device metadata
    device_name: str | None = Field(
        default = None,
        max_length = DISPLAY_NAME_MAX_LENGTH
    )
    last_used_at: datetime | None = Field(
        default = None,
        sa_type = DateTime(timezone = True),
    )

    def __repr__(self) -> str:
        """
        String representation of Credential
        """
        return f"<Credential {self.credential_id[:16]}...>"
