"""
ⒸAngelaMos | 2025
Pydantic schemas for WebAuthn authentication
"""

from typing import Any

from pydantic import BaseModel, Field

from app.config import (
    DEVICE_NAME_MAX_LENGTH,
    DISPLAY_NAME_MAX_LENGTH,
    DISPLAY_NAME_MIN_LENGTH,
    USERNAME_MAX_LENGTH,
    USERNAME_MIN_LENGTH,
    USER_SEARCH_DEFAULT_LIMIT,
    USER_SEARCH_MAX_LIMIT,
    USER_SEARCH_MIN_LENGTH,
)


class RegistrationOptionsResponse(BaseModel):
    """
    WebAuthn registration options returned to client
    """
    options: dict[str, Any]
    challenge: bytes


class VerifiedRegistration(BaseModel):
    """
    Verified WebAuthn registration data
    """
    credential_id: bytes
    credential_public_key: bytes
    sign_count: int
    aaguid: bytes
    attestation_object: bytes
    credential_type: str
    user_verified: bool
    attestation_format: str
    credential_device_type: str
    credential_backed_up: bool
    backup_eligible: bool
    backup_state: bool


class AuthenticationOptionsResponse(BaseModel):
    """
    WebAuthn authentication options returned to client
    """
    options: dict[str, Any]
    challenge: bytes


class VerifiedAuthentication(BaseModel):
    """
    Verified WebAuthn authentication data
    """
    new_sign_count: int
    credential_id: bytes
    user_verified: bool
    backup_state: bool
    backup_eligible: bool


class RegistrationBeginRequest(BaseModel):
    """
    Request to begin passkey registration
    """
    username: str = Field(
        min_length = USERNAME_MIN_LENGTH,
        max_length = USERNAME_MAX_LENGTH,
    )
    display_name: str = Field(
        min_length = DISPLAY_NAME_MIN_LENGTH,
        max_length = DISPLAY_NAME_MAX_LENGTH,
    )


class RegistrationCompleteRequest(BaseModel):
    """
    Request to complete passkey registration
    """
    username: str = Field(min_length = USERNAME_MIN_LENGTH, max_length = USERNAME_MAX_LENGTH)
    credential: dict[str, Any]
    device_name: str | None = Field(
        default = None,
        max_length = DEVICE_NAME_MAX_LENGTH,
    )


class AuthenticationBeginRequest(BaseModel):
    """
    Request to begin passkey authentication
    """
    username: str | None = Field(
        default = None,
        min_length = USERNAME_MIN_LENGTH,
        max_length = USERNAME_MAX_LENGTH,
    )


class AuthenticationCompleteRequest(BaseModel):
    """
    Request to complete passkey authentication
    """
    credential: dict[str, Any]


class UserResponse(BaseModel):
    """
    User data response
    """
    id: str
    username: str
    display_name: str
    is_active: bool
    is_verified: bool
    created_at: str


class UserSearchRequest(BaseModel):
    """
    Request to search for users
    """
    query: str = Field(
        min_length = USER_SEARCH_MIN_LENGTH,
        max_length = USERNAME_MAX_LENGTH,
    )
    limit: int = Field(
        default = USER_SEARCH_DEFAULT_LIMIT,
        ge = 1,
        le = USER_SEARCH_MAX_LIMIT,
    )


class UserSearchResponse(BaseModel):
    """
    Response containing search results
    """
    users: list[UserResponse]
