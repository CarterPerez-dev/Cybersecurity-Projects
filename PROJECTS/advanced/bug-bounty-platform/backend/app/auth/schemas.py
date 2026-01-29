"""
ⒸAngelaMos | 2025
schemas.py
"""

from pydantic import (
    Field,
    EmailStr,
)

from config import (
    PASSWORD_MAX_LENGTH,
    PASSWORD_MIN_LENGTH,
)
from core.base_schema import BaseSchema
from user.schemas import UserResponse


class LoginRequest(BaseSchema):
    """
    Schema for login request
    """
    email: EmailStr
    password: str = Field(
        min_length = PASSWORD_MIN_LENGTH,
        max_length = PASSWORD_MAX_LENGTH
    )


class TokenResponse(BaseSchema):
    """
    Schema for token response
    """
    access_token: str
    token_type: str = "bearer"


class TokenWithUserResponse(TokenResponse):
    """
    Schema for login response with user data
    """
    user: UserResponse


class RefreshTokenRequest(BaseSchema):
    """
    Schema for refresh token request via body
    """
    refresh_token: str


class PasswordResetRequest(BaseSchema):
    """
    Schema for password reset request
    """
    email: EmailStr


class PasswordResetConfirm(BaseSchema):
    """
    Schema for password reset confirmation
    """
    token: str
    new_password: str = Field(
        min_length = PASSWORD_MIN_LENGTH,
        max_length = PASSWORD_MAX_LENGTH
    )


class PasswordChange(BaseSchema):
    """
    Schema for changing password while authenticated
    """
    current_password: str
    new_password: str = Field(
        min_length = PASSWORD_MIN_LENGTH,
        max_length = PASSWORD_MAX_LENGTH
    )
