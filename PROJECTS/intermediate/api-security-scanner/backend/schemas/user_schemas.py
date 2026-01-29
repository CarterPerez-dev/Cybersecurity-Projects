"""
ⒸAngelaMos | 2025
User model API validation and serialization
"""

from __future__ import annotations

import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
from config import settings


class UserCreate(BaseModel):
    """
    Schema for user registration request.
    """

    email: EmailStr
    password: str = Field(
        min_length = settings.PASSWORD_MIN_LENGTH,
        max_length = settings.PASSWORD_MAX_LENGTH,
    )

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """
        Validate password meets security requirements
        """
        if not re.search(r"[A-Z]", v):
            raise ValueError(
                "Password must contain at least one uppercase letter"
            )
        if not re.search(r"[a-z]", v):
            raise ValueError(
                "Password must contain at least one lowercase letter"
            )
        if not re.search(r"[0-9]", v):
            raise ValueError(
                "Password must contain at least one number"
            )
        return v


class UserLogin(BaseModel):
    """
    Schema for user login request.
    """

    email: EmailStr
    password: str


class UserResponse(BaseModel):
    """
    Schema for user data in API responses.
    Excludes sensitive fields like hashed_password.
    """

    model_config = ConfigDict(from_attributes = True)

    id: int
    email: str
    is_active: bool
    created_at: datetime


class TokenResponse(BaseModel):
    """
    Schema for JWT token response.
    """

    access_token: str
    token_type: str = "bearer"
