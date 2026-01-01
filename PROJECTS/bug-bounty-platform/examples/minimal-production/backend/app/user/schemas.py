"""
ⒸAngelaMos | 2025
schemas.py
"""

from pydantic import (
    Field,
    EmailStr,
    field_validator,
)

from config import (
    PASSWORD_MAX_LENGTH,
    PASSWORD_MIN_LENGTH,
)
from core.base_schema import (
    BaseSchema,
    BaseResponseSchema,
)


class UserCreate(BaseSchema):
    """
    Schema for user registration
    """
    email: EmailStr
    password: str = Field(
        min_length = PASSWORD_MIN_LENGTH,
        max_length = PASSWORD_MAX_LENGTH
    )

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """
        Ensure password has minimum complexity
        """
        if not any(c.isupper() for c in v):
            raise ValueError(
                "Password must contain at least one uppercase letter"
            )
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class UserResponse(BaseResponseSchema):
    """
    Schema for user API responses
    """
    email: EmailStr
    is_active: bool


class PasswordChange(BaseSchema):
    """
    Schema for password change
    """
    current_password: str
    new_password: str = Field(
        min_length = PASSWORD_MIN_LENGTH,
        max_length = PASSWORD_MAX_LENGTH
    )

    @field_validator("new_password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """
        Ensure password has minimum complexity
        """
        if not any(c.isupper() for c in v):
            raise ValueError(
                "Password must contain at least one uppercase letter"
            )
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v
