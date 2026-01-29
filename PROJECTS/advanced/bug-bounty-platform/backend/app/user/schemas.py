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
    UserRole,
    FULL_NAME_MAX_LENGTH,
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
    full_name: str | None = Field(
        default = None,
        max_length = FULL_NAME_MAX_LENGTH
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


class UserUpdate(BaseSchema):
    """
    Schema for updating user profile
    """
    full_name: str | None = Field(
        default = None,
        max_length = FULL_NAME_MAX_LENGTH
    )


class UserUpdateAdmin(UserUpdate):
    """
    Schema for admin updating user
    """
    email: EmailStr | None = None
    is_active: bool | None = None
    is_verified: bool | None = None
    role: UserRole | None = None


class AdminUserCreate(BaseSchema):
    """
    Schema for admin creating a user
    """
    email: EmailStr
    password: str = Field(
        min_length = PASSWORD_MIN_LENGTH,
        max_length = PASSWORD_MAX_LENGTH
    )
    full_name: str | None = Field(
        default = None,
        max_length = FULL_NAME_MAX_LENGTH
    )
    role: UserRole = UserRole.USER
    is_active: bool = True
    is_verified: bool = False


class UserResponse(BaseResponseSchema):
    """
    Schema for user API responses
    """
    email: EmailStr
    full_name: str | None
    is_active: bool
    is_verified: bool
    role: UserRole


class UserListResponse(BaseSchema):
    """
    Schema for paginated user list
    """
    items: list[UserResponse]
    total: int
    page: int
    size: int
