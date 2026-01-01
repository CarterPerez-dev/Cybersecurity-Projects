"""
ⒸAngelaMos | 2025
schemas.py
"""

from core.base_schema import BaseSchema
from user.schemas import UserResponse


class TokenWithUserResponse(BaseSchema):
    """
    Login response with access token and user data
    """
    access_token: str
    user: UserResponse
