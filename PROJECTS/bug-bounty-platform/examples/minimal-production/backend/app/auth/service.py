"""
ⒸAngelaMos | 2025
service.py
"""

from sqlalchemy.ext.asyncio import (
    AsyncSession,
)

from core.exceptions import (
    InvalidCredentials,
)
from core.security import (
    create_access_token,
    verify_password_with_timing_safety,
)
from user.User import User
from user.repository import UserRepository
from .schemas import (
    TokenWithUserResponse,
)
from user.schemas import UserResponse


class AuthService:
    """
    Business logic for authentication operations
    """
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def authenticate(
        self,
        email: str,
        password: str,
    ) -> tuple[str,
               User]:
        """
        Authenticate user and create access token
        """
        user = await UserRepository.get_by_email(self.session, email)
        hashed_password = user.hashed_password if user else None

        is_valid, new_hash = await verify_password_with_timing_safety(
            password, hashed_password
        )

        if not is_valid or user is None:
            raise InvalidCredentials()

        if not user.is_active:
            raise InvalidCredentials()

        if new_hash:
            await UserRepository.update_password(self.session, user, new_hash)

        access_token = create_access_token(user.id)

        return access_token, user

    async def login(
        self,
        email: str,
        password: str,
    ) -> TokenWithUserResponse:
        """
        Login and return token with user data
        """
        access_token, user = await self.authenticate(
            email,
            password,
        )

        response = TokenWithUserResponse(
            access_token = access_token,
            user = UserResponse.model_validate(user),
        )
        return response
