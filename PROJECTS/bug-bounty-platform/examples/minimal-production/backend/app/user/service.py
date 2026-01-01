"""
ⒸAngelaMos | 2025
service.py
"""

from uuid import UUID
from sqlalchemy.ext.asyncio import (
    AsyncSession,
)

from core.exceptions import (
    EmailAlreadyExists,
    InvalidCredentials,
    UserNotFound,
)
from core.security import (
    hash_password,
    verify_password,
)
from .schemas import (
    UserCreate,
    UserResponse,
)
from .User import User
from .repository import UserRepository


class UserService:
    """
    Business logic for user operations
    """
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create_user(
        self,
        user_data: UserCreate,
    ) -> UserResponse:
        """
        Register a new user
        """
        if await UserRepository.email_exists(self.session, user_data.email):
            raise EmailAlreadyExists(user_data.email)

        hashed = await hash_password(user_data.password)
        user = await UserRepository.create_user(
            self.session,
            email = user_data.email,
            hashed_password = hashed,
        )
        return UserResponse.model_validate(user)

    async def get_user_by_id(
        self,
        user_id: UUID,
    ) -> UserResponse:
        """
        Get user by ID
        """
        user = await UserRepository.get_by_id(self.session, user_id)
        if not user:
            raise UserNotFound(str(user_id))
        return UserResponse.model_validate(user)

    async def change_password(
        self,
        user: User,
        current_password: str,
        new_password: str,
    ) -> None:
        """
        Change user password
        """
        is_valid, _ = await verify_password(current_password, user.hashed_password)
        if not is_valid:
            raise InvalidCredentials()

        hashed = await hash_password(new_password)
        await UserRepository.update_password(self.session, user, hashed)

    async def deactivate_user(
        self,
        user: User,
    ) -> UserResponse:
        """
        Deactivate user account
        """
        updated = await UserRepository.update(
            self.session,
            user,
            is_active = False
        )
        return UserResponse.model_validate(updated)
