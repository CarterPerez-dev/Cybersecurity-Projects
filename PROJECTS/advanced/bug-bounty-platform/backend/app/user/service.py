"""
ⒸAngelaMos | 2025
service.py
"""

from uuid import UUID
from sqlalchemy.ext.asyncio import (
    AsyncSession,
)

from config import settings, UserRole
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
    AdminUserCreate,
    UserCreate,
    UserListResponse,
    UserResponse,
    UserUpdate,
    UserUpdateAdmin,
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
        if await UserRepository.email_exists(self.session,
                                             user_data.email):
            raise EmailAlreadyExists(user_data.email)

        role = UserRole.USER
        if settings.ADMIN_EMAIL and user_data.email.lower(
        ) == settings.ADMIN_EMAIL.lower():
            role = UserRole.ADMIN

        hashed = await hash_password(user_data.password)
        user = await UserRepository.create_user(
            self.session,
            email = user_data.email,
            hashed_password = hashed,
            full_name = user_data.full_name,
            role = role,
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

    async def get_user_model_by_id(
        self,
        user_id: UUID,
    ) -> User:
        """
        Get user model by ID (for internal use)
        """
        user = await UserRepository.get_by_id(self.session, user_id)
        if not user:
            raise UserNotFound(str(user_id))
        return user

    async def update_user(
        self,
        user: User,
        user_data: UserUpdate,
    ) -> UserResponse:
        """
        Update user profile
        """
        update_dict = user_data.model_dump(exclude_unset = True)
        updated_user = await UserRepository.update(
            self.session,
            user,
            **update_dict
        )
        return UserResponse.model_validate(updated_user)

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

    async def list_users(
        self,
        page: int,
        size: int,
    ) -> UserListResponse:
        """
        List users with pagination
        """
        skip = (page - 1) * size
        users = await UserRepository.get_multi(
            self.session,
            skip = skip,
            limit = size
        )
        total = await UserRepository.count(self.session)
        return UserListResponse(
            items = [UserResponse.model_validate(u) for u in users],
            total = total,
            page = page,
            size = size,
        )

    async def admin_create_user(
        self,
        user_data: AdminUserCreate,
    ) -> UserResponse:
        """
        Admin creates a new user
        """
        if await UserRepository.email_exists(self.session,
                                             user_data.email):
            raise EmailAlreadyExists(user_data.email)

        hashed = await hash_password(user_data.password)
        user = await UserRepository.create(
            self.session,
            email = user_data.email,
            hashed_password = hashed,
            full_name = user_data.full_name,
            role = user_data.role,
            is_active = user_data.is_active,
            is_verified = user_data.is_verified,
        )
        return UserResponse.model_validate(user)

    async def admin_update_user(
        self,
        user_id: UUID,
        user_data: UserUpdateAdmin,
    ) -> UserResponse:
        """
        Admin updates a user
        """
        user = await UserRepository.get_by_id(self.session, user_id)
        if not user:
            raise UserNotFound(str(user_id))

        update_dict = user_data.model_dump(exclude_unset = True)

        if "email" in update_dict:
            existing = await UserRepository.get_by_email(
                self.session,
                update_dict["email"]
            )
            if existing and existing.id != user_id:
                raise EmailAlreadyExists(update_dict["email"])

        updated_user = await UserRepository.update(
            self.session,
            user,
            **update_dict
        )
        return UserResponse.model_validate(updated_user)

    async def admin_delete_user(
        self,
        user_id: UUID,
    ) -> None:
        """
        Admin deletes a user (hard delete)
        """
        user = await UserRepository.get_by_id(self.session, user_id)
        if not user:
            raise UserNotFound(str(user_id))

        await UserRepository.delete(self.session, user)
