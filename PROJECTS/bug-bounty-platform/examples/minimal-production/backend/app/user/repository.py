"""
ⒸAngelaMos | 2025
repository.py
"""
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .User import User
from core.base_repository import BaseRepository


class UserRepository(BaseRepository[User]):
    """
    Repository for User model database operations
    """
    model = User

    @classmethod
    async def get_by_email(
        cls,
        session: AsyncSession,
        email: str,
    ) -> User | None:
        """
        Get user by email address
        """
        result = await session.execute(
            select(User).where(User.email == email)
        )
        return result.scalars().first()

    @classmethod
    async def get_by_id(
        cls,
        session: AsyncSession,
        id: UUID,
    ) -> User | None:
        """
        Get user by ID
        """
        return await session.get(User, id)

    @classmethod
    async def email_exists(
        cls,
        session: AsyncSession,
        email: str,
    ) -> bool:
        """
        Check if email is already registered
        """
        result = await session.execute(
            select(User.id).where(User.email == email)
        )
        return result.scalars().first() is not None

    @classmethod
    async def create_user(
        cls,
        session: AsyncSession,
        email: str,
        hashed_password: str,
    ) -> User:
        """
        Create a new user
        """
        user = User(
            email = email,
            hashed_password = hashed_password,
        )
        session.add(user)
        await session.flush()
        await session.refresh(user)
        return user

    @classmethod
    async def update_password(
        cls,
        session: AsyncSession,
        user: User,
        hashed_password: str,
    ) -> User:
        """
        Update user password
        """
        user.hashed_password = hashed_password
        await session.flush()
        await session.refresh(user)
        return user
