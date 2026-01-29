"""
ⒸAngelaMos | 2025
Tests for authentication service
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.User import User
from app.services.auth_service import auth_service
from app.core.exceptions import UserExistsError


class TestAuthService:
    """
    Test authentication service basics
    """
    @pytest.mark.asyncio
    async def test_create_user(self, db_session: AsyncSession):
        """
        Test creating a new user
        """
        user = await auth_service.create_user(
            session = db_session,
            username = "newuser",
            display_name = "New User"
        )

        assert user.id is not None
        assert user.username == "newuser"
        assert user.display_name == "New User"
        assert user.is_active is True
        assert user.is_verified is False

    @pytest.mark.asyncio
    async def test_create_duplicate_user_fails(
        self,
        db_session: AsyncSession,
        test_user: User
    ):
        """
        Test cannot create user with duplicate username
        """
        with pytest.raises(UserExistsError, match = "already exists"):
            await auth_service.create_user(
                session = db_session,
                username = test_user.username,
                display_name = "Duplicate"
            )

    @pytest.mark.asyncio
    async def test_get_user_by_username(
        self,
        db_session: AsyncSession,
        test_user: User
    ):
        """
        Test retrieving user by username
        """
        user = await auth_service.get_user_by_username(
            session = db_session,
            username = test_user.username
        )

        assert user is not None
        assert user.id == test_user.id
        assert user.username == test_user.username

    @pytest.mark.asyncio
    async def test_get_nonexistent_user(self, db_session: AsyncSession):
        """
        Test getting user that doesn't exist returns None
        """
        user = await auth_service.get_user_by_username(
            session = db_session,
            username = "nonexistent"
        )

        assert user is None

    @pytest.mark.asyncio
    async def test_get_user_by_id(
        self,
        db_session: AsyncSession,
        test_user: User
    ):
        """
        Test retrieving user by ID
        """
        user = await auth_service.get_user_by_id(
            session = db_session,
            user_id = test_user.id
        )

        assert user is not None
        assert user.id == test_user.id
        assert user.username == test_user.username
