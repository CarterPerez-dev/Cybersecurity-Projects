"""
©AngelaMos | 2025
conftest.py

Test configuration, fixtures, and factories
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "app"))

import hashlib
import secrets
from datetime import (
    UTC,
    datetime,
    timedelta,
)
from uuid import uuid4
from collections.abc import AsyncIterator

import pytest
from httpx import (
    AsyncClient,
    ASGITransport,
)
import pytest_asyncio
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from core.security import (
    hash_password,
    create_access_token,
)
from config import UserRole
from core.database import get_db_session

from core.Base import Base
from user.User import User
from auth.RefreshToken import RefreshToken


@pytest_asyncio.fixture(scope = "session", loop_scope = "session")
async def test_engine():
    """
    Session scoped async engine with in memory SQLite
    StaticPool keeps single connection so DB persists
    """
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass = StaticPool,
        connect_args = {"check_same_thread": False},
        echo = False,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def db_session(test_engine) -> AsyncIterator[AsyncSession]:
    """
    Per test session with transaction rollback for isolation
    App commits become savepoints that rollback with test
    """
    async with test_engine.connect() as conn:
        await conn.begin()

        session = AsyncSession(
            bind = conn,
            expire_on_commit = False,
            join_transaction_mode = "create_savepoint",
        )

        yield session

        await session.close()
        await conn.rollback()


@pytest.fixture
async def client(db_session: AsyncSession) -> AsyncIterator[AsyncClient]:
    """
    Async HTTP client with DB session override
    """
    from factory import create_app

    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db_session] = override_get_db

    async with AsyncClient(
            transport = ASGITransport(app = app),
            base_url = "http://test",
    ) as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest.fixture
def auth_headers(access_token: str) -> dict[str, str]:
    """
    Authorization headers for authenticated requests
    """
    return {"Authorization": f"Bearer {access_token}"}


@pytest.fixture
def admin_auth_headers(admin_access_token: str) -> dict[str, str]:
    """
    Authorization headers for admin requests
    """
    return {"Authorization": f"Bearer {admin_access_token}"}


class UserFactory:
    """
    Factory for creating test users
    """
    _counter = 0

    @classmethod
    async def create(
        cls,
        session: AsyncSession,
        *,
        email: str | None = None,
        password: str = "TestPass123",
        full_name: str | None = None,
        role: UserRole = UserRole.USER,
        is_active: bool = True,
        is_verified: bool = True,
    ) -> User:
        cls._counter += 1

        user = User(
            email = email or f"user{cls._counter}@test.com",
            hashed_password = await hash_password(password),
            full_name = full_name or f"Test User {cls._counter}",
            role = role,
            is_active = is_active,
            is_verified = is_verified,
        )
        session.add(user)
        await session.flush()
        await session.refresh(user)
        return user

    @classmethod
    def reset(cls) -> None:
        cls._counter = 0


class RefreshTokenFactory:
    """
    Factory for creating test refresh tokens
    """
    @classmethod
    async def create(
        cls,
        session: AsyncSession,
        user: User,
        *,
        is_revoked: bool = False,
        expires_delta: timedelta = timedelta(days = 7),
    ) -> tuple[RefreshToken,
               str]:
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

        token = RefreshToken(
            user_id = user.id,
            token_hash = token_hash,
            family_id = uuid4(),
            expires_at = datetime.now(UTC) + expires_delta,
            is_revoked = is_revoked,
        )
        session.add(token)
        await session.flush()
        await session.refresh(token)
        return token, raw_token


@pytest.fixture
async def test_user(db_session: AsyncSession) -> User:
    """
    Standard test user
    """
    return await UserFactory.create(db_session)


@pytest.fixture
async def admin_user(db_session: AsyncSession) -> User:
    """
    Admin test user
    """
    return await UserFactory.create(
        db_session,
        email = "admin@test.com",
        role = UserRole.ADMIN,
    )


@pytest.fixture
async def inactive_user(db_session: AsyncSession) -> User:
    """
    Inactive test user
    """
    return await UserFactory.create(
        db_session,
        email = "inactive@test.com",
        is_active = False,
    )


@pytest.fixture
def access_token(test_user: User) -> str:
    """
    Valid access token for test_user
    """
    return create_access_token(test_user.id, test_user.token_version)


@pytest.fixture
def admin_access_token(admin_user: User) -> str:
    """
    Valid access token for admin_user
    """
    return create_access_token(admin_user.id, admin_user.token_version)


@pytest.fixture
async def refresh_token_pair(
    db_session: AsyncSession,
    test_user: User,
) -> tuple[RefreshToken,
           str]:
    """
    Refresh token DB record and raw token string
    """
    return await RefreshTokenFactory.create(db_session, test_user)


@pytest.fixture
async def expired_refresh_token_pair(
    db_session: AsyncSession,
    test_user: User,
) -> tuple[RefreshToken,
           str]:
    """
    Expired refresh token for testing
    """
    return await RefreshTokenFactory.create(
        db_session,
        test_user,
        expires_delta = timedelta(days = -1),
    )


@pytest.fixture
async def revoked_refresh_token_pair(
    db_session: AsyncSession,
    test_user: User,
) -> tuple[RefreshToken,
           str]:
    """
    Revoked refresh token for testing
    """
    return await RefreshTokenFactory.create(
        db_session,
        test_user,
        is_revoked = True,
    )


@pytest.fixture(autouse = True)
def reset_factories():
    """
    Reset factory counters between tests
    """
    yield
    UserFactory.reset()
