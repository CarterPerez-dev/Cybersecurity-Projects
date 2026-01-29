"""
ⒸAngelaMos | 2025
Pytest configuration and fixtures for all tests
"""

import asyncio
from uuid import uuid4
from typing import Any
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from sqlmodel import SQLModel
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    create_async_engine,
)
from sqlalchemy.orm import sessionmaker
from webauthn.helpers import bytes_to_base64url

from app.models.User import User
from app.models.IdentityKey import IdentityKey
from app.models.SignedPrekey import SignedPrekey
from app.models.OneTimePrekey import OneTimePrekey
from app.core.encryption.x3dh_manager import x3dh_manager


@pytest.fixture(scope = "session")
def event_loop():
    """
    Create event loop for async tests
    """
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope = "function")
async def db_session() -> AsyncGenerator[AsyncSession]:
    """
    Create in-memory SQLite database for testing
    """
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo = False,
        future = True,
    )

    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    async_session = sessionmaker(
        bind = engine,
        class_ = AsyncSession,
        expire_on_commit = False,
    )

    async with async_session() as session:
        yield session
        await session.rollback()

    await engine.dispose()


@pytest_asyncio.fixture
async def test_user(db_session: AsyncSession) -> User:
    """
    Create test user
    """
    user = User(
        username = "testuser",
        display_name = "Test User",
        is_active = True,
        is_verified = True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def test_user_2(db_session: AsyncSession) -> User:
    """
    Create second test user for conversations
    """
    user = User(
        username = "testuser2",
        display_name = "Test User 2",
        is_active = True,
        is_verified = True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def test_identity_key(
    db_session: AsyncSession,
    test_user: User
) -> IdentityKey:
    """
    Create identity key for test user
    """
    ik_private_x25519, ik_public_x25519 = (
        x3dh_manager.generate_identity_keypair_x25519()
    )
    ik_private_ed25519, ik_public_ed25519 = (
        x3dh_manager.generate_identity_keypair_ed25519()
    )

    identity_key = IdentityKey(
        user_id = test_user.id,
        public_key = ik_public_x25519,
        private_key = ik_private_x25519,
        public_key_ed25519 = ik_public_ed25519,
        private_key_ed25519 = ik_private_ed25519,
    )

    db_session.add(identity_key)
    await db_session.commit()
    await db_session.refresh(identity_key)
    return identity_key


@pytest_asyncio.fixture
async def test_signed_prekey(
    db_session: AsyncSession,
    test_user: User,
    test_identity_key: IdentityKey
) -> SignedPrekey:
    """
    Create signed prekey for test user
    """
    spk_private, spk_public, spk_signature = x3dh_manager.generate_signed_prekey(
        test_identity_key.private_key_ed25519
    )

    signed_prekey = SignedPrekey(
        user_id = test_user.id,
        key_id = 1,
        public_key = spk_public,
        private_key = spk_private,
        signature = spk_signature,
        is_active = True,
    )

    db_session.add(signed_prekey)
    await db_session.commit()
    await db_session.refresh(signed_prekey)
    return signed_prekey


@pytest_asyncio.fixture
async def test_one_time_prekey(
    db_session: AsyncSession,
    test_user: User
) -> OneTimePrekey:
    """
    Create one-time prekey for test user
    """
    opk_private, opk_public = x3dh_manager.generate_one_time_prekey()

    one_time_prekey = OneTimePrekey(
        user_id = test_user.id,
        key_id = 1,
        public_key = opk_public,
        private_key = opk_private,
        is_used = False,
    )

    db_session.add(one_time_prekey)
    await db_session.commit()
    await db_session.refresh(one_time_prekey)
    return one_time_prekey


@pytest.fixture
def mock_webauthn_credential() -> dict[str, Any]:
    """
    Mock WebAuthn credential response
    """
    return {
        "id": bytes_to_base64url(uuid4().bytes),
        "rawId": bytes_to_base64url(uuid4().bytes),
        "type": "public-key",
        "response": {
            "clientDataJSON": bytes_to_base64url(b'{"type":"webauthn.create"}'),
            "attestationObject": bytes_to_base64url(b"mock_attestation"),
        },
    }


@pytest.fixture
def sample_plaintext() -> str:
    """
    Sample message for encryption tests
    """
    return "Hello, this is a test message!"


@pytest.fixture
def sample_associated_data() -> bytes:
    """
    Sample associated data for AEAD
    """
    return b"test_sender:test_recipient"
