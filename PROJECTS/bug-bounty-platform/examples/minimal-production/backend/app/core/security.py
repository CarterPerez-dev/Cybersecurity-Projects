"""
ⒸAngelaMos | 2025
security.py
"""

import asyncio
from datetime import (
    UTC,
    datetime,
    timedelta,
)
from typing import Any
from uuid import UUID

import jwt
from pwdlib import PasswordHash

from config import (
    settings,
    TokenType,
)


password_hasher = PasswordHash.recommended()


async def hash_password(password: str) -> str:
    """
    Hash password using Argon2id
    """
    return await asyncio.to_thread(password_hasher.hash, password)


async def verify_password(plain_password: str,
                          hashed_password: str) -> tuple[bool,
                                                         str | None]:
    """
    Verify password and check if rehash is needed
    """
    try:
        return await asyncio.to_thread(
            password_hasher.verify_and_update,
            plain_password,
            hashed_password
        )
    except Exception:
        return False, None


DUMMY_HASH = password_hasher.hash(
    "dummy_password_for_timing_attack_prevention"
)


async def verify_password_with_timing_safety(
    plain_password: str,
    hashed_password: str | None,
) -> tuple[bool,
           str | None]:
    """
    Verify password with constant time behavior to prevent user enumeration
    """
    if hashed_password is None:
        await asyncio.to_thread(
            password_hasher.verify,
            plain_password,
            DUMMY_HASH
        )
        return False, None
    return await verify_password(plain_password, hashed_password)


def create_access_token(
    user_id: UUID,
    extra_claims: dict[str,
                       Any] | None = None,
) -> str:
    """
    Create a short lived access token
    """
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "type": TokenType.ACCESS.value,
        "iat": now,
        "exp":
        now + timedelta(minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    if extra_claims:
        payload.update(extra_claims)

    return jwt.encode(
        payload,
        settings.SECRET_KEY.get_secret_value(),
        algorithm = settings.JWT_ALGORITHM,
    )


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Decode and validate an access token
    """
    return jwt.decode(
        token,
        settings.SECRET_KEY.get_secret_value(),
        algorithms = [settings.JWT_ALGORITHM],
        options = {
            "require": ["exp",
                        "sub",
                        "iat",
                        "type"]
        },
    )
