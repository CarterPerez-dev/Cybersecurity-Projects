"""
ⒸAngelaMos | 2025
security.py
"""

import asyncio
import hashlib
import secrets
from datetime import (
    UTC,
    datetime,
    timedelta,
)
from typing import Any
from uuid import UUID

import jwt
from fastapi import Response
from pwdlib import PasswordHash

from config import (
    API_PREFIX,
    settings,
    TokenType,
)


password_hasher = PasswordHash.recommended()


async def hash_password(password: str) -> str:
    """
    Hash password using Argon2id

    Runs in thread pool to avoid blocking the async event loop
    since Argon2 is CPU intensive by design
    """
    return await asyncio.to_thread(password_hasher.hash, password)


async def verify_password(plain_password: str,
                          hashed_password: str) -> tuple[bool,
                                                         str | None]:
    """
    Verify password and check if rehash is needed

    Returns:
        Tuple of (is_valid, new_hash_if_needs_rehash)
        If password is valid but hash params are outdated, returns new hash
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

    If no hash is provided (user doesn't exist), still performs a dummy
    hash operation to prevent timing attacks
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
    token_version: int,
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
        "token_version": token_version,
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


def create_refresh_token(
    user_id: UUID,
    family_id: UUID,
) -> tuple[str,
           str,
           datetime]:
    """
    Create a long lived refresh token

    Returns:
        Tuple of (raw_token, token_hash, expires_at)
        Raw token is sent to client, hash is stored in database
    """
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = datetime.now(UTC) + timedelta(
        days = settings.REFRESH_TOKEN_EXPIRE_DAYS
    )

    return raw_token, token_hash, expires_at


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Decode and validate an access token

    Raises:
        jwt.InvalidTokenError: If token is invalid or expired
    """
    return jwt.decode(
        token,
        settings.SECRET_KEY.get_secret_value(),
        algorithms = [settings.JWT_ALGORITHM],
        options = {
            "require": ["exp",
                        "sub",
                        "iat",
                        "type",
                        "token_version"]
        },
    )


def hash_token(token: str) -> str:
    """
    Hash a token for secure storage
    """
    return hashlib.sha256(token.encode()).hexdigest()


def generate_secure_token(nbytes: int = 32) -> str:
    """
    Generate a cryptographically secure random token
    """
    return secrets.token_urlsafe(nbytes)


def set_refresh_cookie(response: Response, token: str) -> None:
    """
    Set refresh token as HttpOnly cookie
    """
    response.set_cookie(
        key = "refresh_token",
        value = token,
        httponly = True,
        secure = settings.ENVIRONMENT.value != "development",
        samesite = "strict",
        max_age = settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        path = f"{API_PREFIX}/auth",
    )


def clear_refresh_cookie(response: Response) -> None:
    """
    Clear refresh token cookie
    """
    response.delete_cookie(
        key = "refresh_token",
        path = f"{API_PREFIX}/auth"
    )
