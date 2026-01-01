"""
ⒸAngelaMos | 2025
dependencies.py
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

import jwt
from fastapi import Depends, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from config import (
    API_PREFIX,
    TokenType,
    UserRole,
)
from .database import get_db_session
from .exceptions import (
    InactiveUser,
    PermissionDenied,
    TokenError,
    TokenRevokedError,
    UserNotFound,
)
from user.User import User
from .security import decode_access_token
from user.repository import UserRepository


oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl = f"{API_PREFIX}/auth/login",
    auto_error = True,
)

oauth2_scheme_optional = OAuth2PasswordBearer(
    tokenUrl = f"{API_PREFIX}/auth/login",
    auto_error = False,
)

DBSession = Annotated[AsyncSession, Depends(get_db_session)]


async def get_current_user(
    token: Annotated[str,
                     Depends(oauth2_scheme)],
    db: DBSession,
) -> User:
    """
    Validate access token and return current user
    """
    try:
        payload = decode_access_token(token)
    except jwt.InvalidTokenError as e:
        raise TokenError(message = str(e)) from e

    if payload.get("type") != TokenType.ACCESS.value:
        raise TokenError(message = "Invalid token type")

    user_id = UUID(payload["sub"])
    user = await UserRepository.get_by_id(db, user_id)

    if user is None:
        raise UserNotFound(identifier = str(user_id))

    if payload.get("token_version") != user.token_version:
        raise TokenRevokedError()

    return user


async def get_current_active_user(
    user: Annotated[User,
                    Depends(get_current_user)],
) -> User:
    """
    Ensure user is active
    """
    if not user.is_active:
        raise InactiveUser()
    return user


async def get_optional_user(
    token: Annotated[str | None,
                     Depends(oauth2_scheme_optional)],
    db: DBSession,
) -> User | None:
    """
    Return current user if authenticated, None otherwise
    """
    if token is None:
        return None

    try:
        payload = decode_access_token(token)
        if payload.get("type") != TokenType.ACCESS.value:
            return None
        user_id = UUID(payload["sub"])
        user = await UserRepository.get_by_id(db, user_id)
        if user and user.token_version == payload.get("token_version"):
            return user
    except (jwt.InvalidTokenError, ValueError):
        pass

    return None


class RequireRole:
    """
    Dependency class to check user role
    """
    def __init__(self, *allowed_roles: UserRole) -> None:
        self.allowed_roles = allowed_roles

    async def __call__(
        self,
        user: Annotated[User,
                        Depends(get_current_active_user)],
    ) -> User:
        if user.role not in self.allowed_roles:
            raise PermissionDenied(
                message =
                f"Requires one of roles: {', '.join(r.value for r in self.allowed_roles)}",
            )
        return user


CurrentUser = Annotated["User", Depends(get_current_active_user)]
OptionalUser = Annotated["User | None", Depends(get_optional_user)]


def get_client_ip(request: Request) -> str:
    """
    Extract client IP considering proxy headers
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


ClientIP = Annotated[str, Depends(get_client_ip)]
