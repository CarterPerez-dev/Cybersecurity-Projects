"""
ⒸAngelaMos | 2025
dependencies.py
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

import jwt
from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from config import (
    API_PREFIX,
    TokenType,
)
from .database import get_db_session
from .exceptions import (
    InactiveUser,
    TokenError,
    UserNotFound,
)
from user.User import User
from .security import decode_access_token
from user.repository import UserRepository


oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl = f"{API_PREFIX}/auth/login",
    auto_error = True,
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


CurrentUser = Annotated["User", Depends(get_current_active_user)]
