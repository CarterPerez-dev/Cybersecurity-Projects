"""
©AngelaMos | 2026
dependencies.py
"""

import logging
import secrets
from uuid import UUID

from fastapi import Cookie, Depends, HTTPException, Response, status
from sqlmodel.ext.asyncio.session import AsyncSession

from app.config import (
    SESSION_COOKIE_NAME,
    SESSION_TOKEN_BYTES,
    SESSION_TTL_SECONDS,
    settings,
)
from app.core.redis_manager import redis_manager
from app.models.Base import get_session
from app.models.User import User
from app.services.auth_service import auth_service


logger = logging.getLogger(__name__)


async def issue_session(response: Response, user: User) -> str:
    """
    Create a session token, persist it in Redis, and attach the cookie
    """
    token = secrets.token_urlsafe(SESSION_TOKEN_BYTES)
    await redis_manager.create_session(
        token = token,
        user_id = str(user.id),
        ttl = SESSION_TTL_SECONDS,
    )
    response.set_cookie(
        key = SESSION_COOKIE_NAME,
        value = token,
        max_age = SESSION_TTL_SECONDS,
        httponly = True,
        secure = settings.is_production,
        samesite = "lax",
        path = "/",
    )
    return token


async def revoke_session(response: Response, token: str | None) -> None:
    """
    Drop the session token from Redis and clear the cookie
    """
    if token:
        await redis_manager.delete_session(token)
    response.delete_cookie(
        key = SESSION_COOKIE_NAME,
        path = "/",
    )


async def current_user(
    chat_session: str | None = Cookie(default = None,
                                      alias = SESSION_COOKIE_NAME),
    session: AsyncSession = Depends(get_session),
) -> User:
    """
    Resolve the user bound to the current session cookie or 401
    """
    if not chat_session:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "Not authenticated",
        )

    user_id_str = await redis_manager.get_session_user(chat_session)
    if user_id_str is None:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "Session expired or invalid",
        )

    try:
        user_id = UUID(user_id_str)
    except ValueError as exc:
        logger.error("Corrupt session payload for token: %s", exc)
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "Session expired or invalid",
        ) from exc

    user = await auth_service.get_user_by_id(session = session, user_id = user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "Session expired or invalid",
        )

    return user


async def session_token_from_cookie(
    chat_session: str | None = Cookie(default = None,
                                      alias = SESSION_COOKIE_NAME),
) -> str | None:
    """
    Pass-through dependency to read the session cookie value
    """
    return chat_session
