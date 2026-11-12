"""
©AngelaMos | 2026
auth.py
"""

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request, Response, status
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlmodel.ext.asyncio.session import AsyncSession

from app.config import (
    RATE_LIMIT_AUTH_BEGIN,
    RATE_LIMIT_AUTH_COMPLETE,
    RATE_LIMIT_REGISTER_BEGIN,
    RATE_LIMIT_USER_SEARCH,
)
from app.core.dependencies import (
    current_user,
    issue_session,
    revoke_session,
    session_token_from_cookie,
)
from app.models.Base import get_session
from app.models.User import User
from app.schemas.auth import (
    AuthenticationBeginRequest,
    AuthenticationCompleteRequest,
    RegistrationBeginRequest,
    RegistrationCompleteRequest,
    UserResponse,
    UserSearchRequest,
    UserSearchResponse,
)
from app.services.auth_service import auth_service


logger = logging.getLogger(__name__)

router = APIRouter(prefix = "/auth", tags = ["authentication"])

limiter = Limiter(key_func = get_remote_address)


def _user_to_response(user: User) -> UserResponse:
    """
    Adapt the ORM User into the API response model
    """
    return UserResponse(
        id = str(user.id),
        username = user.username,
        display_name = user.display_name,
        is_active = user.is_active,
        is_verified = user.is_verified,
        created_at = user.created_at.isoformat(),
    )


@router.post("/register/begin", status_code = status.HTTP_200_OK)
@limiter.limit(RATE_LIMIT_REGISTER_BEGIN)
async def register_begin(
    request: Request,
    body: RegistrationBeginRequest,
    session: AsyncSession = Depends(get_session),
) -> dict[str,
          Any]:
    """
    Begin WebAuthn passkey registration flow
    """
    return await auth_service.begin_registration(session, body)


@router.post("/register/complete", status_code = status.HTTP_201_CREATED)
@limiter.limit(RATE_LIMIT_AUTH_COMPLETE)
async def register_complete(
    request: Request,
    body: RegistrationCompleteRequest,
    response: Response,
    session: AsyncSession = Depends(get_session),
) -> UserResponse:
    """
    Complete WebAuthn passkey registration and start a session
    """
    user = await auth_service.complete_registration(session, body, body.username)
    await issue_session(response, user)
    return _user_to_response(user)


@router.post("/authenticate/begin", status_code = status.HTTP_200_OK)
@limiter.limit(RATE_LIMIT_AUTH_BEGIN)
async def authenticate_begin(
    request: Request,
    body: AuthenticationBeginRequest,
    session: AsyncSession = Depends(get_session),
) -> dict[str,
          Any]:
    """
    Begin WebAuthn passkey authentication flow
    """
    return await auth_service.begin_authentication(session, body)


@router.post("/authenticate/complete", status_code = status.HTTP_200_OK)
@limiter.limit(RATE_LIMIT_AUTH_COMPLETE)
async def authenticate_complete(
    request: Request,
    body: AuthenticationCompleteRequest,
    response: Response,
    session: AsyncSession = Depends(get_session),
) -> UserResponse:
    """
    Complete WebAuthn passkey authentication and start a session
    """
    user = await auth_service.complete_authentication(session, body)
    await issue_session(response, user)
    return _user_to_response(user)


@router.get("/me", status_code = status.HTTP_200_OK)
async def me(user: User = Depends(current_user)) -> UserResponse:
    """
    Return the user bound to the current session
    """
    return _user_to_response(user)


@router.post("/logout", status_code = status.HTTP_204_NO_CONTENT)
async def logout(
    response: Response,
    token: str | None = Depends(session_token_from_cookie),
) -> None:
    """
    Invalidate the current session and clear its cookie
    """
    await revoke_session(response, token)


@router.post("/users/search", status_code = status.HTTP_200_OK)
@limiter.limit(RATE_LIMIT_USER_SEARCH)
async def search_users(
    request: Request,
    body: UserSearchRequest,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> UserSearchResponse:
    """
    Search for users by username or display name
    """
    users = await auth_service.search_users(
        session,
        body.query,
        body.limit,
        exclude_user_id = user.id,
    )

    return UserSearchResponse(users = [_user_to_response(u) for u in users])
