"""
ⒸAngelaMos | 2025
WebAuthn passkey registration and login API
"""

import logging
from typing import Any

from fastapi import APIRouter, Depends, status
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models.Base import get_session
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


@router.post("/register/begin", status_code = status.HTTP_200_OK)
async def register_begin(
    request: RegistrationBeginRequest,
    session: AsyncSession = Depends(get_session),
) -> dict[str,
          Any]:
    """
    Begin WebAuthn passkey registration flow
    """
    return await auth_service.begin_registration(session, request)


@router.post("/register/complete", status_code = status.HTTP_201_CREATED)
async def register_complete(
    request: RegistrationCompleteRequest,
    session: AsyncSession = Depends(get_session),
) -> UserResponse:
    """
    Complete WebAuthn passkey registration
    """
    return await auth_service.complete_registration(session, request, request.username)


@router.post("/authenticate/begin", status_code = status.HTTP_200_OK)
async def authenticate_begin(
    request: AuthenticationBeginRequest,
    session: AsyncSession = Depends(get_session),
) -> dict[str,
          Any]:
    """
    Begin WebAuthn passkey authentication flow
    """
    return await auth_service.begin_authentication(session, request)


@router.post("/authenticate/complete", status_code = status.HTTP_200_OK)
async def authenticate_complete(
    request: AuthenticationCompleteRequest,
    session: AsyncSession = Depends(get_session),
) -> UserResponse:
    """
    Complete WebAuthn passkey authentication
    """
    return await auth_service.complete_authentication(session, request)


@router.post("/users/search", status_code = status.HTTP_200_OK)
async def search_users(
    request: UserSearchRequest,
    session: AsyncSession = Depends(get_session),
) -> UserSearchResponse:
    """
    Search for users by username or display name
    """
    users = await auth_service.search_users(
        session,
        request.query,
        request.limit,
    )

    return UserSearchResponse(
        users = [
            UserResponse(
                id = str(user.id),
                username = user.username,
                display_name = user.display_name,
                is_active = user.is_active,
                is_verified = user.is_verified,
                created_at = user.created_at.isoformat(),
            )
            for user in users
        ]
    )
