"""
ⒸAngelaMos | 2025
routes.py
"""

from uuid import UUID

from fastapi import (
    APIRouter,
    status,
)

from core.dependencies import CurrentUser
from core.responses import (
    AUTH_401,
    CONFLICT_409,
    NOT_FOUND_404,
)
from .schemas import (
    UserCreate,
    UserResponse,
    UserUpdate,
)
from .dependencies import UserServiceDep


router = APIRouter(prefix = "/users", tags = ["users"])


@router.post(
    "",
    response_model = UserResponse,
    status_code = status.HTTP_201_CREATED,
    responses = {**CONFLICT_409},
)
async def create_user(
    user_service: UserServiceDep,
    user_data: UserCreate,
) -> UserResponse:
    """
    Register a new user
    """
    return await user_service.create_user(user_data)


@router.get(
    "/{user_id}",
    response_model = UserResponse,
    responses = {
        **AUTH_401,
        **NOT_FOUND_404
    },
)
async def get_user(
    user_service: UserServiceDep,
    user_id: UUID,
    _: CurrentUser,
) -> UserResponse:
    """
    Get user by ID
    """
    return await user_service.get_user_by_id(user_id)


@router.patch(
    "/me",
    response_model = UserResponse,
    responses = {**AUTH_401},
)
async def update_current_user(
    user_service: UserServiceDep,
    current_user: CurrentUser,
    user_data: UserUpdate,
) -> UserResponse:
    """
    Update current user profile
    """
    return await user_service.update_user(current_user, user_data)
