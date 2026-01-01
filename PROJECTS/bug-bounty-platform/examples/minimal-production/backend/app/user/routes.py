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
    PasswordChange,
    UserCreate,
    UserResponse,
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


@router.post(
    "/change-password",
    status_code = status.HTTP_204_NO_CONTENT,
    responses = {**AUTH_401}
)
async def change_password(
    user_service: UserServiceDep,
    current_user: CurrentUser,
    data: PasswordChange,
) -> None:
    """
    Change current user password
    """
    await user_service.change_password(
        current_user,
        data.current_password,
        data.new_password,
    )
