"""
ⒸAngelaMos | 2025
routes.py
"""

from uuid import UUID
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    Query,
    status,
)

from config import (
    settings,
    UserRole,
)
from core.dependencies import RequireRole
from core.responses import (
    AUTH_401,
    CONFLICT_409,
    FORBIDDEN_403,
    NOT_FOUND_404,
)
from user.schemas import (
    AdminUserCreate,
    UserListResponse,
    UserResponse,
    UserUpdateAdmin,
)
from user.User import User
from user.dependencies import UserServiceDep


router = APIRouter(prefix = "/admin", tags = ["admin"])

AdminOnly = Annotated[User, Depends(RequireRole(UserRole.ADMIN))]


@router.get(
    "/users",
    response_model = UserListResponse,
    responses = {
        **AUTH_401,
        **FORBIDDEN_403
    },
)
async def list_users(
    user_service: UserServiceDep,
    _: AdminOnly,
    page: int = Query(default = 1,
                      ge = 1),
    size: int = Query(
        default = settings.PAGINATION_DEFAULT_SIZE,
        ge = 1,
        le = settings.PAGINATION_MAX_SIZE
    ),
) -> UserListResponse:
    """
    List all users (admin only)
    """
    return await user_service.list_users(page, size)


@router.post(
    "/users",
    response_model = UserResponse,
    status_code = status.HTTP_201_CREATED,
    responses = {
        **AUTH_401,
        **FORBIDDEN_403,
        **CONFLICT_409
    },
)
async def create_user(
    user_service: UserServiceDep,
    _: AdminOnly,
    user_data: AdminUserCreate,
) -> UserResponse:
    """
    Create a new user (admin only, bypasses registration)
    """
    return await user_service.admin_create_user(user_data)


@router.get(
    "/users/{user_id}",
    response_model = UserResponse,
    responses = {
        **AUTH_401,
        **FORBIDDEN_403,
        **NOT_FOUND_404
    },
)
async def get_user(
    user_service: UserServiceDep,
    _: AdminOnly,
    user_id: UUID,
) -> UserResponse:
    """
    Get user by ID (admin only)
    """
    return await user_service.get_user_by_id(user_id)


@router.patch(
    "/users/{user_id}",
    response_model = UserResponse,
    responses = {
        **AUTH_401,
        **FORBIDDEN_403,
        **NOT_FOUND_404,
        **CONFLICT_409
    },
)
async def update_user(
    user_service: UserServiceDep,
    _: AdminOnly,
    user_id: UUID,
    user_data: UserUpdateAdmin,
) -> UserResponse:
    """
    Update user (admin only)
    """
    return await user_service.admin_update_user(user_id, user_data)


@router.delete(
    "/users/{user_id}",
    status_code = status.HTTP_204_NO_CONTENT,
    responses = {
        **AUTH_401,
        **FORBIDDEN_403,
        **NOT_FOUND_404
    },
)
async def delete_user(
    user_service: UserServiceDep,
    _: AdminOnly,
    user_id: UUID,
) -> None:
    """
    Delete user (admin only, hard delete)
    """
    await user_service.admin_delete_user(user_id)
