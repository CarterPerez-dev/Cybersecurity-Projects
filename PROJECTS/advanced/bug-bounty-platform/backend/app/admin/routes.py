"""
ⒸAngelaMos | 2026
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
    ProgramStatus,
    ReportStatus,
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
    UserResponse,
    UserUpdateAdmin,
)
from user.User import User
from user.dependencies import UserServiceDep
from .dependencies import AdminServiceDep
from .schemas import (
    AdminProgramListResponse,
    AdminProgramResponse,
    AdminProgramUpdate,
    AdminReportListResponse,
    AdminReportResponse,
    AdminReportUpdate,
    AdminUserListResponse,
    PlatformStatsResponse,
)


router = APIRouter(prefix = "/admin", tags = ["admin"])

AdminOnly = Annotated[User, Depends(RequireRole(UserRole.ADMIN))]


@router.get(
    "/stats",
    response_model = PlatformStatsResponse,
    responses = {
        **AUTH_401,
        **FORBIDDEN_403
    },
)
async def get_platform_stats(
    admin_service: AdminServiceDep,
    _: AdminOnly,
) -> PlatformStatsResponse:
    """
    Get platform-wide statistics (admin only)
    """
    return await admin_service.get_platform_stats()


@router.get(
    "/programs",
    response_model = AdminProgramListResponse,
    responses = {
        **AUTH_401,
        **FORBIDDEN_403
    },
)
async def list_programs(
    admin_service: AdminServiceDep,
    _: AdminOnly,
    page: int = Query(default = 1,
                      ge = 1),
    size: int = Query(
        default = settings.PAGINATION_DEFAULT_SIZE,
        ge = 1,
        le = settings.PAGINATION_MAX_SIZE
    ),
    status_filter: ProgramStatus
    | None = Query(default = None,
                   alias = "status"),
) -> AdminProgramListResponse:
    """
    List all programs (admin only)
    """
    return await admin_service.list_programs(page, size, status_filter)


@router.patch(
    "/programs/{program_id}",
    response_model = AdminProgramResponse,
    responses = {
        **AUTH_401,
        **FORBIDDEN_403,
        **NOT_FOUND_404
    },
)
async def update_program(
    admin_service: AdminServiceDep,
    _: AdminOnly,
    program_id: UUID,
    data: AdminProgramUpdate,
) -> AdminProgramResponse:
    """
    Update a program (admin only)
    """
    return await admin_service.update_program(program_id, data)


@router.delete(
    "/programs/{program_id}",
    status_code = status.HTTP_204_NO_CONTENT,
    responses = {
        **AUTH_401,
        **FORBIDDEN_403,
        **NOT_FOUND_404
    },
)
async def delete_program(
    admin_service: AdminServiceDep,
    _: AdminOnly,
    program_id: UUID,
) -> None:
    """
    Delete a program (admin only, hard delete)
    """
    await admin_service.delete_program(program_id)


@router.get(
    "/reports",
    response_model = AdminReportListResponse,
    responses = {
        **AUTH_401,
        **FORBIDDEN_403
    },
)
async def list_reports(
    admin_service: AdminServiceDep,
    _: AdminOnly,
    page: int = Query(default = 1,
                      ge = 1),
    size: int = Query(
        default = settings.PAGINATION_DEFAULT_SIZE,
        ge = 1,
        le = settings.PAGINATION_MAX_SIZE
    ),
    status_filter: ReportStatus
    | None = Query(default = None,
                   alias = "status"),
    severity_filter: str
    | None = Query(default = None,
                   alias = "severity"),
) -> AdminReportListResponse:
    """
    List all reports (admin only)
    """
    return await admin_service.list_reports(
        page,
        size,
        status_filter,
        severity_filter
    )


@router.patch(
    "/reports/{report_id}",
    response_model = AdminReportResponse,
    responses = {
        **AUTH_401,
        **FORBIDDEN_403,
        **NOT_FOUND_404
    },
)
async def update_report(
    admin_service: AdminServiceDep,
    _: AdminOnly,
    report_id: UUID,
    data: AdminReportUpdate,
) -> AdminReportResponse:
    """
    Update a report (admin only, override)
    """
    return await admin_service.update_report(report_id, data)


@router.get(
    "/users",
    response_model = AdminUserListResponse,
    responses = {
        **AUTH_401,
        **FORBIDDEN_403
    },
)
async def list_users(
    admin_service: AdminServiceDep,
    _: AdminOnly,
    page: int = Query(default = 1,
                      ge = 1),
    size: int = Query(
        default = settings.PAGINATION_DEFAULT_SIZE,
        ge = 1,
        le = settings.PAGINATION_MAX_SIZE
    ),
    role_filter: UserRole | None = Query(default = None,
                                         alias = "role"),
) -> AdminUserListResponse:
    """
    List all users with stats (admin only)
    """
    return await admin_service.list_users_with_stats(
        page,
        size,
        role_filter
    )


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
