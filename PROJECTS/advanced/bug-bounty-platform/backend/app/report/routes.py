"""
ⒸAngelaMos | 2025
routes.py
"""

from uuid import UUID

from fastapi import APIRouter, Query, status

from config import ReportStatus
from core.dependencies import CurrentUser
from core.responses import (
    AUTH_401,
    FORBIDDEN_403,
    NOT_FOUND_404,
)
from .schemas import (
    CommentCreate,
    CommentResponse,
    ReportCreate,
    ReportDetailResponse,
    ReportListResponse,
    ReportResponse,
    ReportStatsResponse,
    ReportTriageUpdate,
    ReportUpdate,
)
from .dependencies import ReportServiceDep


router = APIRouter(prefix = "/reports", tags = ["reports"])


@router.post(
    "",
    response_model = ReportResponse,
    status_code = status.HTTP_201_CREATED,
    responses = {
        **AUTH_401,
        **NOT_FOUND_404
    },
)
async def submit_report(
    report_service: ReportServiceDep,
    current_user: CurrentUser,
    report_data: ReportCreate,
) -> ReportResponse:
    """
    Submit a new vulnerability report
    """
    return await report_service.submit_report(current_user, report_data)


@router.get(
    "",
    response_model = ReportListResponse,
    responses = {**AUTH_401},
)
async def list_my_reports(
    report_service: ReportServiceDep,
    current_user: CurrentUser,
    page: int = Query(default = 1,
                      ge = 1),
    size: int = Query(default = 20,
                      ge = 1,
                      le = 100),
) -> ReportListResponse:
    """
    List reports submitted by current user
    """
    return await report_service.list_my_reports(current_user, page, size)


@router.get(
    "/inbox",
    response_model = ReportListResponse,
    responses = {**AUTH_401},
)
async def list_inbox(
    report_service: ReportServiceDep,
    current_user: CurrentUser,
    page: int = Query(default = 1,
                      ge = 1),
    size: int = Query(default = 20,
                      ge = 1,
                      le = 100),
) -> ReportListResponse:
    """
    List all reports across user's programs (company inbox)
    """
    return await report_service.list_inbox(current_user, page, size)


@router.get(
    "/stats",
    response_model = ReportStatsResponse,
    responses = {**AUTH_401},
)
async def get_my_stats(
    report_service: ReportServiceDep,
    current_user: CurrentUser,
) -> ReportStatsResponse:
    """
    Get current user's report statistics
    """
    return await report_service.get_my_stats(current_user)


@router.get(
    "/program/{program_id}",
    response_model = ReportListResponse,
    responses = {
        **AUTH_401,
        **FORBIDDEN_403,
        **NOT_FOUND_404
    },
)
async def list_program_reports(
    report_service: ReportServiceDep,
    current_user: CurrentUser,
    program_id: UUID,
    page: int = Query(default = 1,
                      ge = 1),
    size: int = Query(default = 20,
                      ge = 1,
                      le = 100),
    status_filter: ReportStatus | None = None,
) -> ReportListResponse:
    """
    List reports for a specific program (program owner only)
    """
    return await report_service.list_program_reports(
        current_user,
        program_id,
        page,
        size,
        status_filter,
    )


@router.get(
    "/{report_id}",
    response_model = ReportDetailResponse,
    responses = {
        **AUTH_401,
        **NOT_FOUND_404
    },
)
async def get_report(
    report_service: ReportServiceDep,
    current_user: CurrentUser,
    report_id: UUID,
) -> ReportDetailResponse:
    """
    Get report by ID with full details
    """
    return await report_service.get_report(current_user, report_id)


@router.patch(
    "/{report_id}",
    response_model = ReportResponse,
    responses = {
        **AUTH_401,
        **FORBIDDEN_403,
        **NOT_FOUND_404
    },
)
async def update_report(
    report_service: ReportServiceDep,
    current_user: CurrentUser,
    report_id: UUID,
    report_data: ReportUpdate,
) -> ReportResponse:
    """
    Update report (researcher only, only if still open)
    """
    return await report_service.update_report(
        current_user,
        report_id,
        report_data
    )


@router.patch(
    "/{report_id}/triage",
    response_model = ReportResponse,
    responses = {
        **AUTH_401,
        **FORBIDDEN_403,
        **NOT_FOUND_404
    },
)
async def triage_report(
    report_service: ReportServiceDep,
    current_user: CurrentUser,
    report_id: UUID,
    triage_data: ReportTriageUpdate,
) -> ReportResponse:
    """
    Triage a report (program owner only)
    """
    return await report_service.triage_report(
        current_user,
        report_id,
        triage_data
    )


@router.get(
    "/{report_id}/comments",
    response_model = list[CommentResponse],
    responses = {
        **AUTH_401,
        **NOT_FOUND_404
    },
)
async def list_comments(
    report_service: ReportServiceDep,
    current_user: CurrentUser,
    report_id: UUID,
) -> list[CommentResponse]:
    """
    List comments for a report
    """
    return await report_service.list_comments(current_user, report_id)


@router.post(
    "/{report_id}/comments",
    response_model = CommentResponse,
    status_code = status.HTTP_201_CREATED,
    responses = {
        **AUTH_401,
        **NOT_FOUND_404
    },
)
async def add_comment(
    report_service: ReportServiceDep,
    current_user: CurrentUser,
    report_id: UUID,
    comment_data: CommentCreate,
) -> CommentResponse:
    """
    Add comment to a report
    """
    return await report_service.add_comment(
        current_user,
        report_id,
        comment_data
    )
