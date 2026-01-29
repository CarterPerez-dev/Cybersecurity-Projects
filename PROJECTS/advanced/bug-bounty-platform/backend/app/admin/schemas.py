"""
ⒸAngelaMos | 2026
schemas.py
"""

from datetime import datetime
from decimal import Decimal
from uuid import UUID

from pydantic import Field

from config import (
    ProgramStatus,
    ProgramVisibility,
    ReportStatus,
    Severity,
    UserRole,
)
from core.base_schema import BaseSchema, BaseResponseSchema


class AdminProgramUpdate(BaseSchema):
    """
    Schema for admin updating a program
    """
    name: str | None = None
    status: ProgramStatus | None = None
    visibility: ProgramVisibility | None = None
    is_featured: bool | None = None


class AdminProgramResponse(BaseResponseSchema):
    """
    Schema for admin program view with company info
    """
    company_id: UUID
    company_email: str
    company_name: str | None
    name: str
    slug: str
    description: str | None
    status: ProgramStatus
    visibility: ProgramVisibility
    response_sla_hours: int
    report_count: int


class AdminProgramListResponse(BaseSchema):
    """
    Schema for paginated admin program list
    """
    items: list[AdminProgramResponse]
    total: int
    page: int
    size: int


class AdminReportUpdate(BaseSchema):
    """
    Schema for admin overriding a report
    """
    status: ReportStatus | None = None
    severity_final: Severity | None = None
    cvss_score: Decimal | None = Field(default = None, ge = 0, le = 10)
    bounty_amount: int | None = Field(default = None, ge = 0)
    admin_notes: str | None = None


class AdminReportResponse(BaseResponseSchema):
    """
    Schema for admin report view with program/researcher info
    """
    program_id: UUID
    program_name: str
    program_slug: str
    researcher_id: UUID
    researcher_email: str
    researcher_name: str | None
    title: str
    severity_submitted: Severity
    severity_final: Severity | None
    status: ReportStatus
    bounty_amount: int | None
    triaged_at: datetime | None
    resolved_at: datetime | None


class AdminReportListResponse(BaseSchema):
    """
    Schema for paginated admin report list
    """
    items: list[AdminReportResponse]
    total: int
    page: int
    size: int


class PlatformStatsResponse(BaseSchema):
    """
    Schema for platform-wide statistics
    """
    total_users: int
    total_researchers: int
    total_companies: int
    total_programs: int
    active_programs: int
    total_reports: int
    reports_by_status: dict[str, int]
    total_bounties_paid: int
    reports_this_month: int
    new_users_this_month: int


class AdminUserResponse(BaseResponseSchema):
    """
    Schema for admin user view with stats
    """
    email: str
    full_name: str | None
    company_name: str | None
    is_active: bool
    is_verified: bool
    role: UserRole
    reputation_score: int
    program_count: int
    report_count: int


class AdminUserListResponse(BaseSchema):
    """
    Schema for paginated admin user list with stats
    """
    items: list[AdminUserResponse]
    total: int
    page: int
    size: int
