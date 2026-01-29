"""
ⒸAngelaMos | 2025
schemas.py
"""

from uuid import UUID
from datetime import datetime
from decimal import Decimal

from pydantic import Field

from config import (
    CWE_ID_MAX_LENGTH,
    REPORT_TITLE_MAX_LENGTH,
    ReportStatus,
    Severity,
)
from core.base_schema import (
    BaseSchema,
    BaseResponseSchema,
)


class ReportCreate(BaseSchema):
    """
    Schema for submitting a vulnerability report
    """
    program_id: UUID
    title: str = Field(max_length = REPORT_TITLE_MAX_LENGTH)
    description: str
    steps_to_reproduce: str | None = None
    impact: str | None = None
    severity_submitted: Severity = Severity.MEDIUM


class ReportUpdate(BaseSchema):
    """
    Schema for researcher updating their report
    """
    title: str | None = Field(
        default = None,
        max_length = REPORT_TITLE_MAX_LENGTH
    )
    description: str | None = None
    steps_to_reproduce: str | None = None
    impact: str | None = None
    severity_submitted: Severity | None = None


class ReportTriageUpdate(BaseSchema):
    """
    Schema for company triaging a report
    """
    status: ReportStatus | None = None
    severity_final: Severity | None = None
    cvss_score: Decimal | None = Field(default = None, ge = 0, le = 10)
    cwe_id: str | None = Field(
        default = None,
        max_length = CWE_ID_MAX_LENGTH
    )
    bounty_amount: int | None = Field(default = None, ge = 0)
    duplicate_of_id: UUID | None = None


class ReportResponse(BaseResponseSchema):
    """
    Schema for report API responses
    """
    program_id: UUID
    researcher_id: UUID
    title: str
    description: str
    steps_to_reproduce: str | None
    impact: str | None
    severity_submitted: Severity
    severity_final: Severity | None
    status: ReportStatus
    cvss_score: Decimal | None
    cwe_id: str | None
    bounty_amount: int | None
    duplicate_of_id: UUID | None
    triaged_at: datetime | None
    resolved_at: datetime | None
    disclosed_at: datetime | None


class ReportListResponse(BaseSchema):
    """
    Schema for paginated report list
    """
    items: list[ReportResponse]
    total: int
    page: int
    size: int


class CommentCreate(BaseSchema):
    """
    Schema for adding a comment to a report
    """
    content: str
    is_internal: bool = False


class CommentResponse(BaseResponseSchema):
    """
    Schema for comment API responses
    """
    report_id: UUID
    author_id: UUID
    content: str
    is_internal: bool


class AttachmentResponse(BaseResponseSchema):
    """
    Schema for attachment API responses
    """
    report_id: UUID
    comment_id: UUID | None
    filename: str
    mime_type: str
    size_bytes: int


class ReportDetailResponse(ReportResponse):
    """
    Schema for report detail with comments
    """
    comments: list[CommentResponse]
    attachments: list[AttachmentResponse]


class ReportStatsResponse(BaseSchema):
    """
    Schema for researcher stats
    """
    total_reports: int
    accepted_reports: int
    total_earned: int
    reputation_score: int
