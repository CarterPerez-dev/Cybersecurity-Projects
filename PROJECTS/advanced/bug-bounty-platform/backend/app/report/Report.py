"""
ⒸAngelaMos | 2025
Report.py
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Numeric, String, Text
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
    relationship,
)

from config import (
    CWE_ID_MAX_LENGTH,
    REPORT_TITLE_MAX_LENGTH,
    ReportStatus,
    SafeEnum,
    Severity,
)
from core.Base import (
    Base,
    TimestampMixin,
    UUIDMixin,
)

if TYPE_CHECKING:
    from program.Program import Program
    from report.Attachment import Attachment
    from report.Comment import Comment
    from user.User import User


class Report(Base, UUIDMixin, TimestampMixin):
    """
    Vulnerability report submitted by a researcher
    """
    __tablename__ = "reports"

    program_id: Mapped[UUID] = mapped_column(
        ForeignKey("programs.id",
                   ondelete = "CASCADE"),
        index = True,
    )
    researcher_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id",
                   ondelete = "CASCADE"),
        index = True,
    )

    title: Mapped[str] = mapped_column(
        String(REPORT_TITLE_MAX_LENGTH),
    )
    description: Mapped[str] = mapped_column(Text)
    steps_to_reproduce: Mapped[str | None] = mapped_column(
        Text,
        default = None,
    )
    impact: Mapped[str | None] = mapped_column(
        Text,
        default = None,
    )

    severity_submitted: Mapped[Severity] = mapped_column(
        SafeEnum(Severity),
        default = Severity.MEDIUM,
    )
    severity_final: Mapped[Severity | None] = mapped_column(
        SafeEnum(Severity),
        default = None,
    )

    status: Mapped[ReportStatus] = mapped_column(
        SafeEnum(ReportStatus),
        default = ReportStatus.NEW,
        index = True,
    )

    cvss_score: Mapped[Decimal | None] = mapped_column(
        Numeric(precision = 3,
                scale = 1),
        default = None,
    )
    cwe_id: Mapped[str | None] = mapped_column(
        String(CWE_ID_MAX_LENGTH),
        default = None,
    )

    bounty_amount: Mapped[int | None] = mapped_column(default = None)

    duplicate_of_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("reports.id",
                   ondelete = "SET NULL"),
        default = None,
    )

    triaged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone = True),
        default = None,
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone = True),
        default = None,
    )
    disclosed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone = True),
        default = None,
    )

    program: Mapped[Program] = relationship(
        back_populates = "reports",
        lazy = "raise",
    )
    researcher: Mapped[User] = relationship(
        back_populates = "reports",
        lazy = "raise",
    )

    comments: Mapped[list[Comment]] = relationship(
        back_populates = "report",
        cascade = "all, delete-orphan",
        lazy = "raise",
    )
    attachments: Mapped[list[Attachment]] = relationship(
        back_populates = "report",
        cascade = "all, delete-orphan",
        lazy = "raise",
    )

    duplicate_of: Mapped[Report | None] = relationship(
        remote_side = "Report.id",
        lazy = "raise",
    )

    def mark_triaging(self) -> None:
        """
        Transition report to triaging status
        """
        self.status = ReportStatus.TRIAGING
        self.triaged_at = datetime.now(UTC)

    def mark_resolved(self) -> None:
        """
        Transition report to resolved status
        """
        self.status = ReportStatus.RESOLVED
        self.resolved_at = datetime.now(UTC)

    def mark_disclosed(self) -> None:
        """
        Transition report to disclosed status
        """
        self.status = ReportStatus.DISCLOSED
        self.disclosed_at = datetime.now(UTC)

    @property
    def is_open(self) -> bool:
        """
        Check if report is still open for action
        """
        return self.status in (
            ReportStatus.NEW,
            ReportStatus.TRIAGING,
            ReportStatus.NEEDS_MORE_INFO,
        )

    @property
    def is_closed(self) -> bool:
        """
        Check if report has reached a terminal state
        """
        return self.status in (
            ReportStatus.ACCEPTED,
            ReportStatus.DUPLICATE,
            ReportStatus.INFORMATIVE,
            ReportStatus.NOT_APPLICABLE,
            ReportStatus.RESOLVED,
            ReportStatus.DISCLOSED,
        )
