"""
ⒸAngelaMos | 2025
Attachment.py
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import BigInteger, ForeignKey, String
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
    relationship,
)

from config import (
    FILENAME_MAX_LENGTH,
    MIME_TYPE_MAX_LENGTH,
    STORAGE_PATH_MAX_LENGTH,
)
from core.Base import (
    Base,
    TimestampMixin,
    UUIDMixin,
)

if TYPE_CHECKING:
    from report.Report import Report


class Attachment(Base, UUIDMixin, TimestampMixin):
    """
    File attachment on a vulnerability report
    """
    __tablename__ = "attachments"

    report_id: Mapped[UUID] = mapped_column(
        ForeignKey("reports.id",
                   ondelete = "CASCADE"),
        index = True,
    )
    comment_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("comments.id",
                   ondelete = "SET NULL"),
        default = None,
    )

    filename: Mapped[str] = mapped_column(
        String(FILENAME_MAX_LENGTH),
    )
    storage_path: Mapped[str] = mapped_column(
        String(STORAGE_PATH_MAX_LENGTH),
    )
    mime_type: Mapped[str] = mapped_column(
        String(MIME_TYPE_MAX_LENGTH),
    )
    size_bytes: Mapped[int] = mapped_column(BigInteger)

    report: Mapped[Report] = relationship(
        back_populates = "attachments",
        lazy = "raise",
    )
