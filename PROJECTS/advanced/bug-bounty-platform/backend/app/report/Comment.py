"""
ⒸAngelaMos | 2025
Comment.py
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import ForeignKey, Text
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
    relationship,
)

from core.Base import (
    Base,
    TimestampMixin,
    UUIDMixin,
)

if TYPE_CHECKING:
    from report.Report import Report
    from user.User import User


class Comment(Base, UUIDMixin, TimestampMixin):
    """
    Comment on a vulnerability report
    """
    __tablename__ = "comments"

    report_id: Mapped[UUID] = mapped_column(
        ForeignKey("reports.id",
                   ondelete = "CASCADE"),
        index = True,
    )
    author_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id",
                   ondelete = "CASCADE"),
        index = True,
    )

    content: Mapped[str] = mapped_column(Text)

    is_internal: Mapped[bool] = mapped_column(default = False)

    report: Mapped[Report] = relationship(
        back_populates = "comments",
        lazy = "raise",
    )
    author: Mapped[User] = relationship(lazy = "raise")
