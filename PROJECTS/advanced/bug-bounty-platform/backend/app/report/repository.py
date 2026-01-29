"""
ⒸAngelaMos | 2025
repository.py
"""

from typing import Any
from collections.abc import Sequence
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from config import ReportStatus
from core.base_repository import BaseRepository
from program.Program import Program
from .Report import Report
from .Comment import Comment
from .Attachment import Attachment


class ReportRepository(BaseRepository[Report]):
    """
    Repository for Report model database operations
    """
    model = Report

    @classmethod
    async def get_by_id_with_details(
        cls,
        session: AsyncSession,
        report_id: UUID,
    ) -> Report | None:
        """
        Get report by ID with comments and attachments
        """
        result = await session.execute(
            select(Report).where(Report.id == report_id).options(
                selectinload(Report.comments),
                selectinload(Report.attachments),
            )
        )
        return result.scalars().first()

    @classmethod
    async def get_by_researcher(
        cls,
        session: AsyncSession,
        researcher_id: UUID,
        skip: int = 0,
        limit: int = 20,
    ) -> Sequence[Report]:
        """
        Get reports by researcher
        """
        result = await session.execute(
            select(Report).where(Report.researcher_id == researcher_id
                                 ).order_by(Report.created_at.desc()
                                            ).offset(skip).limit(limit)
        )
        return result.scalars().all()

    @classmethod
    async def count_by_researcher(
        cls,
        session: AsyncSession,
        researcher_id: UUID,
    ) -> int:
        """
        Count reports by researcher
        """
        result = await session.execute(
            select(func.count()).select_from(Report).where(
                Report.researcher_id == researcher_id
            )
        )
        return result.scalar_one()

    @classmethod
    async def get_by_program(
        cls,
        session: AsyncSession,
        program_id: UUID,
        skip: int = 0,
        limit: int = 20,
        status_filter: ReportStatus | None = None,
    ) -> Sequence[Report]:
        """
        Get reports for a program (inbox view)
        """
        query = select(Report).where(Report.program_id == program_id)

        if status_filter:
            query = query.where(Report.status == status_filter)

        result = await session.execute(
            query.order_by(Report.created_at.desc()
                           ).offset(skip).limit(limit)
        )
        return result.scalars().all()

    @classmethod
    async def count_by_program(
        cls,
        session: AsyncSession,
        program_id: UUID,
        status_filter: ReportStatus | None = None,
    ) -> int:
        """
        Count reports for a program
        """
        query = (
            select(func.count()).select_from(Report).where(
                Report.program_id == program_id
            )
        )

        if status_filter:
            query = query.where(Report.status == status_filter)

        result = await session.execute(query)
        return result.scalar_one()

    @classmethod
    async def get_inbox_for_company(
        cls,
        session: AsyncSession,
        company_id: UUID,
        skip: int = 0,
        limit: int = 20,
    ) -> Sequence[Report]:
        """
        Get all reports across all programs owned by company
        """
        result = await session.execute(
            select(Report).join(Program,
                                Report.program_id == Program.id).where(
                                    Program.company_id == company_id
                                ).order_by(Report.created_at.desc()
                                           ).offset(skip).limit(limit)
        )
        return result.scalars().all()

    @classmethod
    async def count_inbox_for_company(
        cls,
        session: AsyncSession,
        company_id: UUID,
    ) -> int:
        """
        Count all reports for company's programs
        """
        result = await session.execute(
            select(func.count()).select_from(Report).join(
                Program,
                Report.program_id == Program.id
            ).where(Program.company_id == company_id)
        )
        return result.scalar_one()

    @classmethod
    async def get_researcher_stats(
        cls,
        session: AsyncSession,
        researcher_id: UUID,
    ) -> dict[str,
              Any]:
        """
        Get statistics for a researcher
        """
        total_result = await session.execute(
            select(func.count()).select_from(Report).where(
                Report.researcher_id == researcher_id
            )
        )
        total = total_result.scalar_one()

        accepted_result = await session.execute(
            select(func.count()).select_from(Report).where(
                Report.researcher_id == researcher_id,
                Report.status.in_(
                    [
                        ReportStatus.ACCEPTED,
                        ReportStatus.RESOLVED,
                        ReportStatus.DISCLOSED,
                    ]
                )
            )
        )
        accepted = accepted_result.scalar_one()

        earned_result = await session.execute(
            select(func.coalesce(func.sum(Report.bounty_amount),
                                 0)).where(
                                     Report.researcher_id == researcher_id,
                                     Report.bounty_amount.isnot(None),
                                 )
        )
        earned = earned_result.scalar_one()

        return {
            "total_reports": total,
            "accepted_reports": accepted,
            "total_earned": earned,
        }


class CommentRepository(BaseRepository[Comment]):
    """
    Repository for Comment model database operations
    """
    model = Comment

    @classmethod
    async def get_by_report(
        cls,
        session: AsyncSession,
        report_id: UUID,
        include_internal: bool = False,
    ) -> Sequence[Comment]:
        """
        Get comments for a report
        """
        query = select(Comment).where(Comment.report_id == report_id)

        if not include_internal:
            query = query.where(Comment.is_internal == False)

        result = await session.execute(
            query.order_by(Comment.created_at.asc())
        )
        return result.scalars().all()


class AttachmentRepository(BaseRepository[Attachment]):
    """
    Repository for Attachment model database operations
    """
    model = Attachment

    @classmethod
    async def get_by_report(
        cls,
        session: AsyncSession,
        report_id: UUID,
    ) -> Sequence[Attachment]:
        """
        Get attachments for a report
        """
        result = await session.execute(
            select(Attachment).where(Attachment.report_id == report_id
                                     ).order_by(
                                         Attachment.created_at.asc()
                                     )
        )
        return result.scalars().all()
