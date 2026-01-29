"""
ⒸAngelaMos | 2026
repository.py
"""

from typing import Any
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from config import ProgramStatus, ReportStatus, UserRole
from program.Program import Program
from report.Report import Report
from user.User import User


class AdminRepository:
    """
    Repository for admin-specific database operations
    """
    @classmethod
    async def get_all_programs(
        cls,
        session: AsyncSession,
        skip: int = 0,
        limit: int = 20,
        status_filter: ProgramStatus | None = None,
    ) -> Sequence[tuple[Program,
                        User,
                        int]]:
        """
        Get all programs with company info and report count
        """
        report_count_subq = (
            select(
                Report.program_id,
                func.count(Report.id).label("report_count")
            ).group_by(Report.program_id).subquery()
        )

        query = (
            select(
                Program,
                User,
                func.coalesce(report_count_subq.c.report_count,
                              0).label("report_count")
            ).join(User,
                   Program.company_id == User.id).outerjoin(
                       report_count_subq,
                       Program.id == report_count_subq.c.program_id
                   )
        )

        if status_filter:
            query = query.where(Program.status == status_filter)

        result = await session.execute(
            query.order_by(Program.created_at.desc()
                           ).offset(skip).limit(limit)
        )
        return [tuple(row) for row in result.all()]

    @classmethod
    async def count_all_programs(
        cls,
        session: AsyncSession,
        status_filter: ProgramStatus | None = None,
    ) -> int:
        """
        Count all programs
        """
        query = select(func.count()).select_from(Program)

        if status_filter:
            query = query.where(Program.status == status_filter)

        result = await session.execute(query)
        return result.scalar_one()

    @classmethod
    async def get_program_by_id(
        cls,
        session: AsyncSession,
        program_id: UUID,
    ) -> Program | None:
        """
        Get program by ID for admin operations
        """
        return await session.get(Program, program_id)

    @classmethod
    async def get_all_reports(
        cls,
        session: AsyncSession,
        skip: int = 0,
        limit: int = 20,
        status_filter: ReportStatus | None = None,
        severity_filter: str | None = None,
    ) -> Sequence[tuple[Report,
                        Program,
                        User]]:
        """
        Get all reports with program and researcher info
        """
        query = (
            select(Report,
                   Program,
                   User).join(Program,
                              Report.program_id == Program.id).join(
                                  User,
                                  Report.researcher_id == User.id
                              )
        )

        if status_filter:
            query = query.where(Report.status == status_filter)

        if severity_filter:
            query = query.where(
                Report.severity_submitted == severity_filter
            )

        result = await session.execute(
            query.order_by(Report.created_at.desc()
                           ).offset(skip).limit(limit)
        )
        return [tuple(row) for row in result.all()]

    @classmethod
    async def count_all_reports(
        cls,
        session: AsyncSession,
        status_filter: ReportStatus | None = None,
        severity_filter: str | None = None,
    ) -> int:
        """
        Count all reports
        """
        query = select(func.count()).select_from(Report)

        if status_filter:
            query = query.where(Report.status == status_filter)

        if severity_filter:
            query = query.where(
                Report.severity_submitted == severity_filter
            )

        result = await session.execute(query)
        return result.scalar_one()

    @classmethod
    async def get_report_by_id(
        cls,
        session: AsyncSession,
        report_id: UUID,
    ) -> Report | None:
        """
        Get report by ID for admin operations
        """
        return await session.get(Report, report_id)

    @classmethod
    async def get_all_users_with_stats(
        cls,
        session: AsyncSession,
        skip: int = 0,
        limit: int = 20,
        role_filter: UserRole | None = None,
    ) -> Sequence[tuple[User,
                        int,
                        int]]:
        """
        Get all users with program and report counts
        """
        program_count_subq = (
            select(
                Program.company_id,
                func.count(Program.id).label("program_count")
            ).group_by(Program.company_id).subquery()
        )

        report_count_subq = (
            select(
                Report.researcher_id,
                func.count(Report.id).label("report_count")
            ).group_by(Report.researcher_id).subquery()
        )

        query = (
            select(
                User,
                func.coalesce(program_count_subq.c.program_count,
                              0).label("program_count"),
                func.coalesce(report_count_subq.c.report_count,
                              0).label("report_count")
            ).outerjoin(
                program_count_subq,
                User.id == program_count_subq.c.company_id
            ).outerjoin(
                report_count_subq,
                User.id == report_count_subq.c.researcher_id
            )
        )

        if role_filter:
            query = query.where(User.role == role_filter)

        result = await session.execute(
            query.order_by(User.created_at.desc()
                           ).offset(skip).limit(limit)
        )
        return [tuple(row) for row in result.all()]

    @classmethod
    async def count_all_users(
        cls,
        session: AsyncSession,
        role_filter: UserRole | None = None,
    ) -> int:
        """
        Count all users
        """
        query = select(func.count()).select_from(User)

        if role_filter:
            query = query.where(User.role == role_filter)

        result = await session.execute(query)
        return result.scalar_one()

    @classmethod
    async def get_platform_stats(
        cls,
        session: AsyncSession,
    ) -> dict[str,
              Any]:
        """
        Get platform-wide statistics
        """
        now = datetime.now(UTC)
        month_ago = now - timedelta(days = 30)

        total_users = await session.execute(
            select(func.count()).select_from(User)
        )

        users_by_role = await session.execute(
            select(User.role,
                   func.count()).group_by(User.role)
        )
        role_counts = {
            str(role): count
            for role, count in users_by_role.all()
        }

        total_programs = await session.execute(
            select(func.count()).select_from(Program)
        )

        active_programs = await session.execute(
            select(func.count()).select_from(Program).where(
                Program.status == ProgramStatus.ACTIVE
            )
        )

        total_reports = await session.execute(
            select(func.count()).select_from(Report)
        )

        reports_by_status = await session.execute(
            select(Report.status,
                   func.count()).group_by(Report.status)
        )
        status_counts = {
            str(status): count
            for status, count in reports_by_status.all()
        }

        total_bounties = await session.execute(
            select(func.coalesce(func.sum(Report.bounty_amount),
                                 0)).where(
                                     Report.bounty_amount.isnot(None)
                                 )
        )

        reports_this_month = await session.execute(
            select(func.count()).select_from(Report).where(
                Report.created_at >= month_ago
            )
        )

        new_users_this_month = await session.execute(
            select(func.count()
                   ).select_from(User).where(User.created_at >= month_ago)
        )

        return {
            "total_users": total_users.scalar_one(),
            "total_researchers": role_counts.get("user",
                                                 0),
            "total_companies": role_counts.get("company",
                                               0),
            "total_programs": total_programs.scalar_one(),
            "active_programs": active_programs.scalar_one(),
            "total_reports": total_reports.scalar_one(),
            "reports_by_status": status_counts,
            "total_bounties_paid": total_bounties.scalar_one(),
            "reports_this_month": reports_this_month.scalar_one(),
            "new_users_this_month": new_users_this_month.scalar_one(),
        }
