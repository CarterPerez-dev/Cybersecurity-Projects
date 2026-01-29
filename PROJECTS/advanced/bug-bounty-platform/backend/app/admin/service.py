"""
ⒸAngelaMos | 2026
service.py
"""

from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from config import ProgramStatus, ReportStatus, UserRole
from core.exceptions import ResourceNotFound
from .repository import AdminRepository
from .schemas import (
    AdminProgramListResponse,
    AdminProgramResponse,
    AdminProgramUpdate,
    AdminReportListResponse,
    AdminReportResponse,
    AdminReportUpdate,
    AdminUserListResponse,
    AdminUserResponse,
    PlatformStatsResponse,
)


class AdminService:
    """
    Service for admin operations
    """
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def list_programs(
        self,
        page: int,
        size: int,
        status_filter: ProgramStatus | None = None,
    ) -> AdminProgramListResponse:
        """
        List all programs with company info
        """
        skip = (page - 1) * size

        results = await AdminRepository.get_all_programs(
            self.session,
            skip = skip,
            limit = size,
            status_filter = status_filter,
        )

        total = await AdminRepository.count_all_programs(
            self.session,
            status_filter = status_filter,
        )

        items = [
            AdminProgramResponse(
                id = program.id,
                created_at = program.created_at,
                updated_at = program.updated_at,
                company_id = program.company_id,
                company_email = company.email,
                company_name = company.company_name or company.full_name,
                name = program.name,
                slug = program.slug,
                description = program.description,
                status = program.status,
                visibility = program.visibility,
                response_sla_hours = program.response_sla_hours,
                report_count = report_count,
            ) for program, company, report_count in results
        ]

        return AdminProgramListResponse(
            items = items,
            total = total,
            page = page,
            size = size,
        )

    async def update_program(
        self,
        program_id: UUID,
        data: AdminProgramUpdate,
    ) -> AdminProgramResponse:
        """
        Update a program (admin override)
        """
        program = await AdminRepository.get_program_by_id(
            self.session,
            program_id
        )
        if not program:
            raise ResourceNotFound("Program", str(program_id))

        update_data = data.model_dump(exclude_unset = True)
        for key, value in update_data.items():
            setattr(program, key, value)

        await self.session.flush()
        await self.session.refresh(program)

        results = await AdminRepository.get_all_programs(
            self.session,
            skip = 0,
            limit = 1,
            status_filter = None
        )
        for p, company, report_count in results:
            if p.id == program_id:
                return AdminProgramResponse(
                    id = program.id,
                    created_at = program.created_at,
                    updated_at = program.updated_at,
                    company_id = program.company_id,
                    company_email = company.email,
                    company_name = company.company_name
                    or company.full_name,
                    name = program.name,
                    slug = program.slug,
                    description = program.description,
                    status = program.status,
                    visibility = program.visibility,
                    response_sla_hours = program.response_sla_hours,
                    report_count = report_count,
                )

        raise ResourceNotFound("Program", str(program_id))

    async def delete_program(self, program_id: UUID) -> None:
        """
        Delete a program (hard delete)
        """
        program = await AdminRepository.get_program_by_id(
            self.session,
            program_id
        )
        if not program:
            raise ResourceNotFound("Program", str(program_id))

        await self.session.delete(program)
        await self.session.flush()

    async def list_reports(
        self,
        page: int,
        size: int,
        status_filter: ReportStatus | None = None,
        severity_filter: str | None = None,
    ) -> AdminReportListResponse:
        """
        List all reports with program/researcher info
        """
        skip = (page - 1) * size

        results = await AdminRepository.get_all_reports(
            self.session,
            skip = skip,
            limit = size,
            status_filter = status_filter,
            severity_filter = severity_filter,
        )

        total = await AdminRepository.count_all_reports(
            self.session,
            status_filter = status_filter,
            severity_filter = severity_filter,
        )

        items = [
            AdminReportResponse(
                id = report.id,
                created_at = report.created_at,
                updated_at = report.updated_at,
                program_id = report.program_id,
                program_name = program.name,
                program_slug = program.slug,
                researcher_id = report.researcher_id,
                researcher_email = researcher.email,
                researcher_name = researcher.full_name,
                title = report.title,
                severity_submitted = report.severity_submitted,
                severity_final = report.severity_final,
                status = report.status,
                bounty_amount = report.bounty_amount,
                triaged_at = report.triaged_at,
                resolved_at = report.resolved_at,
            ) for report, program, researcher in results
        ]

        return AdminReportListResponse(
            items = items,
            total = total,
            page = page,
            size = size,
        )

    async def update_report(
        self,
        report_id: UUID,
        data: AdminReportUpdate,
    ) -> AdminReportResponse:
        """
        Update a report (admin override)
        """
        report = await AdminRepository.get_report_by_id(
            self.session,
            report_id
        )
        if not report:
            raise ResourceNotFound("Report", str(report_id))

        update_data = data.model_dump(
            exclude_unset = True,
            exclude = {"admin_notes"}
        )
        for key, value in update_data.items():
            setattr(report, key, value)

        await self.session.flush()
        await self.session.refresh(report)

        results = await AdminRepository.get_all_reports(
            self.session,
            skip = 0,
            limit = 1000
        )
        for r, program, researcher in results:
            if r.id == report_id:
                return AdminReportResponse(
                    id = report.id,
                    created_at = report.created_at,
                    updated_at = report.updated_at,
                    program_id = report.program_id,
                    program_name = program.name,
                    program_slug = program.slug,
                    researcher_id = report.researcher_id,
                    researcher_email = researcher.email,
                    researcher_name = researcher.full_name,
                    title = report.title,
                    severity_submitted = report.severity_submitted,
                    severity_final = report.severity_final,
                    status = report.status,
                    bounty_amount = report.bounty_amount,
                    triaged_at = report.triaged_at,
                    resolved_at = report.resolved_at,
                )

        raise ResourceNotFound("Report", str(report_id))

    async def list_users_with_stats(
        self,
        page: int,
        size: int,
        role_filter: UserRole | None = None,
    ) -> AdminUserListResponse:
        """
        List all users with program/report counts
        """
        skip = (page - 1) * size

        results = await AdminRepository.get_all_users_with_stats(
            self.session,
            skip = skip,
            limit = size,
            role_filter = role_filter,
        )

        total = await AdminRepository.count_all_users(
            self.session,
            role_filter = role_filter,
        )

        items = [
            AdminUserResponse(
                id = user.id,
                created_at = user.created_at,
                updated_at = user.updated_at,
                email = user.email,
                full_name = user.full_name,
                company_name = user.company_name,
                is_active = user.is_active,
                is_verified = user.is_verified,
                role = user.role,
                reputation_score = user.reputation_score,
                program_count = program_count,
                report_count = report_count,
            ) for user, program_count, report_count in results
        ]

        return AdminUserListResponse(
            items = items,
            total = total,
            page = page,
            size = size,
        )

    async def get_platform_stats(self) -> PlatformStatsResponse:
        """
        Get platform-wide statistics
        """
        stats = await AdminRepository.get_platform_stats(self.session)
        return PlatformStatsResponse(**stats)
