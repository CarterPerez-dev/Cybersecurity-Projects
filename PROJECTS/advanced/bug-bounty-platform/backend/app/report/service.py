"""
ⒸAngelaMos | 2025
service.py
"""

from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from config import ReportStatus
from core.exceptions import (
    CannotSubmitToOwnProgram,
    NotProgramOwner,
    NotReportOwner,
    ProgramNotActive,
    ProgramNotFound,
    ReportNotFound,
)
from program.repository import ProgramRepository
from user.User import User
from .schemas import (
    AttachmentResponse,
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
from .repository import (
    CommentRepository,
    ReportRepository,
)


class ReportService:
    """
    Business logic for report operations
    """
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def submit_report(
        self,
        user: User,
        report_data: ReportCreate,
    ) -> ReportResponse:
        """
        Submit a new vulnerability report
        """
        program = await ProgramRepository.get_by_id(
            self.session,
            report_data.program_id
        )
        if not program:
            raise ProgramNotFound(str(report_data.program_id))

        if not program.is_active:
            raise ProgramNotActive()

        if program.company_id == user.id:
            raise CannotSubmitToOwnProgram()

        report = await ReportRepository.create(
            self.session,
            program_id = report_data.program_id,
            researcher_id = user.id,
            title = report_data.title,
            description = report_data.description,
            steps_to_reproduce = report_data.steps_to_reproduce,
            impact = report_data.impact,
            severity_submitted = report_data.severity_submitted,
        )
        return ReportResponse.model_validate(report)

    async def get_report(
        self,
        user: User,
        report_id: UUID,
    ) -> ReportDetailResponse:
        """
        Get report by ID with details
        """
        report = await ReportRepository.get_by_id_with_details(
            self.session,
            report_id
        )
        if not report:
            raise ReportNotFound(str(report_id))

        program = await ProgramRepository.get_by_id(
            self.session,
            report.program_id
        )

        is_researcher = report.researcher_id == user.id
        is_program_owner = program and program.company_id == user.id

        if not is_researcher and not is_program_owner:
            raise ReportNotFound(str(report_id))

        comments = report.comments
        if is_researcher and not is_program_owner:
            comments = [c for c in comments if not c.is_internal]

        return ReportDetailResponse(
            id = report.id,
            created_at = report.created_at,
            updated_at = report.updated_at,
            program_id = report.program_id,
            researcher_id = report.researcher_id,
            title = report.title,
            description = report.description,
            steps_to_reproduce = report.steps_to_reproduce,
            impact = report.impact,
            severity_submitted = report.severity_submitted,
            severity_final = report.severity_final,
            status = report.status,
            cvss_score = report.cvss_score,
            cwe_id = report.cwe_id,
            bounty_amount = report.bounty_amount,
            duplicate_of_id = report.duplicate_of_id,
            triaged_at = report.triaged_at,
            resolved_at = report.resolved_at,
            disclosed_at = report.disclosed_at,
            comments = [
                CommentResponse.model_validate(c) for c in comments
            ],
            attachments = [
                AttachmentResponse.model_validate(a)
                for a in report.attachments
            ],
        )

    async def list_my_reports(
        self,
        user: User,
        page: int,
        size: int,
    ) -> ReportListResponse:
        """
        List reports submitted by current user
        """
        skip = (page - 1) * size
        reports = await ReportRepository.get_by_researcher(
            self.session,
            researcher_id = user.id,
            skip = skip,
            limit = size,
        )
        total = await ReportRepository.count_by_researcher(
            self.session,
            user.id
        )
        return ReportListResponse(
            items = [ReportResponse.model_validate(r) for r in reports],
            total = total,
            page = page,
            size = size,
        )

    async def list_program_reports(
        self,
        user: User,
        program_id: UUID,
        page: int,
        size: int,
        status_filter: ReportStatus | None = None,
    ) -> ReportListResponse:
        """
        List reports for a program (program owner only)
        """
        program = await ProgramRepository.get_by_id(
            self.session,
            program_id
        )
        if not program:
            raise ProgramNotFound(str(program_id))

        if program.company_id != user.id:
            raise NotProgramOwner()

        skip = (page - 1) * size
        reports = await ReportRepository.get_by_program(
            self.session,
            program_id = program_id,
            skip = skip,
            limit = size,
            status_filter = status_filter,
        )
        total = await ReportRepository.count_by_program(
            self.session,
            program_id,
            status_filter
        )
        return ReportListResponse(
            items = [ReportResponse.model_validate(r) for r in reports],
            total = total,
            page = page,
            size = size,
        )

    async def list_inbox(
        self,
        user: User,
        page: int,
        size: int,
    ) -> ReportListResponse:
        """
        List all reports across user's programs
        """
        skip = (page - 1) * size
        reports = await ReportRepository.get_inbox_for_company(
            self.session,
            company_id = user.id,
            skip = skip,
            limit = size,
        )
        total = await ReportRepository.count_inbox_for_company(
            self.session,
            user.id
        )
        return ReportListResponse(
            items = [ReportResponse.model_validate(r) for r in reports],
            total = total,
            page = page,
            size = size,
        )

    async def update_report(
        self,
        user: User,
        report_id: UUID,
        report_data: ReportUpdate,
    ) -> ReportResponse:
        """
        Update report (researcher only, only if still open)
        """
        report = await ReportRepository.get_by_id(self.session, report_id)
        if not report:
            raise ReportNotFound(str(report_id))

        if report.researcher_id != user.id:
            raise NotReportOwner()

        if not report.is_open:
            raise ReportNotFound(str(report_id))

        update_dict = report_data.model_dump(exclude_unset = True)
        updated = await ReportRepository.update(
            self.session,
            report,
            **update_dict,
        )
        return ReportResponse.model_validate(updated)

    async def triage_report(
        self,
        user: User,
        report_id: UUID,
        triage_data: ReportTriageUpdate,
    ) -> ReportResponse:
        """
        Triage a report (program owner only)
        """
        report = await ReportRepository.get_by_id(self.session, report_id)
        if not report:
            raise ReportNotFound(str(report_id))

        program = await ProgramRepository.get_by_id(
            self.session,
            report.program_id
        )
        if not program or program.company_id != user.id:
            raise NotProgramOwner()

        update_dict = triage_data.model_dump(exclude_unset = True)

        if "status" in update_dict:
            new_status = update_dict["status"]
            if new_status == ReportStatus.TRIAGING and report.triaged_at is None:
                report.mark_triaging()
            elif new_status == ReportStatus.RESOLVED:
                report.mark_resolved()
            elif new_status == ReportStatus.DISCLOSED:
                report.mark_disclosed()

        updated = await ReportRepository.update(
            self.session,
            report,
            **update_dict,
        )
        return ReportResponse.model_validate(updated)

    async def add_comment(
        self,
        user: User,
        report_id: UUID,
        comment_data: CommentCreate,
    ) -> CommentResponse:
        """
        Add comment to a report
        """
        report = await ReportRepository.get_by_id(self.session, report_id)
        if not report:
            raise ReportNotFound(str(report_id))

        program = await ProgramRepository.get_by_id(
            self.session,
            report.program_id
        )

        is_researcher = report.researcher_id == user.id
        is_program_owner = program and program.company_id == user.id

        if not is_researcher and not is_program_owner:
            raise ReportNotFound(str(report_id))

        if comment_data.is_internal and not is_program_owner:
            comment_data.is_internal = False

        comment = await CommentRepository.create(
            self.session,
            report_id = report_id,
            author_id = user.id,
            content = comment_data.content,
            is_internal = comment_data.is_internal,
        )
        return CommentResponse.model_validate(comment)

    async def list_comments(
        self,
        user: User,
        report_id: UUID,
    ) -> list[CommentResponse]:
        """
        List comments for a report
        """
        report = await ReportRepository.get_by_id(self.session, report_id)
        if not report:
            raise ReportNotFound(str(report_id))

        program = await ProgramRepository.get_by_id(
            self.session,
            report.program_id
        )

        is_researcher = report.researcher_id == user.id
        is_program_owner = bool(program and program.company_id == user.id)

        if not is_researcher and not is_program_owner:
            raise ReportNotFound(str(report_id))

        include_internal = is_program_owner
        comments = await CommentRepository.get_by_report(
            self.session,
            report_id,
            include_internal = include_internal,
        )
        return [CommentResponse.model_validate(c) for c in comments]

    async def get_my_stats(
        self,
        user: User,
    ) -> ReportStatsResponse:
        """
        Get current user's report statistics
        """
        stats = await ReportRepository.get_researcher_stats(
            self.session,
            user.id
        )
        return ReportStatsResponse(
            total_reports = stats["total_reports"],
            accepted_reports = stats["accepted_reports"],
            total_earned = stats["total_earned"],
            reputation_score = user.reputation_score,
        )
