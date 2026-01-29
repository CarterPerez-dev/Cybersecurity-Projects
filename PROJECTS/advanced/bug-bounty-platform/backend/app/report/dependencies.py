"""
ⒸAngelaMos | 2025
dependencies.py
"""

from typing import Annotated

from fastapi import Depends

from core.dependencies import DBSession
from .service import ReportService


def get_report_service(db: DBSession) -> ReportService:
    """
    Dependency to inject ReportService instance
    """
    return ReportService(db)


ReportServiceDep = Annotated[ReportService, Depends(get_report_service)]
