"""
ⒸAngelaMos | 2025
dependencies.py
"""

from typing import Annotated

from fastapi import Depends

from core.dependencies import DBSession
from .service import ProgramService


def get_program_service(db: DBSession) -> ProgramService:
    """
    Dependency to inject ProgramService instance
    """
    return ProgramService(db)


ProgramServiceDep = Annotated[ProgramService, Depends(get_program_service)]
