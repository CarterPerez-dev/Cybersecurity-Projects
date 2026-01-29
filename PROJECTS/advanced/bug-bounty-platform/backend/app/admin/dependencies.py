"""
ⒸAngelaMos | 2026
dependencies.py
"""

from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db_session
from .service import AdminService


async def get_admin_service(
    session: Annotated[AsyncSession,
                       Depends(get_db_session)],
) -> AdminService:
    """
    Dependency for AdminService
    """
    return AdminService(session)


AdminServiceDep = Annotated[AdminService, Depends(get_admin_service)]
