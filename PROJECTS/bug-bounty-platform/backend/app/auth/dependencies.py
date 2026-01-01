"""
ⒸAngelaMos | 2025
dependencies.py
"""

from typing import Annotated

from fastapi import Depends

from core.dependencies import DBSession
from .service import AuthService


def get_auth_service(db: DBSession) -> AuthService:
    """
    Dependency to inject AuthService instance
    """
    return AuthService(db)


AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]
