"""
ⒸAngelaMos | 2025
dependencies.py
"""

from typing import Annotated

from fastapi import Depends

from core.dependencies import DBSession
from .service import UserService


def get_user_service(db: DBSession) -> UserService:
    """
    Dependency to inject UserService instance
    """
    return UserService(db)


UserServiceDep = Annotated[UserService, Depends(get_user_service)]
