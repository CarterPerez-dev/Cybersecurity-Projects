"""
FastAPI dependency injection functions.
"""

from fastapi import (
    Depends,
    HTTPException,
    status,
)
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
)
from sqlalchemy.orm import Session
from .security import decode_token
from .database import get_db
from repositories.user_repository import UserRepository
from schemas.user_schemas import UserResponse


security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> UserResponse:
    """
    FastAPI dependency to extract and verify the current authenticated user
    """
    try:
        payload = decode_token(credentials.credentials)
        email: str | None = payload.get("sub")

        if email is None:
            raise HTTPException(
                status_code = status.HTTP_401_UNAUTHORIZED,
                detail = "Invalid authentication credentials",
                headers = {"WWW-Authenticate": "Bearer"},
            )

        user = UserRepository.get_by_email(db, email)

        if not user:
            raise HTTPException(
                status_code = status.HTTP_401_UNAUTHORIZED,
                detail = "User not found",
                headers = {"WWW-Authenticate": "Bearer"},
            )

        return UserResponse.model_validate(user)

    except ValueError:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "Invalid authentication credentials",
            headers = {"WWW-Authenticate": "Bearer"},
        ) from None
