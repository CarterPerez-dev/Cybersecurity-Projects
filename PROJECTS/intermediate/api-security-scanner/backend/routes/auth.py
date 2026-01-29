"""
©AngelaMos | 2025
Authentication routes
"""

from fastapi import (
    APIRouter,
    Depends,
    Request,
    status,
)
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from config import settings
from core.database import get_db
from schemas.user_schemas import (
    TokenResponse,
    UserCreate,
    UserLogin,
    UserResponse,
)
from services.auth_service import AuthService


router = APIRouter(prefix="/auth", tags=["authentication"])
limiter = Limiter(key_func=get_remote_address)


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit(settings.API_RATE_LIMIT_REGISTER)
async def register(
    request: Request,
    user_data: UserCreate,
    db: Session = Depends(get_db),
) -> UserResponse:
    """
    Register a new user account
    """
    return AuthService.register_user(db, user_data)


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
)
@limiter.limit(settings.API_RATE_LIMIT_LOGIN)
async def login(
    request: Request,
    login_data: UserLogin,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """
    Authenticate user and receive JWT token
    """
    return AuthService.login_user(db, login_data)
