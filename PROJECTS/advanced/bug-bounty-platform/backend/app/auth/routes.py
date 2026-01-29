"""
ⒸAngelaMos | 2025
routes.py
"""

from typing import Annotated

from fastapi import (
    APIRouter,
    Cookie,
    Depends,
    Request,
    Response,
    status,
)
from fastapi.security import (
    OAuth2PasswordRequestForm,
)

from config import settings
from core.dependencies import (
    ClientIP,
    CurrentUser,
)
from core.security import (
    clear_refresh_cookie,
    set_refresh_cookie,
)
from core.rate_limit import limiter
from core.exceptions import TokenError
from .schemas import (
    PasswordChange,
    TokenResponse,
    TokenWithUserResponse,
)
from user.schemas import UserResponse
from .dependencies import AuthServiceDep
from user.dependencies import UserServiceDep
from core.responses import AUTH_401


router = APIRouter(prefix = "/auth", tags = ["auth"])


@router.post(
    "/login",
    response_model = TokenWithUserResponse,
    responses = {**AUTH_401}
)
@limiter.limit(settings.RATE_LIMIT_AUTH)
async def login(
    request: Request,
    response: Response,
    auth_service: AuthServiceDep,
    ip: ClientIP,
    form_data: Annotated[OAuth2PasswordRequestForm,
                         Depends()],
) -> TokenWithUserResponse:
    """
    Login with email and password
    """
    result, refresh_token = await auth_service.login(
        email=form_data.username,
        password=form_data.password,
        ip_address=ip,
    )
    set_refresh_cookie(response, refresh_token)
    return result


@router.post(
    "/refresh",
    response_model = TokenResponse,
    responses = {**AUTH_401}
)
async def refresh_token(
    response: Response,
    auth_service: AuthServiceDep,
    ip: ClientIP,
    refresh_token: str | None = Cookie(None),
) -> TokenResponse:
    """
    Refresh access token
    """
    if not refresh_token:
        raise TokenError("Refresh token required")
    result, new_refresh_token = await auth_service.refresh_tokens(
        refresh_token,
        ip_address = ip
    )
    set_refresh_cookie(response, new_refresh_token)
    return result


@router.post(
    "/logout",
    status_code = status.HTTP_204_NO_CONTENT,
    responses = {**AUTH_401}
)
async def logout(
    response: Response,
    auth_service: AuthServiceDep,
    refresh_token: str | None = Cookie(None),
) -> None:
    """
    Logout current session
    """
    if not refresh_token:
        raise TokenError("Refresh token required")
    await auth_service.logout(refresh_token)
    clear_refresh_cookie(response)


@router.post("/logout-all", responses = {**AUTH_401})
async def logout_all(
    response: Response,
    auth_service: AuthServiceDep,
    current_user: CurrentUser,
) -> dict[str,
          int]:
    """
    Logout from all devices
    """
    count = await auth_service.logout_all(current_user)
    clear_refresh_cookie(response)
    return {"revoked_sessions": count}


@router.get("/me", response_model = UserResponse, responses = {**AUTH_401})
async def get_current_user(current_user: CurrentUser) -> UserResponse:
    """
    Get current authenticated user
    """
    return UserResponse.model_validate(current_user)


@router.post(
    "/change-password",
    status_code = status.HTTP_204_NO_CONTENT,
    responses = {**AUTH_401}
)
async def change_password(
    user_service: UserServiceDep,
    current_user: CurrentUser,
    data: PasswordChange,
) -> None:
    """
    Change current user password
    """
    await user_service.change_password(
        current_user,
        data.current_password,
        data.new_password,
    )
