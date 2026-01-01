"""
ⒸAngelaMos | 2025
routes.py
"""

from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    status,
)
from fastapi.security import (
    OAuth2PasswordRequestForm,
)

from core.dependencies import CurrentUser
from .schemas import TokenWithUserResponse
from user.schemas import UserResponse
from .dependencies import AuthServiceDep
from core.responses import AUTH_401


router = APIRouter(prefix = "/auth", tags = ["auth"])


@router.post(
    "/login",
    response_model = TokenWithUserResponse,
    responses = {**AUTH_401}
)
async def login(
    auth_service: AuthServiceDep,
    form_data: Annotated[OAuth2PasswordRequestForm,
                         Depends()],
) -> TokenWithUserResponse:
    """
    Login with email and password
    """
    return await auth_service.login(
        email=form_data.username,
        password=form_data.password,
    )


@router.get("/me", response_model = UserResponse, responses = {**AUTH_401})
async def get_current_user(current_user: CurrentUser) -> UserResponse:
    """
    Get current authenticated user
    """
    return UserResponse.model_validate(current_user)


@router.post(
    "/logout",
    status_code = status.HTTP_204_NO_CONTENT,
    responses = {**AUTH_401}
)
async def logout(_: CurrentUser) -> None:
    """
    Logout current session
    """
    pass
