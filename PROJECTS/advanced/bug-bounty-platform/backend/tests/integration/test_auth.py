"""
©AngelaMos | 2025
test_auth.py
"""

import pytest
from httpx import AsyncClient

from user.User import User
from auth.RefreshToken import RefreshToken


URL_LOGIN = "/v1/auth/login"
URL_REFRESH = "/v1/auth/refresh"
URL_LOGOUT = "/v1/auth/logout"
URL_LOGOUT_ALL = "/v1/auth/logout-all"
URL_ME = "/v1/auth/me"
URL_CHANGE_PASSWORD = "/v1/auth/change-password"


@pytest.mark.asyncio
async def test_login_success(client: AsyncClient, test_user: User):
    """
    Valid credentials return access token and set refresh cookie
    """
    response = await client.post(
        URL_LOGIN,
        data = {
            "username": test_user.email,
            "password": "TestPass123",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert "user" in data
    assert data["user"]["email"] == test_user.email
    assert "refresh_token" in response.cookies


@pytest.mark.asyncio
async def test_login_invalid_password(
    client: AsyncClient,
    test_user: User
):
    """
    Wrong password returns 401
    """
    response = await client.post(
        URL_LOGIN,
        data = {
            "username": test_user.email,
            "password": "WrongPassword123",
        },
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_login_invalid_email(client: AsyncClient):
    """
    Non-existent email returns 401
    """
    response = await client.post(
        URL_LOGIN,
        data = {
            "username": "nonexistent@test.com",
            "password": "TestPass123",
        },
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_login_inactive_user(
    client: AsyncClient,
    inactive_user: User
):
    """
    Inactive user cannot login
    """
    response = await client.post(
        URL_LOGIN,
        data = {
            "username": inactive_user.email,
            "password": "TestPass123",
        },
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_refresh_token_success(
    client: AsyncClient,
    refresh_token_pair: tuple[RefreshToken,
                              str],
):
    """
    Valid refresh token returns new access token
    """
    _, raw_token = refresh_token_pair

    response = await client.post(
        URL_REFRESH,
        cookies = {"refresh_token": raw_token},
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_refresh_token_missing_returns_401(client: AsyncClient):
    """
    Missing refresh token cookie returns 401, not 422.
    """
    response = await client.post(URL_REFRESH)

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_refresh_token_expired(
    client: AsyncClient,
    expired_refresh_token_pair: tuple[RefreshToken,
                                      str],
):
    """
    Expired refresh token returns 401
    """
    _, raw_token = expired_refresh_token_pair

    response = await client.post(
        URL_REFRESH,
        cookies = {"refresh_token": raw_token},
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_refresh_token_revoked(
    client: AsyncClient,
    revoked_refresh_token_pair: tuple[RefreshToken,
                                      str],
):
    """
    Revoked refresh token returns 401.
    """
    _, raw_token = revoked_refresh_token_pair

    response = await client.post(
        URL_REFRESH,
        cookies = {"refresh_token": raw_token},
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_logout_success(
    client: AsyncClient,
    refresh_token_pair: tuple[RefreshToken,
                              str],
):
    """
    Logout revokes refresh token and clears cookie.
    """
    _, raw_token = refresh_token_pair

    response = await client.post(
        URL_LOGOUT,
        cookies = {"refresh_token": raw_token},
    )

    assert response.status_code == 204


@pytest.mark.asyncio
async def test_logout_missing_token_returns_401(client: AsyncClient):
    """
    Logout without refresh token returns 401, not 422.
    """
    response = await client.post(URL_LOGOUT)

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_logout_all(
    client: AsyncClient,
    test_user: User,
    auth_headers: dict[str,
                       str],
):
    """
    Logout all revokes all user sessions.
    """
    response = await client.post(
        URL_LOGOUT_ALL,
        headers = auth_headers,
    )

    assert response.status_code == 200
    data = response.json()
    assert "revoked_sessions" in data


@pytest.mark.asyncio
async def test_get_current_user(
    client: AsyncClient,
    test_user: User,
    auth_headers: dict[str,
                       str],
):
    """
    /me returns current authenticated user.
    """
    response = await client.get(
        URL_ME,
        headers = auth_headers,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["email"] == test_user.email
    assert data["id"] == str(test_user.id)


@pytest.mark.asyncio
async def test_get_current_user_unauthenticated(client: AsyncClient):
    """
    /me without auth returns 401.
    """
    response = await client.get(URL_ME)

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_change_password(
    client: AsyncClient,
    test_user: User,
    auth_headers: dict[str,
                       str],
):
    """
    Password change works with valid current password.
    """
    response = await client.post(
        URL_CHANGE_PASSWORD,
        headers = auth_headers,
        json = {
            "current_password": "TestPass123",
            "new_password": "NewTestPass456",
        },
    )

    assert response.status_code == 204


@pytest.mark.asyncio
async def test_change_password_wrong_current(
    client: AsyncClient,
    test_user: User,
    auth_headers: dict[str,
                       str],
):
    """
    Password change fails with wrong current password.
    """
    response = await client.post(
        URL_CHANGE_PASSWORD,
        headers = auth_headers,
        json = {
            "current_password": "WrongPassword123",
            "new_password": "NewTestPass456",
        },
    )

    assert response.status_code == 401
