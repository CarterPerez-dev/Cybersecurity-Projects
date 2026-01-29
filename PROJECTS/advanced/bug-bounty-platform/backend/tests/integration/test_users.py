"""
©AngelaMos | 2025
test_users.py
"""

import pytest
from httpx import AsyncClient

from user.User import User


URL_USERS = "/v1/users"
URL_ADMIN_USERS = "/v1/admin/users"
URL_USER_ME = "/v1/users/me"


def url_user_by_id(user_id: str) -> str:
    return f"{URL_USERS}/{user_id}"


def url_admin_user_by_id(user_id: str) -> str:
    return f"{URL_ADMIN_USERS}/{user_id}"


@pytest.mark.asyncio
async def test_create_user(client: AsyncClient):
    """
    User registration creates new user
    """
    response = await client.post(
        URL_USERS,
        json = {
            "email": "newuser@test.com",
            "password": "ValidPass123",
            "full_name": "New User",
        },
    )

    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "newuser@test.com"
    assert data["full_name"] == "New User"
    assert "id" in data
    assert "hashed_password" not in data


@pytest.mark.asyncio
async def test_create_user_duplicate_email(
    client: AsyncClient,
    test_user: User
):
    """
    Duplicate email returns 409 conflict
    """
    response = await client.post(
        URL_USERS,
        json = {
            "email": test_user.email,
            "password": "ValidPass123",
        },
    )

    assert response.status_code == 409


@pytest.mark.asyncio
async def test_create_user_weak_password(client: AsyncClient):
    """
    Weak password (no uppercase/digit) returns 422
    """
    response = await client.post(
        URL_USERS,
        json = {
            "email": "weakpass@test.com",
            "password": "weakpassword",
        },
    )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_get_user_by_id(
    client: AsyncClient,
    test_user: User,
    auth_headers: dict[str,
                       str],
):
    """
    Get user by ID returns user data
    """
    response = await client.get(
        url_user_by_id(str(test_user.id)),
        headers = auth_headers,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["email"] == test_user.email
    assert data["id"] == str(test_user.id)


@pytest.mark.asyncio
async def test_get_user_unauthenticated(
    client: AsyncClient,
    test_user: User
):
    """
    Get user without auth returns 401
    """
    response = await client.get(url_user_by_id(str(test_user.id)))

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_get_user_not_found(
    client: AsyncClient,
    auth_headers: dict[str,
                       str],
):
    """
    Get non existent user returns 404
    """
    fake_id = "00000000-0000-0000-0000-000000000000"
    response = await client.get(
        url_user_by_id(fake_id),
        headers = auth_headers,
    )

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_update_current_user(
    client: AsyncClient,
    test_user: User,
    auth_headers: dict[str,
                       str],
):
    """
    Update current user profile
    """
    response = await client.patch(
        URL_USER_ME,
        headers = auth_headers,
        json = {"full_name": "Updated Name"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["full_name"] == "Updated Name"


@pytest.mark.asyncio
async def test_update_user_clear_field(
    client: AsyncClient,
    test_user: User,
    auth_headers: dict[str,
                       str],
):
    """
    Setting field to null clears it
    """
    response = await client.patch(
        URL_USER_ME,
        headers = auth_headers,
        json = {"full_name": None},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["full_name"] is None


@pytest.mark.asyncio
async def test_list_users_admin_only(
    client: AsyncClient,
    test_user: User,
    auth_headers: dict[str,
                       str],
):
    """
    Non admin cannot list users (403).
    """
    response = await client.get(
        URL_ADMIN_USERS,
        headers = auth_headers,
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_list_users_as_admin(
    client: AsyncClient,
    admin_user: User,
    admin_auth_headers: dict[str,
                             str],
):
    """
    Admin can list users with pagination
    """
    response = await client.get(
        URL_ADMIN_USERS,
        headers = admin_auth_headers,
    )

    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data
    assert "page" in data
    assert "size" in data
    assert isinstance(data["items"], list)


@pytest.mark.asyncio
async def test_list_users_pagination(
    client: AsyncClient,
    admin_user: User,
    admin_auth_headers: dict[str,
                             str],
):
    """
    Pagination params work correctly
    """
    response = await client.get(
        URL_ADMIN_USERS,
        headers = admin_auth_headers,
        params = {
            "page": 1,
            "size": 5
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["page"] == 1
    assert data["size"] == 5
