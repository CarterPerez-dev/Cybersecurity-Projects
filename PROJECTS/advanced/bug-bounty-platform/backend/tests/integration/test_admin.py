"""
©AngelaMos | 2025
test_admin.py
"""

import pytest
from httpx import AsyncClient

from user.User import User


URL_ADMIN_USERS = "/v1/admin/users"


def url_admin_user_by_id(user_id: str) -> str:
    return f"{URL_ADMIN_USERS}/{user_id}"


@pytest.mark.asyncio
async def test_admin_create_user(
    client: AsyncClient,
    admin_user: User,
    admin_auth_headers: dict[str, str],
):
    """
    Admin can create a new user
    """
    response = await client.post(
        URL_ADMIN_USERS,
        headers = admin_auth_headers,
        json = {
            "email": "adminmade@test.com",
            "password": "ValidPass123",
            "full_name": "Admin Created User",
        },
    )

    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "adminmade@test.com"
    assert data["full_name"] == "Admin Created User"
    assert "id" in data
    assert "hashed_password" not in data


@pytest.mark.asyncio
async def test_admin_create_user_non_admin_forbidden(
    client: AsyncClient,
    test_user: User,
    auth_headers: dict[str, str],
):
    """
    Non admin cannot create user via admin endpoint
    """
    response = await client.post(
        URL_ADMIN_USERS,
        headers = auth_headers,
        json = {
            "email": "shouldfail@test.com",
            "password": "ValidPass123",
        },
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_admin_create_user_duplicate_email(
    client: AsyncClient,
    admin_user: User,
    admin_auth_headers: dict[str, str],
    test_user: User,
):
    """
    Admin create with duplicate email returns 409
    """
    response = await client.post(
        URL_ADMIN_USERS,
        headers = admin_auth_headers,
        json = {
            "email": test_user.email,
            "password": "ValidPass123",
        },
    )

    assert response.status_code == 409


@pytest.mark.asyncio
async def test_admin_get_user_by_id(
    client: AsyncClient,
    admin_user: User,
    admin_auth_headers: dict[str, str],
    test_user: User,
):
    """
    Admin can get any user by ID
    """
    response = await client.get(
        url_admin_user_by_id(str(test_user.id)),
        headers = admin_auth_headers,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(test_user.id)
    assert data["email"] == test_user.email


@pytest.mark.asyncio
async def test_admin_get_user_not_found(
    client: AsyncClient,
    admin_user: User,
    admin_auth_headers: dict[str, str],
):
    """
    Admin get non existent user returns 404
    """
    fake_id = "00000000-0000-0000-0000-000000000000"
    response = await client.get(
        url_admin_user_by_id(fake_id),
        headers = admin_auth_headers,
    )

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_admin_update_user(
    client: AsyncClient,
    admin_user: User,
    admin_auth_headers: dict[str, str],
    test_user: User,
):
    """
    Admin can update any user
    """
    response = await client.patch(
        url_admin_user_by_id(str(test_user.id)),
        headers = admin_auth_headers,
        json = {"full_name": "Admin Updated Name"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["full_name"] == "Admin Updated Name"
    assert data["id"] == str(test_user.id)


@pytest.mark.asyncio
async def test_admin_update_user_not_found(
    client: AsyncClient,
    admin_user: User,
    admin_auth_headers: dict[str, str],
):
    """
    Admin update non existent user returns 404
    """
    fake_id = "00000000-0000-0000-0000-000000000000"
    response = await client.patch(
        url_admin_user_by_id(fake_id),
        headers = admin_auth_headers,
        json = {"full_name": "Should Fail"},
    )

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_admin_update_user_non_admin_forbidden(
    client: AsyncClient,
    test_user: User,
    auth_headers: dict[str, str],
):
    """
    Non admin cannot update via admin endpoint
    """
    response = await client.patch(
        url_admin_user_by_id(str(test_user.id)),
        headers = auth_headers,
        json = {"full_name": "Should Fail"},
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_admin_delete_user(
    client: AsyncClient,
    admin_user: User,
    admin_auth_headers: dict[str, str],
    db_session,
):
    """
    Admin can delete a user
    """
    from user.User import User as UserModel
    from core.security import hash_password

    user_to_delete = UserModel(
        email = "deleteme@test.com",
        hashed_password = await hash_password("TestPass123"),
        full_name = "Delete Me",
    )
    db_session.add(user_to_delete)
    await db_session.flush()
    await db_session.refresh(user_to_delete)
    user_id = str(user_to_delete.id)

    response = await client.delete(
        url_admin_user_by_id(user_id),
        headers = admin_auth_headers,
    )

    assert response.status_code == 204

    get_response = await client.get(
        url_admin_user_by_id(user_id),
        headers = admin_auth_headers,
    )
    assert get_response.status_code == 404


@pytest.mark.asyncio
async def test_admin_delete_user_not_found(
    client: AsyncClient,
    admin_user: User,
    admin_auth_headers: dict[str, str],
):
    """
    Admin delete non existent user returns 404
    """
    fake_id = "00000000-0000-0000-0000-000000000000"
    response = await client.delete(
        url_admin_user_by_id(fake_id),
        headers = admin_auth_headers,
    )

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_admin_delete_user_non_admin_forbidden(
    client: AsyncClient,
    test_user: User,
    auth_headers: dict[str, str],
):
    """
    Non admin cannot delete users
    """
    response = await client.delete(
        url_admin_user_by_id(str(test_user.id)),
        headers = auth_headers,
    )

    assert response.status_code == 403
