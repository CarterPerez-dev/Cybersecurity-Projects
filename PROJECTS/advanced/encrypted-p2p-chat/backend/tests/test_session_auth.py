"""
©AngelaMos | 2026
test_session_auth.py
"""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.api.auth import router as auth_router
from app.api.encryption import router as encryption_router
from app.api.rooms import router as rooms_router
from app.core.exception_handlers import register_exception_handlers


@pytest.fixture
def app(monkeypatch) -> FastAPI:
    """
    Build a FastAPI app without DB or Redis lifespan for protected-route checks
    """
    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(auth_router)
    app.include_router(rooms_router)
    app.include_router(encryption_router)
    return app


class _StubRedis:
    """
    No-op Redis stand-in for unauthenticated tests
    """
    async def get_session_user(self, token: str) -> str | None:
        """
        Always return None to simulate an absent session
        """
        return None


@pytest.fixture(autouse = True)
def stub_redis(monkeypatch):
    """
    Replace the real Redis client used by the auth dependency
    """
    from app.core import redis_manager as redis_module

    monkeypatch.setattr(redis_module, "redis_manager", _StubRedis())


@pytest.mark.asyncio
async def test_me_requires_session(app: FastAPI) -> None:
    """
    /auth/me returns 401 with no cookie
    """
    transport = ASGITransport(app = app)
    async with AsyncClient(transport = transport, base_url = "http://test") as ac:
        resp = await ac.get("/auth/me")
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_rooms_list_requires_session(app: FastAPI) -> None:
    """
    GET /rooms returns 401 with no cookie
    """
    transport = ASGITransport(app = app)
    async with AsyncClient(transport = transport, base_url = "http://test") as ac:
        resp = await ac.get("/rooms")
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_rooms_create_requires_session(app: FastAPI) -> None:
    """
    POST /rooms returns 401 with no cookie
    """
    transport = ASGITransport(app = app)
    async with AsyncClient(transport = transport, base_url = "http://test") as ac:
        resp = await ac.post(
            "/rooms",
            json = {
                "participant_id": "00000000-0000-0000-0000-000000000000",
                "room_type": "direct",
            },
        )
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_search_users_requires_session(app: FastAPI) -> None:
    """
    POST /auth/users/search returns 401 with no cookie
    """
    transport = ASGITransport(app = app)
    async with AsyncClient(transport = transport, base_url = "http://test") as ac:
        resp = await ac.post(
            "/auth/users/search",
            json = {
                "query": "alice",
                "limit": 10
            },
        )
        assert resp.status_code == 401
