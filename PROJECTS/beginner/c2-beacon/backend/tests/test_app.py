"""
AngelaMos | 2026
test_app.py

Integration tests for the FastAPI HTTP endpoints

Spins up the full application using ASGITransport and verifies the
health check, root info endpoint, empty beacon list, and 404 handling
for unknown beacon IDs.

Tests:
  __main__.py - create_app, /health, /, /beacons, /beacons/{id}
"""

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from beacon.registry import BeaconRegistry
from beacon.tasking import TaskManager
from database import init_db
from ops.manager import OpsManager


@pytest.fixture
async def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AsyncClient:
    """
    Provide an async HTTP client with a test app using isolated database
    """
    test_db_path = tmp_path / "test.db"

    import config
    monkeypatch.setattr(config.settings, "DATABASE_PATH", test_db_path)
    monkeypatch.setattr(config.settings, "APP_NAME", "C2 Beacon Server")

    import database
    monkeypatch.setattr(database, "settings", config.settings)

    await init_db()

    from app.__main__ import create_app

    test_app = create_app()
    test_app.state.registry = BeaconRegistry()
    test_app.state.task_manager = TaskManager()
    test_app.state.ops_manager = OpsManager()

    transport = ASGITransport(app = test_app)
    async with AsyncClient(transport = transport, base_url = "http://test") as ac:
        yield ac


class TestHealthAndRoot:
    """
    Verify health check and root information endpoints
    """
    async def test_health_returns_200(self, client: AsyncClient) -> None:
        """
        Health endpoint responds with 200 and status healthy
        """
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

    async def test_root_returns_app_info(self, client: AsyncClient) -> None:
        """
        Root endpoint returns application name and version
        """
        response = await client.get("/")
        data = response.json()
        assert "name" in data
        assert "version" in data


class TestBeaconEndpoints:
    """
    Verify REST beacon listing endpoints
    """
    async def test_list_beacons_empty(self, client: AsyncClient) -> None:
        """
        Beacons list returns empty array with no registered beacons
        """
        response = await client.get("/beacons")
        assert response.status_code == 200
        assert response.json() == []

    async def test_get_beacon_not_found(self, client: AsyncClient) -> None:
        """
        Non-existent beacon ID returns 404
        """
        response = await client.get("/beacons/nonexistent")
        assert response.status_code == 404
