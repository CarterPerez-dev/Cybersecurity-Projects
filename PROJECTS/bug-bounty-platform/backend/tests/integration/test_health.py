"""
©AngelaMos | 2025
test_health.py
"""

import pytest
from httpx import AsyncClient


URL_HEALTH = "/health"
URL_HEALTH_DETAILED = "/health/detailed"


@pytest.mark.asyncio
async def test_health_basic(client: AsyncClient):
    """
    Basic health check returns 200 with healthy status
    """
    response = await client.get(URL_HEALTH)

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "environment" in data
    assert "version" in data


@pytest.mark.asyncio
async def test_health_detailed(client: AsyncClient):
    """
    Detailed health check includes database status
    """
    response = await client.get(URL_HEALTH_DETAILED)

    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["healthy", "degraded"]
    assert "database" in data
    assert "environment" in data
    assert "version" in data
