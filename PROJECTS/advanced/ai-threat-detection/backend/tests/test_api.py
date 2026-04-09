"""
©AngelaMos | 2026
test_api.py

Tests the FastAPI REST endpoints for health, threats, stats,
and model management using an in-memory database

Validates /health returns status, uptime, and pipeline flag.
Tests /threats CRUD: empty list returns zero total, random
UUID returns 404, seeded event is fetchable by ID with all
fields, and severity filter returns only matching items.
Tests /stats returns zeroed counts on empty window.
Tests /models/status returns detection_mode and
active_models list, and POST /models/retrain returns 202
with a 32-char job ID

Connects to:
  api/health     - liveness endpoint
  api/threats    - threat CRUD
  api/stats      - statistics endpoint
  api/models_api - model status and retrain
"""

import uuid
from datetime import datetime, UTC

import pytest

from app.models.threat_event import ThreatEvent


@pytest.mark.asyncio
async def test_health_returns_200(db_client) -> None:
    """
    Health endpoint returns 200 with status, uptime, and pipeline flag.
    """
    response = await db_client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert isinstance(data["uptime_seconds"], int | float)
    assert isinstance(data["pipeline_running"], bool)


@pytest.mark.asyncio
async def test_list_threats_empty(db_client) -> None:
    """
    GET /threats on an empty database returns zero items.
    """
    response = await db_client.get("/threats")

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 0
    assert data["limit"] == 50
    assert data["offset"] == 0
    assert data["items"] == []


@pytest.mark.asyncio
async def test_get_threat_not_found(db_client) -> None:
    """
    GET /threats/{random_id} returns 404 when the event does not exist.
    """
    fake_id = uuid.uuid4()
    response = await db_client.get(f"/threats/{fake_id}")

    assert response.status_code == 404
    assert response.json()["detail"] == "Threat event not found"


@pytest.mark.asyncio
async def test_get_threat_by_id(db_session, db_client) -> None:
    """
    Seed a threat event, then fetch it by ID.
    """
    event_id = uuid.uuid4()
    event = ThreatEvent(
        id=event_id,
        created_at=datetime.now(UTC),
        source_ip="10.0.0.1",
        request_method="GET",
        request_path="/admin",
        status_code=200,
        response_size=512,
        user_agent="TestBot/1.0",
        threat_score=0.85,
        severity="HIGH",
        component_scores={"SQL_INJECTION": 0.85},
        feature_vector=[0.0] * 35,
        matched_rules=["SQL_INJECTION"],
    )
    db_session.add(event)
    await db_session.commit()

    response = await db_client.get(f"/threats/{event_id}")

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(event_id)
    assert data["source_ip"] == "10.0.0.1"
    assert data["threat_score"] == 0.85
    assert data["severity"] == "HIGH"
    assert data["matched_rules"] == ["SQL_INJECTION"]
    assert data["geo"]["country"] is None


@pytest.mark.asyncio
async def test_list_threats_severity_filter(db_session, db_client) -> None:
    """
    Seed threats with different severities and filter by HIGH.
    """
    now = datetime.now(UTC)
    for severity, score in [("HIGH", 0.9), ("MEDIUM", 0.6), ("LOW", 0.3)]:
        event = ThreatEvent(
            id=uuid.uuid4(),
            created_at=now,
            source_ip="192.168.1.1",
            request_method="GET",
            request_path="/test",
            status_code=200,
            response_size=100,
            user_agent="Mozilla/5.0",
            threat_score=score,
            severity=severity,
            component_scores={},
            feature_vector=[0.0] * 35,
        )
        db_session.add(event)
    await db_session.commit()

    response = await db_client.get("/threats", params={"severity": "HIGH"})

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["severity"] == "HIGH"


@pytest.mark.asyncio
async def test_stats_empty_window(db_client) -> None:
    """
    GET /stats on an empty database returns zero counts.
    """
    response = await db_client.get("/stats")

    assert response.status_code == 200
    data = response.json()
    assert data["time_range"] == "24h"
    assert data["threats_stored"] == 0
    assert data["threats_detected"] == 0
    assert data["severity_breakdown"]["high"] == 0
    assert data["severity_breakdown"]["medium"] == 0
    assert data["severity_breakdown"]["low"] == 0
    assert data["top_source_ips"] == []
    assert data["top_attacked_paths"] == []


@pytest.mark.asyncio
async def test_model_status(db_client) -> None:
    """
    GET /models/status returns detection mode and active model list.
    """
    response = await db_client.get("/models/status")

    assert response.status_code == 200
    data = response.json()
    assert "detection_mode" in data
    assert "active_models" in data
    assert isinstance(data["active_models"], list)


@pytest.mark.asyncio
async def test_retrain_returns_202(db_client) -> None:
    """
    POST /models/retrain returns 202 Accepted with a job ID.
    """
    response = await db_client.post("/models/retrain")

    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "accepted"
    assert len(data["job_id"]) == 32
