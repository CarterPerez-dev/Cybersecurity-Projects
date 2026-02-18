"""
©AngelaMos | 2026
threats.py
"""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_session
from app.schemas.threats import ThreatEventResponse, ThreatListResponse
from app.services import threat_service

router = APIRouter(prefix="/threats", tags=["threats"])


@router.get("", response_model=ThreatListResponse)
async def list_threats(
    session: AsyncSession = Depends(get_session),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    severity: str | None = Query(None),
    source_ip: str | None = Query(None),
    since: datetime | None = Query(None),
    until: datetime | None = Query(None),
) -> ThreatListResponse:
    """
    List threat events with optional filters and pagination.
    """
    return await threat_service.get_threats(
        session,
        limit,
        offset,
        severity,
        source_ip,
        since,
        until,
    )


@router.get("/{threat_id}", response_model=ThreatEventResponse)
async def get_threat(
    threat_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> ThreatEventResponse:
    """
    Fetch a single threat event by ID.
    """
    result = await threat_service.get_threat_by_id(session, threat_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Threat event not found")
    return result
