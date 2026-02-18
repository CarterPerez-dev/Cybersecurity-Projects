"""
©AngelaMos | 2026
threat_service.py
"""

import uuid
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.ingestion.pipeline import ScoredRequest
from app.models.threat_event import ThreatEvent
from app.schemas.threats import (
    GeoInfo,
    ThreatEventResponse,
    ThreatListResponse,
)


def _to_response(event: ThreatEvent) -> ThreatEventResponse:
    """
    Convert a ThreatEvent DB model to an API response schema.
    """
    return ThreatEventResponse(
        id=event.id,
        created_at=event.created_at,
        source_ip=event.source_ip,
        request_method=event.request_method,
        request_path=event.request_path,
        status_code=event.status_code,
        response_size=event.response_size,
        user_agent=event.user_agent,
        threat_score=event.threat_score,
        severity=event.severity,  # type: ignore[arg-type]
        component_scores=event.component_scores,
        geo=GeoInfo(
            country=event.geo_country,
            city=event.geo_city,
            lat=event.geo_lat,
            lon=event.geo_lon,
        ),
        matched_rules=event.matched_rules,
        model_version=event.model_version,
        reviewed=event.reviewed,
        review_label=event.review_label,
    )


async def get_threats(
    session: AsyncSession,
    limit: int = 50,
    offset: int = 0,
    severity: str | None = None,
    source_ip: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> ThreatListResponse:
    """
    Query threat events with optional filters, returning a paginated response.
    """
    query = select(ThreatEvent)
    count_query = select(func.count()).select_from(ThreatEvent)

    if severity:
        query = query.where(ThreatEvent.severity == severity.upper())  # type: ignore[arg-type]
        count_query = count_query.where(ThreatEvent.severity == severity.upper())  # type: ignore[arg-type]
    if source_ip:
        query = query.where(ThreatEvent.source_ip == source_ip)  # type: ignore[arg-type]
        count_query = count_query.where(ThreatEvent.source_ip == source_ip)  # type: ignore[arg-type]
    if since:
        query = query.where(ThreatEvent.created_at >= since)  # type: ignore[arg-type]
        count_query = count_query.where(ThreatEvent.created_at >= since)  # type: ignore[arg-type]
    if until:
        query = query.where(ThreatEvent.created_at <= until)  # type: ignore[arg-type]
        count_query = count_query.where(ThreatEvent.created_at <= until)  # type: ignore[arg-type]

    query = query.order_by(ThreatEvent.created_at.desc())  # type: ignore[attr-defined]
    query = query.offset(offset).limit(limit)

    total = (await session.execute(count_query)).scalar_one()
    rows = (await session.execute(query)).scalars().all()

    return ThreatListResponse(
        total=total,
        limit=limit,
        offset=offset,
        items=[_to_response(row) for row in rows],
    )


async def get_threat_by_id(
    session: AsyncSession,
    threat_id: uuid.UUID,
) -> ThreatEventResponse | None:
    """
    Fetch a single threat event by its UUID.
    """
    result = await session.get(ThreatEvent, threat_id)
    if result is None:
        return None
    return _to_response(result)


async def create_threat_event(
    session: AsyncSession,
    scored: ScoredRequest,
) -> ThreatEvent:
    """
    Persist a scored request as a threat event in the database.
    """
    event = ThreatEvent(
        source_ip=scored.entry.ip,
        request_method=scored.entry.method,
        request_path=scored.entry.path,
        status_code=scored.entry.status_code,
        response_size=scored.entry.response_size,
        user_agent=scored.entry.user_agent,
        threat_score=scored.rule_result.threat_score,
        severity=scored.rule_result.severity,
        component_scores=scored.rule_result.component_scores,
        geo_country=scored.geo.country if scored.geo else None,
        geo_city=scored.geo.city if scored.geo else None,
        geo_lat=scored.geo.lat if scored.geo else None,
        geo_lon=scored.geo.lon if scored.geo else None,
        feature_vector=scored.feature_vector,
        matched_rules=scored.rule_result.matched_rules or None,
        model_version="rules-v1",
    )
    session.add(event)
    await session.flush()
    return event
