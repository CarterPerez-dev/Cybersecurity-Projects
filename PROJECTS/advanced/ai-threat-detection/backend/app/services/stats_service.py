"""
©AngelaMos | 2026
stats_service.py
"""

from datetime import datetime, timedelta, UTC

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat_event import ThreatEvent
from app.schemas.stats import (
    IPStatEntry,
    PathStatEntry,
    SeverityBreakdown,
    StatsResponse,
)

_RANGE_MAP: dict[str, timedelta] = {
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}


async def get_stats(
    session: AsyncSession,
    time_range: str = "24h",
) -> StatsResponse:
    """
    Compute aggregate threat statistics for a given time window.
    """
    delta = _RANGE_MAP.get(time_range, timedelta(hours=24))
    cutoff = datetime.now(UTC) - delta

    base = select(ThreatEvent).where(ThreatEvent.created_at >= cutoff)  # type: ignore[arg-type]

    total_q = select(func.count()).select_from(base.subquery())
    total = (await session.execute(total_q)).scalar_one()

    sev_q = (
        select(ThreatEvent.severity, func.count())  # type: ignore[call-overload]
        .where(ThreatEvent.created_at >= cutoff)
        .group_by(ThreatEvent.severity)
    )
    sev_rows = (await session.execute(sev_q)).all()
    sev_map = {row[0]: row[1] for row in sev_rows}

    threats_detected = sev_map.get("HIGH", 0) + sev_map.get("MEDIUM", 0)

    ip_q = (
        select(ThreatEvent.source_ip, func.count().label("cnt"))  # type: ignore[call-overload]
        .where(ThreatEvent.created_at >= cutoff)
        .group_by(ThreatEvent.source_ip)
        .order_by(func.count().desc())
        .limit(10)
    )
    ip_rows = (await session.execute(ip_q)).all()

    path_q = (
        select(ThreatEvent.request_path, func.count().label("cnt"))  # type: ignore[call-overload]
        .where(ThreatEvent.created_at >= cutoff)
        .group_by(ThreatEvent.request_path)
        .order_by(func.count().desc())
        .limit(10)
    )
    path_rows = (await session.execute(path_q)).all()

    return StatsResponse(
        time_range=time_range,
        total_requests=total,
        threats_detected=threats_detected,
        severity_breakdown=SeverityBreakdown(
            high=sev_map.get("HIGH", 0),
            medium=sev_map.get("MEDIUM", 0),
            low=sev_map.get("LOW", 0),
        ),
        top_source_ips=[IPStatEntry(source_ip=row[0], count=row[1]) for row in ip_rows],
        top_attacked_paths=[PathStatEntry(path=row[0], count=row[1]) for row in path_rows],
    )
