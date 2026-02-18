"""
©AngelaMos | 2026
stats.py
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_session
from app.schemas.stats import StatsResponse
from app.services import stats_service

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("", response_model=StatsResponse)
async def get_stats(
    session: AsyncSession = Depends(get_session),
    time_range: str = Query("24h", alias="range"),
) -> StatsResponse:
    """
    Aggregate threat statistics for a given time window.
    """
    return await stats_service.get_stats(session, time_range)
