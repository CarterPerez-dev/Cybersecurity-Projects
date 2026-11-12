"""
©AngelaMos | 2026
dashboard.py

Pydantic schemas for dashboard query endpoints

Minimal schemas for timeline and top-sources endpoints carrying only
the window and limit parameters with sensible defaults from config.

Key exports:
  TimelineParams - hours window and bucket size for timeline aggregation
  TopSourcesParams - result count limit for top source IPs

Connects to:
  config.py - reads TIMELINE_DEFAULT_HOURS, TIMELINE_BUCKET_MINUTES, TOP_SOURCES_LIMIT
  routes/dashboard.py - passed to S()
"""

from pydantic import BaseModel, Field

from app.config import settings


class TimelineParams(BaseModel):
    """
    Query params for event timeline aggregation
    """
    hours: int = Field(
        default = settings.TIMELINE_DEFAULT_HOURS,
        ge = 1,
    )
    bucket_minutes: int = Field(
        default = settings.TIMELINE_BUCKET_MINUTES,
        ge = 1,
    )


class TopSourcesParams(BaseModel):
    """
    Query params for top source IPs
    """
    limit: int = Field(
        default = settings.TOP_SOURCES_LIMIT,
        ge = 1,
    )
