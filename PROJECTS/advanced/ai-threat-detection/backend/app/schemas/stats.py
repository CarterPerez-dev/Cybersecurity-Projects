"""
©AngelaMos | 2026
stats.py
"""

from pydantic import BaseModel


class SeverityBreakdown(BaseModel):
    """
    Count of threats per severity tier.
    """

    high: int = 0
    medium: int = 0
    low: int = 0


class IPStatEntry(BaseModel):
    """
    Source IP with associated threat count.
    """

    source_ip: str
    count: int


class PathStatEntry(BaseModel):
    """
    Request path with associated threat count.
    """

    path: str
    count: int


class StatsResponse(BaseModel):
    """
    Aggregate threat statistics for a given time range.
    """

    time_range: str
    total_requests: int
    threats_detected: int
    severity_breakdown: SeverityBreakdown
    top_source_ips: list[IPStatEntry]
    top_attacked_paths: list[PathStatEntry]
