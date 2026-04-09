"""
©AngelaMos | 2026
stats.py

Pydantic response models for the /stats endpoint

SeverityBreakdown holds high/medium/low threat counts.
IPStatEntry and PathStatEntry pair a source_ip or path
with a count. StatsResponse aggregates time_range,
threats_stored, threats_detected, severity_breakdown,
top_source_ips (top 10), and top_attacked_paths (top 10)

Connects to:
  api/stats              - StatsResponse as response_model
  services/stats_service - constructs StatsResponse
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
    threats_stored: int
    threats_detected: int
    severity_breakdown: SeverityBreakdown
    top_source_ips: list[IPStatEntry]
    top_attacked_paths: list[PathStatEntry]
