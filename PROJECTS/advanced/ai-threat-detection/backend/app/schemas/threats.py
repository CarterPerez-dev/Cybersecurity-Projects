"""
©AngelaMos | 2026
threats.py
"""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class GeoInfo(BaseModel):
    """
    Geographic location data from GeoIP lookup.
    """

    country: str | None = None
    city: str | None = None
    lat: float | None = None
    lon: float | None = None


class ThreatEventResponse(BaseModel):
    """
    Single threat event returned by the API.
    """

    id: uuid.UUID
    created_at: datetime
    source_ip: str
    request_method: str
    request_path: str
    status_code: int
    response_size: int
    user_agent: str
    threat_score: float
    severity: Literal["HIGH", "MEDIUM", "LOW"]
    component_scores: dict[str, float]
    geo: GeoInfo
    matched_rules: list[str] | None = None
    model_version: str | None = None
    reviewed: bool = False
    review_label: str | None = None

    model_config = {"from_attributes": True}


class ThreatListResponse(BaseModel):
    """
    Paginated list of threat events.
    """

    total: int
    limit: int
    offset: int
    items: list[ThreatEventResponse]
