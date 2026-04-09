"""
©AngelaMos | 2026
threat_event.py

SQLModel table for detected threat events with full
request context and ML metadata

ThreatEvent stores source_ip, request_method, request_path,
status_code, response_size, user_agent, threat_score,
severity, component_scores (JSON), geo fields (country,
city, lat, lon), feature_vector (JSON float array),
matched_rules (JSON string array), model_version,
reviewed flag, and review_label for analyst feedback.
Indexed on created_at, source_ip, severity, threat_score,
and a partial index on reviewed=FALSE for triage queries

Connects to:
  models/base             - inherits TimestampedModel
  services/threat_service - CRUD operations
  api/models_api          - training data source for
                             retrain
  core/alerts/dispatcher  - persisted on MEDIUM+ severity
"""

from sqlalchemy import (
    Column,
    Float,
    Index,
    JSON,
    SmallInteger,
    text,
)
from sqlmodel import Field

from app.models.base import TimestampedModel


class ThreatEvent(TimestampedModel, table=True):
    """
    Primary table for detected threat events.
    """

    __tablename__ = "threat_events"
    __table_args__ = (
        Index("idx_threat_events_created_at", "created_at"),
        Index("idx_threat_events_source_ip", "source_ip"),
        Index("idx_threat_events_severity", "severity"),
        Index("idx_threat_events_score", "threat_score"),
        Index(
            "idx_threat_events_reviewed",
            "reviewed",
            postgresql_where=text("reviewed = FALSE"),
        ),
    )

    source_ip: str = Field(max_length=45)
    request_method: str = Field(max_length=10)
    request_path: str
    status_code: int = Field(sa_column=Column(SmallInteger, nullable=False))
    response_size: int
    user_agent: str
    threat_score: float = Field(sa_column=Column(Float, nullable=False))
    severity: str = Field(max_length=6)
    component_scores: dict[str, float] = Field(
        sa_column=Column(JSON, nullable=False))
    geo_country: str | None = Field(default=None, max_length=2)
    geo_city: str | None = Field(default=None, max_length=255)
    geo_lat: float | None = Field(default=None)
    geo_lon: float | None = Field(default=None)
    feature_vector: list[float] = Field(sa_column=Column(JSON, nullable=False))
    matched_rules: list[str] | None = Field(default=None,
                                            sa_column=Column(JSON,
                                                             nullable=True))
    model_version: str | None = Field(default=None, max_length=64)
    reviewed: bool = Field(default=False)
    review_label: str | None = Field(default=None, max_length=20)
