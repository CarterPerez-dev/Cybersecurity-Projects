"""
©AngelaMos | 2026
model_metadata.py
"""

from sqlalchemy import Column, Index, JSON, text
from sqlmodel import Field

from app.models.base import TimestampedModel


class ModelMetadata(TimestampedModel, table=True):
    """
    Tracks ML model versions, training metrics, and deployment status.
    """

    __tablename__ = "model_metadata"
    __table_args__ = (
        Index(
            "idx_model_metadata_active",
            "model_type",
            unique=True,
            postgresql_where=text("is_active = TRUE"),
        ),
    )

    model_type: str = Field(max_length=30)
    version: str = Field(max_length=64)
    training_samples: int
    metrics: dict[str, object] = Field(sa_column=Column(JSON, nullable=False))
    artifact_path: str
    is_active: bool = Field(default=False)
    mlflow_run_id: str | None = Field(default=None, max_length=64)
    threshold: float | None = Field(default=None)
    notes: str | None = Field(default=None)
