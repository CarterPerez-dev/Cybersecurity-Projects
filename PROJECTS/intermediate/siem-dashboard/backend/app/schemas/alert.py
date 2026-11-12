"""
©AngelaMos | 2026
alert.py

Pydantic schemas for the alerts endpoints

Defines AlertStatusUpdate for status transitions and AlertQueryParams
for paginated alert listing with optional status and severity filters.

Key exports:
  AlertStatusUpdate - status transition request
  AlertQueryParams - listing filters with pagination

Connects to:
  models/Alert.py - imports AlertStatus for the status field
  config.py - reads DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
  routes/alerts.py - passed to S()
"""

from pydantic import BaseModel, Field

from app.config import settings
from app.models.Alert import AlertStatus


class AlertStatusUpdate(BaseModel):
    """
    Schema for transitioning an alert to a new status
    """
    status: AlertStatus
    notes: str | None = None


class AlertQueryParams(BaseModel):
    """
    Filters for listing alerts
    """
    page: int = Field(default = 1, ge = 1)
    per_page: int = Field(
        default = settings.DEFAULT_PAGE_SIZE,
        ge = 1,
        le = settings.MAX_PAGE_SIZE,
    )
    status: str | None = None
    severity: str | None = None
