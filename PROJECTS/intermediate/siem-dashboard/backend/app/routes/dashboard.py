"""
©AngelaMos | 2026
dashboard.py

Route handlers for the dashboard API (/v1/dashboard)

Mounts GET / (overview stats), GET /timeline, GET /severity-breakdown,
and GET /top-sources.

Connects to:
  controllers/dashboard_ctrl.py - business logic
  schemas/dashboard.py - TimelineParams, TopSourcesParams
  routes/__init__.py - dashboard_bp registered here
"""

from typing import Any

from flask import Blueprint

from app.controllers import dashboard_ctrl
from app.core.decorators import endpoint, S, R
from app.schemas.dashboard import TimelineParams, TopSourcesParams


dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.get("")
@endpoint()
@R()
def overview() -> Any:
    """
    Return combined dashboard statistics
    """
    return dashboard_ctrl.overview()


@dashboard_bp.get("/timeline")
@endpoint()
@S(TimelineParams, source = "query")
@R()
def timeline() -> Any:
    """
    Return event counts bucketed over a time window
    """
    return dashboard_ctrl.timeline()


@dashboard_bp.get("/severity-breakdown")
@endpoint()
@R()
def severity_breakdown() -> Any:
    """
    Return event counts grouped by severity level
    """
    return dashboard_ctrl.severity_breakdown()


@dashboard_bp.get("/top-sources")
@endpoint()
@S(TopSourcesParams, source = "query")
@R()
def top_sources() -> Any:
    """
    Return the most frequent source IPs
    """
    return dashboard_ctrl.top_sources()
