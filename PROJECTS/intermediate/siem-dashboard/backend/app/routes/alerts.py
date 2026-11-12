"""
©AngelaMos | 2026
alerts.py

Route handlers for the alerts API (/v1/alerts)

Mounts GET /, GET /stream (SSE), GET /<alert_id>, and
PATCH /<alert_id>/status.

Connects to:
  controllers/alert_ctrl.py - business logic
  schemas/alert.py - AlertStatusUpdate, AlertQueryParams
  routes/__init__.py - alerts_bp registered here
"""

from typing import Any

from flask import Blueprint

from app.controllers import alert_ctrl
from app.core.decorators import endpoint, S, R
from app.schemas.alert import AlertStatusUpdate, AlertQueryParams


alerts_bp = Blueprint("alerts", __name__)


@alerts_bp.get("")
@endpoint()
@S(AlertQueryParams, source = "query")
@R()
def list_alerts() -> Any:
    """
    Return paginated and filtered alerts
    """
    return alert_ctrl.list_alerts()


@alerts_bp.get("/stream")
@endpoint()
def stream_alerts() -> Any:
    """
    SSE stream of real-time alerts
    """
    return alert_ctrl.stream_alerts()


@alerts_bp.get("/<alert_id>")
@endpoint()
@R()
def get_alert_detail(alert_id: str) -> Any:
    """
    Return an alert with its matched log events
    """
    return alert_ctrl.get_alert_detail(alert_id)


@alerts_bp.patch("/<alert_id>/status")
@endpoint()
@S(AlertStatusUpdate)
@R()
def update_alert_status(alert_id: str) -> Any:
    """
    Transition an alert to a new lifecycle status
    """
    return alert_ctrl.update_alert_status(alert_id)
