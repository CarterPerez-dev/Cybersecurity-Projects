"""
©AngelaMos | 2026
alert_ctrl.py

Business logic for alert operations

Handles paginated listing with status and severity filters, single
alert retrieval with matched log events, status lifecycle transitions
with optional acknowledgment metadata, and the SSE alert stream.

Key exports:
  list_alerts, get_alert_detail, update_alert_status, stream_alerts

Connects to:
  models/Alert.py - query and status update methods
  core/streaming.py - calls sse_generator for the alert stream
  config.py - reads ALERT_STREAM_KEY
  routes/alerts.py - called from route handlers
"""

from typing import Any

from flask import Response, g

from app.config import settings
from app.core.streaming import sse_generator
from app.models.Alert import Alert


def list_alerts() -> dict[str, Any]:
    """
    Return paginated and filtered alerts
    """
    params = g.validated
    filters = {}
    if params.status:
        filters["status"] = params.status
    if params.severity:
        filters["severity"] = params.severity

    qs = Alert.objects(**filters).order_by("-created_at")
    return Alert.paginate(
        queryset = qs,
        page = params.page,
        per_page = params.per_page,
    )


def get_alert_detail(alert_id: str) -> dict[str, Any]:
    """
    Return an alert with its matched log events
    """
    alert = Alert.get_by_id(alert_id)
    return alert.get_with_events()


def update_alert_status(alert_id: str) -> Alert:
    """
    Transition an alert to a new lifecycle status
    """
    data = g.validated
    alert = Alert.get_by_id(alert_id)
    username = None
    if g.current_user:
        username = g.current_user.username
    alert.update_status(
        status = data.status,
        username = username,
        notes = data.notes,
    )
    return alert


def stream_alerts() -> Response:
    """
    SSE endpoint that tails the alert Redis Stream
    """
    return Response(
        sse_generator(settings.ALERT_STREAM_KEY,
                      event_type = "alert"),
        mimetype = "text/event-stream",
        headers = {
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
