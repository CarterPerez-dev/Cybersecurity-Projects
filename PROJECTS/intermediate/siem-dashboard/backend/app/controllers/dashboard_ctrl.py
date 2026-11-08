"""
©AngelaMos | 2026
dashboard_ctrl.py

Business logic for dashboard aggregations

Provides the overview summary (event and alert counts, open alert
count, severity breakdown), time-bucketed event timeline, per-severity
event counts, and top source IPs. All calls are read-only MongoDB
aggregation queries with no side effects.

Key exports:
  overview, timeline, severity_breakdown, top_sources

Connects to:
  models/Alert.py - alert count and status aggregations
  models/LogEvent.py - timeline, severity, and top source queries
  routes/dashboard.py - called from route handlers
"""

from typing import Any

from flask import g

from app.models.Alert import Alert, AlertStatus
from app.models.LogEvent import LogEvent


def overview() -> dict[str, Any]:
    """
    Return combined dashboard statistics
    """
    alert_pipeline = [
        {
            "$group": {
                "_id": "$status",
                "count": {
                    "$sum": 1
                },
            }
        },
    ]
    alerts_by_status = {
        doc["_id"]: doc["count"]
        for doc in Alert.objects.aggregate(alert_pipeline)
    }

    return {
        "total_events":
        LogEvent.objects.count(),
        "total_alerts":
        Alert.objects.count(),
        "open_alerts":
        alerts_by_status.get(AlertStatus.NEW,
                             0) + alerts_by_status.get(AlertStatus.ACKNOWLEDGED,
                                                       0) +
        alerts_by_status.get(AlertStatus.INVESTIGATING,
                             0),
        "alerts_by_status":
        alerts_by_status,
        "severity_breakdown":
        LogEvent.severity_breakdown(),
    }


def timeline() -> list[dict[str, Any]]:
    """
    Return event counts bucketed over a time window
    """
    params = g.validated
    return LogEvent.timeline_aggregation(
        hours = params.hours,
        bucket_minutes = params.bucket_minutes,
    )


def severity_breakdown() -> list[dict[str, Any]]:
    """
    Return event counts grouped by severity level
    """
    return LogEvent.severity_breakdown()


def top_sources() -> list[dict[str, Any]]:
    """
    Return the most frequent source IPs
    """
    params = g.validated
    return LogEvent.top_sources(limit = params.limit)
