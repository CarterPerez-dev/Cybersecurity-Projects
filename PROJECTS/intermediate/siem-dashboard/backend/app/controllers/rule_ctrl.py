"""
©AngelaMos | 2026
rule_ctrl.py

Business logic for correlation rule management

CRUD operations plus a test function that replays historical log
events through a rule using an isolated CorrelationState, returning
what alerts would have fired without touching production state or
publishing real alerts.

Key exports:
  list_rules, get_rule, create_rule, update_rule, delete_rule, test_rule

Connects to:
  models/CorrelationRule.py - CRUD operations
  models/LogEvent.py - reads historical events for test_rule
  engine/correlation.py - imports CorrelationState, evaluate_rule
  routes/rules.py - called from route handlers
"""

from typing import Any
from datetime import datetime, timedelta, UTC

from flask import g

from app.engine.correlation import (
    CorrelationState,
    evaluate_rule,
)
from app.models.CorrelationRule import CorrelationRule
from app.models.LogEvent import LogEvent


def list_rules() -> list[Any]:
    """
    Return all correlation rules
    """
    return list(CorrelationRule.objects.order_by("-created_at"))  # type: ignore[no-untyped-call]


def get_rule(rule_id: str) -> CorrelationRule:
    """
    Return a single correlation rule by ID
    """
    return CorrelationRule.get_by_id(rule_id)


def create_rule() -> CorrelationRule:
    """
    Create a new correlation rule from validated request data
    """
    data = g.validated
    rule = CorrelationRule(
        name = data.name,
        description = data.description,
        rule_type = data.rule_type,
        conditions = data.conditions,
        severity = data.severity,
        enabled = data.enabled,
        mitre_tactic = data.mitre_tactic,
        mitre_technique = data.mitre_technique,
    )
    rule.save()  # type: ignore[no-untyped-call]
    return rule


def update_rule(rule_id: str) -> CorrelationRule:
    """
    Partially update an existing correlation rule
    """
    data = g.validated
    rule = CorrelationRule.get_by_id(rule_id)
    updates = data.model_dump(exclude_none = True)
    for field_name, value in updates.items():
        setattr(rule, field_name, value)
    rule.save()  # type: ignore[no-untyped-call]
    return rule


def delete_rule(rule_id: str) -> dict[str, Any]:
    """
    Delete a correlation rule by ID
    """
    rule = CorrelationRule.get_by_id(rule_id)
    rule.delete()  # type: ignore[no-untyped-call]
    return {"deleted": True}


def test_rule(rule_id: str) -> dict[str, Any]:
    """
    Simulate a rule against historical log events and return matches
    """
    data = g.validated
    rule = CorrelationRule.get_by_id(rule_id)

    cutoff = datetime.now(UTC).replace(
        second = 0,
        microsecond = 0,
    )
    since = cutoff - timedelta(hours = data.hours)

    events = LogEvent.objects(timestamp__gte = since).order_by("timestamp")  # type: ignore[no-untyped-call]

    state = CorrelationState()
    alerts_fired: list[dict[str, Any]] = []

    for event in events:
        event_data = {
            "id": str(event.id),
            "timestamp": str(event.timestamp),
            "source_type": event.source_type,
            "severity": event.severity,
            "event_type": event.event_type,
            "source_ip": event.source_ip,
            "dest_ip": event.dest_ip,
            "hostname": event.hostname,
            "username": event.username,
        }

        result = evaluate_rule(rule, event_data, state)
        if result:
            alerts_fired.append(
                {
                    "group_value": result.group_value,
                    "matched_event_count": len(result.matched_event_ids),
                    "matched_event_ids": result.matched_event_ids,
                }
            )

    return {
        "rule_id": str(rule.id),
        "rule_name": rule.name,
        "events_evaluated": events.count(),  # type: ignore[no-untyped-call]
        "alerts_would_fire": len(alerts_fired),
        "alerts": alerts_fired,
    }
