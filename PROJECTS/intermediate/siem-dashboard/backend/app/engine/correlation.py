"""
©AngelaMos | 2026
correlation.py

Rule evaluation logic and correlation engine daemon

Implements three rule evaluators (threshold, sequence, aggregation)
and a thread-safe sliding window state store. CorrelationEngine runs
as a daemon thread, consuming log events from the Redis Stream via
consumer group, evaluating all enabled rules, and calling
Alert.create_from_rule when a rule fires.

Key exports:
  CorrelationEngine - daemon thread that runs the correlation loop
  CorrelationState - in-memory sliding window and cooldown tracker
  evaluate_rule - evaluates one rule against one event, returns result or None
  start_engine, stop_engine - singleton lifecycle functions

Connects to:
  config.py - reads CORRELATION_* and STREAM settings
  core/streaming.py - calls read_stream, ensure_consumer_group, ack_message
  models/Alert.py - calls Alert.create_from_rule on rule fire
  models/CorrelationRule.py - calls get_enabled_rules, uses RuleType
  controllers/rule_ctrl.py - imports CorrelationState, evaluate_rule for testing
  __init__.py - calls start_engine
"""

import time
import threading
from dataclasses import dataclass
from typing import Any

import structlog

from app.config import settings
from app.core.streaming import (
    read_stream,
    ensure_consumer_group,
    ack_message,
)
from app.models.Alert import Alert
from app.models.CorrelationRule import CorrelationRule, RuleType


logger = structlog.get_logger()


@dataclass
class WindowEntry:
    """
    A single event recorded in a correlation sliding window
    """
    timestamp: float
    event_id: str
    event_data: dict[str, Any]
    step_index: int | None = None


@dataclass
class EvaluationResult:
    """
    Outcome of a rule that fired with matched event references
    """
    matched_event_ids: list[str]
    group_value: str


class CorrelationState:
    """
    Thread-safe in-memory sliding window state for correlation tracking
    """
    def __init__(self) -> None:
        self._windows: dict[str, dict[str, list[WindowEntry]]] = {}
        self._cooldowns: dict[str, dict[str, float]] = {}
        self._lock = threading.Lock()

    def record_event(
        self,
        rule_id: str,
        group_key: str,
        event_id: str,
        event_data: dict[str,
                         Any],
        step_index: int | None = None,
    ) -> None:
        """
        Add an event to the sliding window for a rule and group key
        """
        with self._lock:
            windows = self._windows.setdefault(rule_id, {})
            entries = windows.setdefault(group_key, [])
            entries.append(
                WindowEntry(
                    timestamp = time.time(),
                    event_id = event_id,
                    event_data = event_data,
                    step_index = step_index,
                )
            )

    def get_window(
        self,
        rule_id: str,
        group_key: str,
        window_seconds: int,
    ) -> list[WindowEntry]:
        """
        Return non-expired entries for a rule and group key
        """
        cutoff = time.time() - window_seconds
        with self._lock:
            entries = self._windows.get(rule_id, {}).get(group_key, [])
            valid = [e for e in entries if e.timestamp >= cutoff]
            if rule_id in self._windows and group_key in self._windows[rule_id]:
                self._windows[rule_id][group_key] = valid
            return valid

    def is_cooling_down(self, rule_id: str, group_key: str) -> bool:
        """
        Check if a rule recently fired for this group key
        """
        with self._lock:
            last_fired = self._cooldowns.get(rule_id, {}).get(group_key, 0.0)
            return (time.time() - last_fired) < settings.CORRELATION_COOLDOWN_SECONDS

    def mark_fired(self, rule_id: str, group_key: str) -> None:
        """
        Record the fire time for cooldown tracking
        """
        with self._lock:
            cooldowns = self._cooldowns.setdefault(rule_id, {})
            cooldowns[group_key] = time.time()

    def clear(self) -> None:
        """
        Reset all state for testing or shutdown
        """
        with self._lock:
            self._windows.clear()
            self._cooldowns.clear()


def _matches_filter(event_data: dict[str, Any], event_filter: dict[str, Any]) -> bool:
    """
    Check if an event satisfies all key-value pairs in the filter
    """
    return all(event_data.get(k) == v for k, v in event_filter.items())


def evaluate_rule(
    rule: CorrelationRule,
    event_data: dict[str,
                     Any],
    state: CorrelationState,
) -> EvaluationResult | None:
    """
    Evaluate a single rule against an event and return a result if fired
    """
    rule_id = str(rule.id)
    conditions = rule.conditions
    group_by = conditions.get("group_by", "")
    group_key = event_data.get(group_by, "")

    if not group_key:
        return None

    if state.is_cooling_down(rule_id, group_key):
        return None

    evaluators = {
        RuleType.THRESHOLD: _evaluate_threshold,
        RuleType.SEQUENCE: _evaluate_sequence,
        RuleType.AGGREGATION: _evaluate_aggregation,
    }
    evaluator = evaluators.get(rule.rule_type)
    if evaluator is None:
        return None

    return evaluator(rule, event_data, state, rule_id, group_key)


def _evaluate_threshold(
    rule: CorrelationRule,
    event_data: dict[str,
                     Any],
    state: CorrelationState,
    rule_id: str,
    group_key: str,
) -> EvaluationResult | None:
    """
    Fire when event count exceeds threshold within window for a group
    """
    conditions = rule.conditions
    event_filter = conditions.get("event_filter", {})

    if not _matches_filter(event_data, event_filter):
        return None

    event_id = event_data.get("id", "")
    state.record_event(rule_id, group_key, event_id, event_data)

    window_seconds = conditions.get("window_seconds", 0)
    threshold = conditions.get("threshold", 0)
    entries = state.get_window(rule_id, group_key, window_seconds)

    if len(entries) >= threshold:
        state.mark_fired(rule_id, group_key)
        return EvaluationResult(
            matched_event_ids = [e.event_id for e in entries],
            group_value = group_key,
        )
    return None


def _evaluate_sequence(
    rule: CorrelationRule,
    event_data: dict[str,
                     Any],
    state: CorrelationState,
    rule_id: str,
    group_key: str,
) -> EvaluationResult | None:
    """
    Fire when all steps of a sequence are observed within window for a group
    """
    conditions = rule.conditions
    steps = conditions.get("steps", [])

    matched_step = None
    for idx, step in enumerate(steps):
        step_filter = step.get("event_filter", {})
        if _matches_filter(event_data, step_filter):
            matched_step = idx
            break

    if matched_step is None:
        return None

    event_id = event_data.get("id", "")
    state.record_event(
        rule_id,
        group_key,
        event_id,
        event_data,
        step_index = matched_step,
    )

    window_seconds = conditions.get("window_seconds", 0)
    entries = state.get_window(rule_id, group_key, window_seconds)

    for idx, step in enumerate(steps):
        required_count = step.get("count", 1)
        step_entries = [e for e in entries if e.step_index == idx]
        if len(step_entries) < required_count:
            return None

    state.mark_fired(rule_id, group_key)
    return EvaluationResult(
        matched_event_ids = [e.event_id for e in entries],
        group_value = group_key,
    )


def _evaluate_aggregation(
    rule: CorrelationRule,
    event_data: dict[str,
                     Any],
    state: CorrelationState,
    rule_id: str,
    group_key: str,
) -> EvaluationResult | None:
    """
    Fire when distinct values of a field exceed threshold for a group
    """
    conditions = rule.conditions
    event_filter = conditions.get("event_filter", {})

    if not _matches_filter(event_data, event_filter):
        return None

    event_id = event_data.get("id", "")
    state.record_event(rule_id, group_key, event_id, event_data)

    window_seconds = conditions.get("window_seconds", 0)
    threshold = conditions.get("threshold", 0)
    aggregation_field = conditions.get("aggregation_field", "")
    entries = state.get_window(rule_id, group_key, window_seconds)

    distinct_values = {
        e.event_data.get(aggregation_field)
        for e in entries
        if e.event_data.get(aggregation_field)
    }

    if len(distinct_values) >= threshold:
        state.mark_fired(rule_id, group_key)
        return EvaluationResult(
            matched_event_ids = [e.event_id for e in entries],
            group_value = group_key,
        )
    return None


class CorrelationEngine:
    """
    Daemon thread that consumes log events and evaluates correlation rules
    """
    def __init__(self) -> None:
        self._state = CorrelationState()
        self._stop_event = threading.Event()
        self._rules_cache: list[CorrelationRule] = []
        self._rules_cache_time: float = 0.0
        self._thread = threading.Thread(
            target = self._run,
            daemon = True,
            name = "correlation-engine",
        )

    def start(self) -> None:
        """
        Initialize consumer group and start the engine thread
        """
        ensure_consumer_group(settings.LOG_STREAM_KEY)
        self._thread.start()
        logger.info("correlation_engine_started")

    def stop(self) -> None:
        """
        Signal the engine thread to stop
        """
        self._stop_event.set()
        logger.info("correlation_engine_stopped")

    def _get_rules(self) -> list[CorrelationRule]:
        """
        Return cached rules, refreshing if the cache TTL has expired
        """
        now = time.time()
        elapsed = now - self._rules_cache_time
        if elapsed > settings.CORRELATION_RULE_CACHE_SECONDS:
            self._rules_cache = CorrelationRule.get_enabled_rules()
            self._rules_cache_time = now
        return self._rules_cache

    def _run(self) -> None:
        """
        Main loop that reads events and evaluates rules
        """
        while not self._stop_event.is_set():
            try:
                messages = read_stream(settings.LOG_STREAM_KEY)
                for msg_id, event_data in messages:
                    if self._stop_event.is_set():
                        break
                    self._process_event(event_data)
                    ack_message(settings.LOG_STREAM_KEY, msg_id)
            except Exception:
                logger.exception("correlation_engine_error")
                self._stop_event.wait(settings.CORRELATION_ERROR_BACKOFF_SECONDS)

    def _process_event(self, event_data: dict[str, Any]) -> None:
        """
        Evaluate all enabled rules against a single event
        """
        rules = self._get_rules()
        for rule in rules:
            result = evaluate_rule(rule, event_data, self._state)
            if result is None:
                continue
            Alert.create_from_rule(
                rule = rule,
                matched_event_ids = result.matched_event_ids,
                group_value = result.group_value,
            )
            logger.info(
                "alert_generated",
                rule_name = rule.name,
                group_value = result.group_value,
                matched_count = len(result.matched_event_ids),
            )


_engine: CorrelationEngine | None = None


def start_engine() -> None:
    """
    Create and start the singleton correlation engine
    """
    global _engine
    if _engine is not None:
        return
    _engine = CorrelationEngine()
    _engine.start()


def stop_engine() -> None:
    """
    Stop the singleton correlation engine
    """
    global _engine
    if _engine:
        _engine.stop()
        _engine = None
