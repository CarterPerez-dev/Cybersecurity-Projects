"""
©AngelaMos | 2026
normalizer.py

Log event normalization by source type

Provides a registry of per-source-type normalizers (firewall, IDS,
auth, endpoint, DNS, proxy, generic) registered via a decorator.
normalize extracts common fields then merges source-specific fields
into a normalized dict before the event is persisted.

Key exports:
  normalize - dispatches to the correct normalizer and returns enriched data

Connects to:
  models/LogEvent.py - imports SourceType for the registry
  controllers/log_ctrl.py - calls normalize before persisting an event
  scenarios/runner.py - calls normalize for each playbook event
"""

from datetime import datetime, UTC
from typing import Any
from collections.abc import Callable

from app.models.LogEvent import SourceType


NormalizerFn = Callable[[dict[str, Any]], dict[str, Any]]

NORMALIZERS: dict[str, NormalizerFn] = {}


def _register(source_type: SourceType) -> Callable[[NormalizerFn], NormalizerFn]:
    """
    Register a normalizer function for a source type
    """
    def decorator(fn: NormalizerFn) -> NormalizerFn:
        NORMALIZERS[source_type.value] = fn
        return fn

    return decorator


def normalize(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Dispatch to the appropriate format normalizer and return enriched data
    """
    source_type = raw.get("source_type", SourceType.GENERIC)
    normalizer_fn = NORMALIZERS.get(source_type, _normalize_generic)
    base = _extract_common(raw)
    specific = normalizer_fn(raw)
    base["normalized"] = {**base.get("normalized", {}), **specific}
    return base


def _extract_common(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Pull fields shared across all log formats into a base dict
    """
    return {
        "timestamp": raw.get("timestamp",
                             datetime.now(UTC)),
        "source_type": raw.get("source_type",
                               SourceType.GENERIC),
        "source_ip": raw.get("source_ip"),
        "dest_ip": raw.get("dest_ip"),
        "source_port": raw.get("source_port"),
        "dest_port": raw.get("dest_port"),
        "event_type": raw.get("event_type"),
        "hostname": raw.get("hostname"),
        "username": raw.get("username"),
        "raw": raw,
        "normalized": {},
    }


@_register(SourceType.FIREWALL)
def _normalize_firewall(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Extract firewall-specific fields like action and protocol
    """
    return {
        "action": raw.get("action"),
        "protocol": raw.get("protocol"),
        "bytes_sent": raw.get("bytes_sent"),
        "bytes_received": raw.get("bytes_received"),
        "rule_name": raw.get("rule_name"),
    }


@_register(SourceType.IDS)
def _normalize_ids(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Extract IDS-specific fields like signature and severity
    """
    return {
        "signature_id": raw.get("signature_id"),
        "signature_name": raw.get("signature_name"),
        "classification": raw.get("classification"),
        "priority": raw.get("priority"),
    }


@_register(SourceType.AUTH)
def _normalize_auth(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Extract authentication-specific fields like method and result
    """
    return {
        "auth_method": raw.get("auth_method"),
        "result": raw.get("result"),
        "failure_reason": raw.get("failure_reason"),
        "service": raw.get("service"),
    }


@_register(SourceType.ENDPOINT)
def _normalize_endpoint(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Extract endpoint-specific fields like process and command line
    """
    return {
        "process_name": raw.get("process_name"),
        "process_id": raw.get("process_id"),
        "parent_process": raw.get("parent_process"),
        "command_line": raw.get("command_line"),
        "file_path": raw.get("file_path"),
    }


@_register(SourceType.DNS)
def _normalize_dns(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Extract DNS-specific fields like query and record type
    """
    return {
        "query": raw.get("query"),
        "query_type": raw.get("query_type"),
        "response": raw.get("response"),
        "response_code": raw.get("response_code"),
    }


@_register(SourceType.PROXY)
def _normalize_proxy(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Extract proxy-specific fields like URL and user agent
    """
    return {
        "url": raw.get("url"),
        "method": raw.get("method"),
        "status_code": raw.get("status_code"),
        "user_agent": raw.get("user_agent"),
        "content_type": raw.get("content_type"),
        "bytes_transferred": raw.get("bytes_transferred"),
    }


@_register(SourceType.GENERIC)
def _normalize_generic(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Fallback normalizer for unrecognized source types
    """
    return {
        "message": raw.get("message"),
    }
