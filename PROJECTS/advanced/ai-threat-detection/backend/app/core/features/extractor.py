"""
©AngelaMos | 2026
extractor.py
"""

import ipaddress
import math
from collections import Counter
from posixpath import splitext

from app.core.features.patterns import (
    ATTACK_COMBINED,
    DOUBLE_ENCODED,
    ENCODED_CHARS,
)
from app.core.features.signatures import BOT_USER_AGENTS, SCANNER_USER_AGENTS
from app.core.ingestion.parsers import ParsedLogEntry


def _shannon_entropy(s: str) -> float:
    """
    Compute Shannon entropy of a string.
    """
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_private_ip(ip_str: str) -> bool:
    """
    Check whether an IP address is in a private or loopback range.
    """
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


def extract_request_features(
    entry: ParsedLogEntry,
    country_code: str = "",
) -> dict[str, int | float | bool | str]:
    """
    Extract 23 stateless per-request features from a parsed log entry.
    """
    full_uri = entry.path
    if entry.query_string:
        full_uri = f"{entry.path}?{entry.query_string}"

    ua_lower = entry.user_agent.lower()
    non_alnum = sum(1 for c in entry.path if not c.isalnum())
    path_len = len(entry.path)

    _, ext = splitext(entry.path)

    return {
        "http_method": entry.method,
        "path_depth": len([s for s in entry.path.split("/") if s]),
        "path_entropy": _shannon_entropy(entry.path),
        "path_length": path_len,
        "query_string_length": len(entry.query_string),
        "query_param_count": (len(entry.query_string.split("&")) if entry.query_string else 0),
        "has_encoded_chars": bool(ENCODED_CHARS.search(full_uri)),
        "has_double_encoding": bool(DOUBLE_ENCODED.search(full_uri)),
        "status_code": entry.status_code,
        "status_class": f"{entry.status_code // 100}xx",
        "response_size": entry.response_size,
        "hour_of_day": entry.timestamp.hour,
        "day_of_week": entry.timestamp.weekday(),
        "is_weekend": entry.timestamp.weekday() >= 5,
        "ua_length": len(entry.user_agent),
        "ua_entropy": _shannon_entropy(entry.user_agent),
        "is_known_bot": any(sig in ua_lower for sig in BOT_USER_AGENTS),
        "is_known_scanner": any(sig in ua_lower for sig in SCANNER_USER_AGENTS),
        "has_attack_pattern": bool(ATTACK_COMBINED.search(full_uri)),
        "special_char_ratio": non_alnum / path_len if path_len else 0.0,
        "file_extension": ext,
        "country_code": country_code,
        "is_private_ip": _is_private_ip(entry.ip),
    }
