"""
©AngelaMos | 2026
rules.py
"""

import re
from dataclasses import dataclass, field
from typing import NamedTuple

from app.core.features.patterns import (
    COMMAND_INJECTION,
    DOUBLE_ENCODED,
    FILE_INCLUSION,
    PATH_TRAVERSAL,
    SQLI,
    XSS,
)
from app.core.features.signatures import SCANNER_USER_AGENTS
from app.core.ingestion.parsers import ParsedLogEntry


class _PatternRule(NamedTuple):
    """
    A regex based detection rule applied to the request URI
    """

    name: str
    pattern: re.Pattern[str]
    score: float


class _ThresholdRule(NamedTuple):
    """
    A threshold-based detection rule applied to a windowed feature
    """

    name: str
    feature_key: str
    threshold: float
    score: float


_PATTERN_RULES: list[_PatternRule] = [
    _PatternRule("COMMAND_INJECTION", COMMAND_INJECTION, 0.90),
    _PatternRule("SQL_INJECTION", SQLI, 0.85),
    _PatternRule("XSS", XSS, 0.80),
    _PatternRule("FILE_INCLUSION", FILE_INCLUSION, 0.75),
    _PatternRule("PATH_TRAVERSAL", PATH_TRAVERSAL, 0.60),
]

_THRESHOLD_RULES: list[_ThresholdRule] = [
    _ThresholdRule("RATE_ANOMALY", "req_count_1m", 100.0, 0.30),
    _ThresholdRule("HIGH_ERROR_RATE", "error_rate_5m", 0.5, 0.25),
]

_DOUBLE_ENCODING_SCORE = 0.40
_SCANNER_UA_SCORE = 0.35
_BOOST_PER_ADDITIONAL_RULE = 0.05


@dataclass(frozen=True, slots=True)
class RuleResult:
    """
    Output of the rule-based detection engine for a single request.
    """

    threat_score: float
    severity: str
    matched_rules: list[str] = field(default_factory=list)
    component_scores: dict[str, float] = field(default_factory=dict)


def _classify_severity(score: float) -> str:
    """
    Map a threat score to a severity label.
    """
    if score >= 0.7:
        return "HIGH"
    if score >= 0.5:
        return "MEDIUM"
    return "LOW"


class RuleEngine:
    """
    Cold-start rule-based detection engine inspired by ModSecurity CRS.
    Scores requests using pattern matching, signature detection,
    and behavioral thresholds from windowed features
    """

    def score_request(
        self,
        features: dict[str, int | float | bool | str],
        entry: ParsedLogEntry,
    ) -> RuleResult:
        """
        Evaluate all rules against a request and return a composite score.
        """
        matched: list[tuple[str, float]] = []

        uri = entry.path
        if entry.query_string:
            uri = f"{entry.path}?{entry.query_string}"

        for rule in _PATTERN_RULES:
            if rule.pattern.search(uri):
                matched.append((rule.name, rule.score))

        if DOUBLE_ENCODED.search(uri):
            matched.append(("DOUBLE_ENCODING", _DOUBLE_ENCODING_SCORE))

        ua_lower = entry.user_agent.lower()
        if any(sig in ua_lower for sig in SCANNER_USER_AGENTS):
            matched.append(("SCANNER_UA", _SCANNER_UA_SCORE))

        for trule in _THRESHOLD_RULES:
            value = features.get(trule.feature_key, 0)
            if isinstance(value, (int, float)) and value > trule.threshold:
                matched.append((trule.name, trule.score))

        if not matched:
            return RuleResult(threat_score=0.0, severity="LOW")

        scores = sorted([s for _, s in matched], reverse=True)
        threat_score = min(
            scores[0] + _BOOST_PER_ADDITIONAL_RULE * (len(scores) - 1),
            1.0,
        )

        return RuleResult(
            threat_score=threat_score,
            severity=_classify_severity(threat_score),
            matched_rules=[name for name, _ in matched],
            component_scores=dict(matched),
        )
