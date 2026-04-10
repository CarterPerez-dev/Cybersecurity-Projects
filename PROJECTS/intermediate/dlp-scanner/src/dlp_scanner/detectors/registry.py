"""
©AngelaMos | 2026
registry.py
"""


import fnmatch

from dlp_scanner.detectors.base import (
    DetectionRule,
    DetectorMatch,
)
from dlp_scanner.detectors.context import (
    apply_context_boost,
)
from dlp_scanner.detectors.entropy import EntropyDetector
from dlp_scanner.detectors.pattern import PatternDetector
from dlp_scanner.detectors.rules.credentials import (
    CREDENTIAL_RULES,
)
from dlp_scanner.detectors.rules.financial import (
    FINANCIAL_RULES,
)
from dlp_scanner.detectors.rules.health import HEALTH_RULES
from dlp_scanner.detectors.rules.pii import PII_RULES


ALL_RULES: list[DetectionRule] = [
    *PII_RULES,
    *FINANCIAL_RULES,
    *CREDENTIAL_RULES,
    *HEALTH_RULES,
]


class DetectorRegistry:
    """
    Central registry that loads, filters, and runs all detectors
    """
    def __init__(
        self,
        enable_patterns: list[str] | None = None,
        disable_patterns: list[str] | None = None,
        allowlist_values: frozenset[str] | None = None,
        context_window_tokens: int = 10,
        entropy_threshold: float = 7.2,
        enable_entropy: bool = True,
    ) -> None:
        active_rules = _filter_rules(
            ALL_RULES,
            enable_patterns or ["*"],
            disable_patterns or [],
        )

        self._pattern_detector = PatternDetector(
            rules = active_rules,
            allowlist_values = allowlist_values,
        )
        self._entropy_detector = (
            EntropyDetector(threshold = entropy_threshold)
            if enable_entropy else None
        )
        self._context_window = context_window_tokens

    def detect(self, text: str) -> list[DetectorMatch]:
        """
        Run all detectors against text and return scored matches
        """
        matches = self._pattern_detector.detect(text)
        matches = apply_context_boost(
            text,
            matches,
            window_tokens = self._context_window,
        )

        if self._entropy_detector is not None:
            entropy_matches = (self._entropy_detector.detect(text))
            matches.extend(entropy_matches)

        return matches

    @property
    def rule_count(self) -> int:
        """
        Return the number of active pattern rules
        """
        return len(self._pattern_detector._rules)


def _filter_rules(
    rules: list[DetectionRule],
    enable_patterns: list[str],
    disable_patterns: list[str],
) -> list[DetectionRule]:
    """
    Filter rules by enable/disable glob patterns
    """
    filtered: list[DetectionRule] = []

    for rule in rules:
        enabled = any(
            fnmatch.fnmatch(rule.rule_id,
                            pat) for pat in enable_patterns
        )
        disabled = any(
            fnmatch.fnmatch(rule.rule_id,
                            pat) for pat in disable_patterns
        )
        if enabled and not disabled:
            filtered.append(rule)

    return filtered
