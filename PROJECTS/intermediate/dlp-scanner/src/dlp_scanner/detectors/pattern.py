"""
©AngelaMos | 2026
pattern.py
"""


from dlp_scanner.constants import CHECKSUM_BOOST, KNOWN_TEST_VALUES
from dlp_scanner.detectors.base import (
    DetectionRule,
    DetectorMatch,
)


class PatternDetector:
    """
    Detects sensitive data using regex patterns with optional
    checksum validation
    """
    def __init__(
        self,
        rules: list[DetectionRule],
        allowlist_values: frozenset[str] | None = None,
    ) -> None:
        self._rules = rules
        self._allowlist = allowlist_values or KNOWN_TEST_VALUES

    def detect(self, text: str) -> list[DetectorMatch]:
        """
        Scan text against all registered patterns
        """
        matches: list[DetectorMatch] = []

        for rule in self._rules:
            for m in rule.pattern.finditer(text):
                matched_text = m.group()

                if self._is_allowlisted(matched_text):
                    continue

                score = rule.base_score

                if rule.validator is not None:
                    if rule.validator(matched_text):
                        score = min(1.0, score + CHECKSUM_BOOST)
                    else:
                        continue

                matches.append(
                    DetectorMatch(
                        rule_id = rule.rule_id,
                        rule_name = rule.rule_name,
                        start = m.start(),
                        end = m.end(),
                        matched_text = matched_text,
                        score = score,
                        context_keywords = rule.context_keywords,
                        compliance_frameworks = rule.compliance_frameworks,
                    )
                )

        return matches

    def _is_allowlisted(self, value: str) -> bool:
        """
        Check if a matched value is in the allowlist
        """
        normalized = value.strip()
        return normalized in self._allowlist
