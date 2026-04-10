"""
©AngelaMos | 2026
test_pattern.py
"""


from dlp_scanner.detectors.pattern import PatternDetector
from dlp_scanner.detectors.rules.pii import PII_RULES


class TestPatternDetector:
    def test_detects_ssn_in_text(self) -> None:
        detector = PatternDetector(
            rules = PII_RULES,
            allowlist_values = frozenset()
        )
        text = "Employee SSN is 234-56-7890 on file."
        matches = detector.detect(text)
        ssn_matches = [m for m in matches if m.rule_id == "PII_SSN"]
        assert len(ssn_matches) == 1
        assert ssn_matches[0].matched_text == "234-56-7890"

    def test_skips_allowlisted_values(self) -> None:
        detector = PatternDetector(rules = PII_RULES)
        text = "Test SSN: 123-45-6789"
        matches = detector.detect(text)
        ssn_matches = [m for m in matches if m.rule_id == "PII_SSN"]
        assert len(ssn_matches) == 0

    def test_detects_email(self) -> None:
        detector = PatternDetector(
            rules = PII_RULES,
            allowlist_values = frozenset()
        )
        text = "Contact: alice@company.com for details."
        matches = detector.detect(text)
        email_matches = [m for m in matches if m.rule_id == "PII_EMAIL"]
        assert len(email_matches) == 1

    def test_no_matches_in_clean_text(self) -> None:
        detector = PatternDetector(rules = PII_RULES)
        text = "This is a perfectly clean document."
        matches = detector.detect(text)
        assert len(matches) == 0

    def test_multiple_matches_in_one_text(self) -> None:
        detector = PatternDetector(
            rules = PII_RULES,
            allowlist_values = frozenset()
        )
        text = (
            "Name: John, SSN: 234-56-7890, "
            "Email: john@test.org, Phone: (555) 234-5678"
        )
        matches = detector.detect(text)
        rule_ids = {m.rule_id for m in matches}
        assert "PII_SSN" in rule_ids
        assert "PII_EMAIL" in rule_ids
