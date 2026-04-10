"""
©AngelaMos | 2026
test_compliance.py
"""


from dlp_scanner.compliance import (
    get_frameworks_for_rule,
    get_remediation_for_rule,
    score_to_severity,
    DEFAULT_REMEDIATION,
)


class TestScoreToSeverity:
    def test_critical_threshold(self) -> None:
        assert score_to_severity(0.85) == "critical"
        assert score_to_severity(0.99) == "critical"
        assert score_to_severity(1.0) == "critical"

    def test_high_threshold(self) -> None:
        assert score_to_severity(0.65) == "high"
        assert score_to_severity(0.84) == "high"

    def test_medium_threshold(self) -> None:
        assert score_to_severity(0.40) == "medium"
        assert score_to_severity(0.64) == "medium"

    def test_low_threshold(self) -> None:
        assert score_to_severity(0.20) == "low"
        assert score_to_severity(0.39) == "low"

    def test_below_minimum(self) -> None:
        assert score_to_severity(0.19) == "low"
        assert score_to_severity(0.0) == "low"


class TestFrameworkMapping:
    def test_ssn_maps_to_hipaa_and_ccpa(self) -> None:
        frameworks = get_frameworks_for_rule("PII_SSN")
        assert "HIPAA" in frameworks
        assert "CCPA" in frameworks
        assert "GLBA" in frameworks

    def test_credit_card_maps_to_pci(self) -> None:
        for rule_id in (
            "FIN_CREDIT_CARD_VISA",
            "FIN_CREDIT_CARD_MC",
            "FIN_CREDIT_CARD_AMEX",
            "FIN_CREDIT_CARD_DISC",
        ):
            frameworks = get_frameworks_for_rule(rule_id)
            assert "PCI_DSS" in frameworks

    def test_unknown_rule_returns_empty(self) -> None:
        assert get_frameworks_for_rule("UNKNOWN") == []

    def test_credential_rules_have_no_frameworks(
        self,
    ) -> None:
        frameworks = get_frameworks_for_rule("CRED_AWS_ACCESS_KEY")
        assert frameworks == []


class TestRemediation:
    def test_known_rule_has_remediation(self) -> None:
        text = get_remediation_for_rule("PII_SSN")
        assert "encrypt" in text.lower() or "tokeniz" in text.lower()

    def test_unknown_rule_returns_default(self) -> None:
        assert get_remediation_for_rule("UNKNOWN") == DEFAULT_REMEDIATION
