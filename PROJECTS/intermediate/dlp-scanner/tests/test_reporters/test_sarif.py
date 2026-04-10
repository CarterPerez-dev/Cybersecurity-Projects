"""
©AngelaMos | 2026
test_sarif.py
"""


import json

import pytest

from dlp_scanner.models import (
    Finding,
    Location,
    ScanResult,
)
from dlp_scanner.reporters.sarif import (
    SarifReporter,
)


@pytest.fixture
def result_with_findings() -> ScanResult:
    """
    Provide a ScanResult with test findings
    """
    result = ScanResult(targets_scanned = 2)
    result.findings = [
        Finding(
            rule_id = "PII_SSN",
            rule_name = "US Social Security Number",
            severity = "critical",
            confidence = 0.95,
            location = Location(
                source_type = "file",
                uri = "data/employees.csv",
                line = 10,
                column = 5,
            ),
            redacted_snippet = "***-**-6789",
            compliance_frameworks = [
                "HIPAA",
                "CCPA",
            ],
            remediation = "Encrypt SSN data",
        ),
        Finding(
            rule_id = "CRED_AWS_ACCESS_KEY",
            rule_name = "AWS Access Key",
            severity = "high",
            confidence = 0.85,
            location = Location(
                source_type = "database",
                uri = "postgresql://host/db",
                table_name = "config",
            ),
            redacted_snippet = "AKIA****",
            compliance_frameworks = [],
            remediation = "Rotate credentials",
        ),
    ]
    return result


class TestSarifReporter:
    def test_generates_valid_json(
        self,
        result_with_findings: ScanResult
    ) -> None:
        reporter = SarifReporter()
        output = reporter.generate(result_with_findings)
        data = json.loads(output)
        assert isinstance(data, dict)

    def test_has_sarif_version(
        self,
        result_with_findings: ScanResult
    ) -> None:
        reporter = SarifReporter()
        output = reporter.generate(result_with_findings)
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert "$schema" in data

    def test_has_tool_driver(
        self,
        result_with_findings: ScanResult
    ) -> None:
        reporter = SarifReporter()
        output = reporter.generate(result_with_findings)
        data = json.loads(output)
        driver = data["runs"][0]["tool"]["driver"]
        assert driver["name"] == "dlp-scanner"
        assert driver["version"] == "0.1.0"

    def test_rules_collected(
        self,
        result_with_findings: ScanResult
    ) -> None:
        reporter = SarifReporter()
        output = reporter.generate(result_with_findings)
        data = json.loads(output)
        rules = (data["runs"][0]["tool"]["driver"]["rules"])
        assert len(rules) == 2
        rule_ids = {r["id"] for r in rules}
        assert "PII_SSN" in rule_ids
        assert "CRED_AWS_ACCESS_KEY" in rule_ids

    def test_results_match_findings(
        self,
        result_with_findings: ScanResult
    ) -> None:
        reporter = SarifReporter()
        output = reporter.generate(result_with_findings)
        data = json.loads(output)
        results = data["runs"][0]["results"]
        assert len(results) == 2

    def test_severity_mapped_to_level(
        self,
        result_with_findings: ScanResult
    ) -> None:
        reporter = SarifReporter()
        output = reporter.generate(result_with_findings)
        data = json.loads(output)
        results = data["runs"][0]["results"]
        assert results[0]["level"] == "error"
        assert results[1]["level"] == "error"

    def test_location_has_artifact(
        self,
        result_with_findings: ScanResult
    ) -> None:
        reporter = SarifReporter()
        output = reporter.generate(result_with_findings)
        data = json.loads(output)
        loc = data["runs"][0]["results"][0]["locations"][0]
        physical = loc["physicalLocation"]
        assert (
            physical["artifactLocation"]["uri"] == "data/employees.csv"
        )
        assert physical["region"]["startLine"] == 10
        assert (physical["region"]["startColumn"] == 5)

    def test_database_finding_has_logical_location(
        self,
        result_with_findings: ScanResult
    ) -> None:
        reporter = SarifReporter()
        output = reporter.generate(result_with_findings)
        data = json.loads(output)
        loc = data["runs"][0]["results"][1]["locations"][0]
        logical = loc["logicalLocations"]
        assert logical[0]["name"] == "config"
        assert logical[0]["kind"] == "table"

    def test_properties_has_confidence(
        self,
        result_with_findings: ScanResult
    ) -> None:
        reporter = SarifReporter()
        output = reporter.generate(result_with_findings)
        data = json.loads(output)
        props = data["runs"][0]["results"][0]["properties"]
        assert props["confidence"] == 0.95
        assert props["redactedSnippet"]
        assert "HIPAA" in (props["complianceFrameworks"])

    def test_empty_result(self) -> None:
        reporter = SarifReporter()
        result = ScanResult()
        output = reporter.generate(result)
        data = json.loads(output)
        assert len(data["runs"][0]["results"]) == 0
        assert (len(data["runs"][0]["tool"]["driver"]["rules"]) == 0)
