"""
©AngelaMos | 2026
test_json_report.py
"""


import json

import pytest

from dlp_scanner.models import (
    Finding,
    Location,
    ScanResult,
)
from dlp_scanner.reporters.json_report import (
    JsonReporter,
)


@pytest.fixture
def result_with_findings() -> ScanResult:
    """
    Provide a ScanResult with test findings
    """
    result = ScanResult(targets_scanned = 3)
    result.findings = [
        Finding(
            rule_id = "PII_SSN",
            rule_name = "US Social Security Number",
            severity = "critical",
            confidence = 0.95,
            location = Location(
                source_type = "file",
                uri = "employees.csv",
                line = 2,
            ),
            redacted_snippet = "SSN: ***-**-6789",
            compliance_frameworks = [
                "HIPAA",
                "CCPA",
            ],
            remediation = "Encrypt SSN data",
        ),
        Finding(
            rule_id = "PII_EMAIL",
            rule_name = "Email Address",
            severity = "medium",
            confidence = 0.65,
            location = Location(
                source_type = "file",
                uri = "contacts.json",
            ),
            redacted_snippet = "j***@example.com",
            compliance_frameworks = ["GDPR"],
            remediation = "Hash emails",
        ),
    ]
    return result


@pytest.fixture
def empty_result() -> ScanResult:
    """
    Provide a ScanResult with no findings
    """
    return ScanResult(targets_scanned = 5)


class TestJsonReporter:
    def test_generates_valid_json(
        self,
        result_with_findings: ScanResult
    ) -> None:
        reporter = JsonReporter()
        output = reporter.generate(result_with_findings)
        data = json.loads(output)
        assert isinstance(data, dict)

    def test_has_metadata_section(
        self,
        result_with_findings: ScanResult
    ) -> None:
        reporter = JsonReporter()
        output = reporter.generate(result_with_findings)
        data = json.loads(output)
        meta = data["scan_metadata"]
        assert meta["scan_id"]
        assert meta["tool_version"] == "0.1.0"
        assert meta["targets_scanned"] == 3
        assert meta["total_findings"] == 2

    def test_has_findings_section(
        self,
        result_with_findings: ScanResult
    ) -> None:
        reporter = JsonReporter()
        output = reporter.generate(result_with_findings)
        data = json.loads(output)
        findings = data["findings"]
        assert len(findings) == 2
        assert findings[0]["rule_id"] == "PII_SSN"
        assert findings[0]["severity"] == "critical"
        assert findings[0]["confidence"] == 0.95

    def test_finding_has_location(
        self,
        result_with_findings: ScanResult
    ) -> None:
        reporter = JsonReporter()
        output = reporter.generate(result_with_findings)
        data = json.loads(output)
        loc = data["findings"][0]["location"]
        assert loc["source_type"] == "file"
        assert loc["uri"] == "employees.csv"
        assert loc["line"] == 2

    def test_has_summary_section(
        self,
        result_with_findings: ScanResult
    ) -> None:
        reporter = JsonReporter()
        output = reporter.generate(result_with_findings)
        data = json.loads(output)
        summary = data["summary"]
        assert summary["by_severity"]["critical"] == 1
        assert summary["by_severity"]["medium"] == 1
        assert summary["by_rule"]["PII_SSN"] == 1
        assert summary["by_framework"]["HIPAA"] == 1

    def test_empty_result_has_zero_findings(
        self,
        empty_result: ScanResult
    ) -> None:
        reporter = JsonReporter()
        output = reporter.generate(empty_result)
        data = json.loads(output)
        assert len(data["findings"]) == 0
        assert (data["scan_metadata"]["total_findings"] == 0)

    def test_finding_has_remediation(
        self,
        result_with_findings: ScanResult
    ) -> None:
        reporter = JsonReporter()
        output = reporter.generate(result_with_findings)
        data = json.loads(output)
        assert (data["findings"][0]["remediation"] == "Encrypt SSN data")

    def test_finding_has_compliance(
        self,
        result_with_findings: ScanResult
    ) -> None:
        reporter = JsonReporter()
        output = reporter.generate(result_with_findings)
        data = json.loads(output)
        frameworks = data["findings"][0]["compliance_frameworks"]
        assert "HIPAA" in frameworks
        assert "CCPA" in frameworks
