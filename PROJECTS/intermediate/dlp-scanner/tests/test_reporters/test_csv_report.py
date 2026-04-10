"""
©AngelaMos | 2026
test_csv_report.py
"""


import csv
import io

import pytest

from dlp_scanner.models import (
    Finding,
    Location,
    ScanResult,
)
from dlp_scanner.reporters.csv_report import (
    CSV_COLUMNS,
    CsvReporter,
)


@pytest.fixture
def result_with_findings() -> ScanResult:
    """
    Provide a ScanResult with test findings
    """
    result = ScanResult(targets_scanned = 1)
    result.findings = [
        Finding(
            rule_id = "PII_SSN",
            rule_name = "US Social Security Number",
            severity = "critical",
            confidence = 0.95,
            location = Location(
                source_type = "file",
                uri = "data.csv",
                line = 5,
            ),
            redacted_snippet = "***-**-6789",
            compliance_frameworks = [
                "HIPAA",
                "CCPA",
            ],
            remediation = "Encrypt data",
        ),
    ]
    return result


class TestCsvReporter:
    def test_generates_valid_csv(
        self,
        result_with_findings: ScanResult
    ) -> None:
        reporter = CsvReporter()
        output = reporter.generate(result_with_findings)
        reader = csv.reader(io.StringIO(output))
        rows = list(reader)
        assert len(rows) == 2

    def test_header_matches_columns(
        self,
        result_with_findings: ScanResult
    ) -> None:
        reporter = CsvReporter()
        output = reporter.generate(result_with_findings)
        reader = csv.reader(io.StringIO(output))
        header = next(reader)
        assert header == CSV_COLUMNS

    def test_finding_row_data(
        self,
        result_with_findings: ScanResult
    ) -> None:
        reporter = CsvReporter()
        output = reporter.generate(result_with_findings)
        reader = csv.reader(io.StringIO(output))
        next(reader)
        row = next(reader)
        assert row[2] == "critical"
        assert row[4] == "PII_SSN"
        assert row[7] == "data.csv"
        assert "HIPAA" in row[12]
        assert "CCPA" in row[12]

    def test_empty_result(self) -> None:
        reporter = CsvReporter()
        result = ScanResult()
        output = reporter.generate(result)
        reader = csv.reader(io.StringIO(output))
        rows = list(reader)
        assert len(rows) == 1

    def test_frameworks_semicolon_separated(
        self,
        result_with_findings: ScanResult
    ) -> None:
        reporter = CsvReporter()
        output = reporter.generate(result_with_findings)
        reader = csv.reader(io.StringIO(output))
        next(reader)
        row = next(reader)
        assert row[12] == "HIPAA;CCPA"
