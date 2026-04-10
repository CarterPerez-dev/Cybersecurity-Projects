"""
©AngelaMos | 2026
test_engine.py
"""


import json
import tempfile
from pathlib import Path
from collections.abc import Generator

import pytest

from dlp_scanner.config import ScanConfig
from dlp_scanner.engine import ScanEngine
from dlp_scanner.models import (
    Finding,
    Location,
    ScanResult,
)


@pytest.fixture
def engine() -> ScanEngine:
    """
    Provide a ScanEngine with default config
    """
    return ScanEngine(ScanConfig())


@pytest.fixture
def pii_dir() -> Generator[Path, None, None]:
    """
    Provide a temp directory with valid detectable SSNs
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        csv_path = root / "employees.csv"
        csv_path.write_text(
            "name,ssn\n"
            "Alice,456-78-9012\n"
            "Bob,234-56-7890\n"
        )
        yield root


@pytest.fixture
def clean_dir() -> Generator[Path, None, None]:
    """
    Provide a temp directory with no sensitive data
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        txt_path = root / "readme.txt"
        txt_path.write_text("This file contains no sensitive data.")
        yield root


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
            compliance_frameworks = ["HIPAA",
                                     "CCPA"],
            remediation = "Encrypt data",
        ),
    ]
    return result


class TestScanEngine:
    def test_scan_files_finds_pii(
        self,
        engine: ScanEngine,
        pii_dir: Path
    ) -> None:
        result = engine.scan_files(str(pii_dir))
        assert len(result.findings) > 0

    def test_scan_files_clean_dir(
        self,
        engine: ScanEngine,
        clean_dir: Path
    ) -> None:
        result = engine.scan_files(str(clean_dir))
        assert len(result.findings) == 0

    def test_scan_files_nonexistent(self, engine: ScanEngine) -> None:
        result = engine.scan_files("/no/such/path")
        assert len(result.errors) > 0

    def test_scan_files_sets_completed_at(
        self,
        engine: ScanEngine,
        pii_dir: Path
    ) -> None:
        result = engine.scan_files(str(pii_dir))
        assert result.scan_completed_at is not None

    def test_scan_database_sqlite(self, engine: ScanEngine) -> None:
        with tempfile.NamedTemporaryFile(suffix = ".db",
                                         delete = False) as f:
            db_path = f.name

        import sqlite3

        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE users "
                     "(name TEXT, ssn TEXT)")
        conn.execute(
            "INSERT INTO users VALUES "
            "('Alice', '456-78-9012')"
        )
        conn.commit()
        conn.close()

        uri = f"sqlite:///{db_path}"
        result = engine.scan_database(uri)
        assert len(result.findings) > 0

        Path(db_path).unlink(missing_ok = True)

    def test_generate_report_json(
        self,
        engine: ScanEngine,
        result_with_findings: ScanResult,
    ) -> None:
        output = engine.generate_report(result_with_findings, "json")
        data = json.loads(output)
        assert "findings" in data
        assert len(data["findings"]) == 1

    def test_generate_report_sarif(
        self,
        engine: ScanEngine,
        result_with_findings: ScanResult,
    ) -> None:
        output = engine.generate_report(result_with_findings, "sarif")
        data = json.loads(output)
        assert data["version"] == "2.1.0"

    def test_generate_report_csv(
        self,
        engine: ScanEngine,
        result_with_findings: ScanResult,
    ) -> None:
        output = engine.generate_report(result_with_findings, "csv")
        lines = output.strip().split("\n")
        assert len(lines) == 2

    def test_generate_report_console(
        self,
        engine: ScanEngine,
        result_with_findings: ScanResult,
    ) -> None:
        output = engine.generate_report(result_with_findings, "console")
        assert "PII_SSN" in output or "Social" in output

    def test_generate_report_uses_config_default(
        self,
        result_with_findings: ScanResult,
    ) -> None:
        config = ScanConfig()
        config.output.format = "json"
        engine = ScanEngine(config)
        output = engine.generate_report(result_with_findings)
        data = json.loads(output)
        assert "findings" in data

    def test_display_console(
        self,
        engine: ScanEngine,
        result_with_findings: ScanResult,
    ) -> None:
        engine.display_console(result_with_findings)

    def test_write_report(
        self,
        engine: ScanEngine,
        result_with_findings: ScanResult,
    ) -> None:
        with tempfile.NamedTemporaryFile(
                suffix = ".json",
                delete = False,
                mode = "w",
        ) as f:
            output_path = f.name

        engine.write_report(
            result_with_findings,
            output_path,
            "json",
        )
        content = Path(output_path).read_text()
        data = json.loads(content)
        assert len(data["findings"]) == 1

        Path(output_path).unlink(missing_ok = True)


class TestReporterMap:
    def test_all_formats_have_reporters(self) -> None:
        from dlp_scanner.engine import REPORTER_MAP

        expected = {"console", "json", "sarif", "csv"}
        assert set(REPORTER_MAP.keys()) == expected
