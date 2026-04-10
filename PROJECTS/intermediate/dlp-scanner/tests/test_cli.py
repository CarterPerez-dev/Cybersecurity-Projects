"""
©AngelaMos | 2026
test_cli.py
"""


import json
import tempfile
from pathlib import Path
from collections.abc import Generator

import pytest
from typer.testing import CliRunner

from dlp_scanner.cli import app


runner = CliRunner()


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
def json_result_file() -> Generator[Path, None, None]:
    """
    Provide a JSON scan results file for report tests
    """
    data = {
        "scan_metadata": {
            "scan_id": "test-123",
            "tool_version": "0.1.0",
            "scan_started_at": ("2026-01-01T00:00:00+00:00"),
            "scan_completed_at": ("2026-01-01T00:01:00+00:00"),
            "targets_scanned": 1,
            "total_findings": 1,
            "errors": [],
        },
        "findings": [
            {
                "finding_id": "f-001",
                "rule_id": "PII_SSN",
                "rule_name": ("US Social Security Number"),
                "severity": "critical",
                "confidence": 0.95,
                "location": {
                    "source_type": "file",
                    "uri": "data.csv",
                    "line": 5,
                    "column": None,
                    "table_name": None,
                    "column_name": None,
                },
                "redacted_snippet": "***-**-6789",
                "compliance_frameworks": [
                    "HIPAA",
                    "CCPA",
                ],
                "remediation": "Encrypt data",
                "detected_at": ("2026-01-01T00:00:30+00:00"),
            }
        ],
        "summary": {
            "by_severity": {
                "critical": 1
            },
            "by_rule": {
                "PII_SSN": 1
            },
            "by_framework": {
                "HIPAA": 1,
                "CCPA": 1,
            },
        },
    }

    with tempfile.NamedTemporaryFile(
            suffix = ".json",
            delete = False,
            mode = "w",
    ) as f:
        json.dump(data, f)
        path = Path(f.name)

    yield path
    path.unlink(missing_ok = True)


class TestCliHelp:
    def test_help_shows_commands(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "file" in result.output
        assert "db" in result.output
        assert "network" in result.output
        assert "report" in result.output

    def test_version(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_file_help(self) -> None:
        result = runner.invoke(app, ["file", "--help"])
        assert result.exit_code == 0
        assert "TARGET" in result.output

    def test_db_help(self) -> None:
        result = runner.invoke(app, ["db", "--help"])
        assert result.exit_code == 0
        assert "TARGET" in result.output

    def test_network_help(self) -> None:
        result = runner.invoke(app, ["network", "--help"])
        assert result.exit_code == 0
        assert "TARGET" in result.output

    def test_report_help(self) -> None:
        result = runner.invoke(app, ["report", "--help"])
        assert result.exit_code == 0
        assert "convert" in result.output
        assert "summary" in result.output


class TestFileScan:
    def test_scan_console_output(self, pii_dir: Path) -> None:
        result = runner.invoke(app, ["file", str(pii_dir)])
        assert result.exit_code == 0

    def test_scan_json_output(self, pii_dir: Path) -> None:
        result = runner.invoke(
            app,
            ["file",
             str(pii_dir),
             "-f",
             "json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "findings" in data

    def test_scan_to_file(self, pii_dir: Path) -> None:
        with tempfile.NamedTemporaryFile(suffix = ".json",
                                         delete = False) as f:
            out_path = f.name

        result = runner.invoke(
            app,
            [
                "file",
                str(pii_dir),
                "-f",
                "json",
                "-o",
                out_path,
            ],
        )
        assert "Report written" in result.output
        content = Path(out_path).read_text()
        assert "findings" in content
        Path(out_path).unlink(missing_ok = True)

    def test_scan_nonexistent_target(self) -> None:
        result = runner.invoke(app, ["file", "/no/such/path"])
        assert result.exit_code == 1

    def test_invalid_format(self, pii_dir: Path) -> None:
        result = runner.invoke(
            app,
            [
                "file",
                str(pii_dir),
                "-f",
                "invalid",
            ],
        )
        assert result.exit_code == 1

    def test_with_config_flag(self, pii_dir: Path) -> None:
        result = runner.invoke(
            app,
            [
                "--config",
                "nonexistent.yml",
                "file",
                str(pii_dir),
            ],
        )
        assert result.exit_code == 0

    def test_with_verbose_flag(self, pii_dir: Path) -> None:
        result = runner.invoke(
            app,
            ["--verbose",
             "file",
             str(pii_dir)],
        )
        assert result.exit_code == 0


class TestReportCommands:
    def test_convert_to_sarif(self, json_result_file: Path) -> None:
        result = runner.invoke(
            app,
            [
                "report",
                "convert",
                str(json_result_file),
                "-f",
                "sarif",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["version"] == "2.1.0"

    def test_convert_to_csv(self, json_result_file: Path) -> None:
        result = runner.invoke(
            app,
            [
                "report",
                "convert",
                str(json_result_file),
                "-f",
                "csv",
            ],
        )
        assert result.exit_code == 0
        assert "PII_SSN" in result.output

    def test_convert_to_file(self, json_result_file: Path) -> None:
        with tempfile.NamedTemporaryFile(suffix = ".sarif",
                                         delete = False) as f:
            out_path = f.name

        result = runner.invoke(
            app,
            [
                "report",
                "convert",
                str(json_result_file),
                "-f",
                "sarif",
                "-o",
                out_path,
            ],
        )
        assert result.exit_code == 0
        assert "Converted" in result.output
        content = Path(out_path).read_text()
        data = json.loads(content)
        assert data["version"] == "2.1.0"
        Path(out_path).unlink(missing_ok = True)

    def test_convert_missing_file(self) -> None:
        result = runner.invoke(
            app,
            [
                "report",
                "convert",
                "/no/such/file.json",
            ],
        )
        assert result.exit_code == 1

    def test_convert_invalid_format(self, json_result_file: Path) -> None:
        result = runner.invoke(
            app,
            [
                "report",
                "convert",
                str(json_result_file),
                "-f",
                "invalid",
            ],
        )
        assert result.exit_code == 1

    def test_summary(self, json_result_file: Path) -> None:
        result = runner.invoke(
            app,
            [
                "report",
                "summary",
                str(json_result_file),
            ],
        )
        assert result.exit_code == 0

    def test_summary_missing_file(self) -> None:
        result = runner.invoke(
            app,
            [
                "report",
                "summary",
                "/no/such/file.json",
            ],
        )
        assert result.exit_code == 1
