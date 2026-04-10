"""
©AngelaMos | 2026
conftest.py
"""


import tempfile
from pathlib import Path
from collections.abc import Generator

import pytest

from dlp_scanner.config import ScanConfig
from dlp_scanner.models import Finding, Location


@pytest.fixture
def default_config() -> ScanConfig:
    """
    Provide a default ScanConfig instance
    """
    return ScanConfig()


@pytest.fixture
def sample_location() -> Location:
    """
    Provide a sample file location
    """
    return Location(
        source_type = "file",
        uri = "test/employees.csv",
        line = 42,
        column = 15,
    )


@pytest.fixture
def sample_finding(sample_location: Location) -> Finding:
    """
    Provide a sample finding
    """
    return Finding(
        rule_id = "PII_SSN",
        rule_name = "US Social Security Number",
        severity = "critical",
        confidence = 0.95,
        location = sample_location,
        redacted_snippet = "...SSN: ***-**-6789...",
        compliance_frameworks = ["HIPAA",
                                 "CCPA"],
        remediation = "Encrypt or remove SSN data",
    )


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """
    Provide a temporary directory for test files
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def temp_dir_with_pii(
    temp_dir: Path,
) -> Path:
    """
    Provide a temp directory containing files with known PII
    """
    csv_path = temp_dir / "employees.csv"
    csv_path.write_text(
        "name,ssn,email\n"
        "John Doe,123-45-6789,john@example.com\n"
        "Jane Smith,987-65-4321,jane@example.com\n"
    )

    txt_path = temp_dir / "clean.txt"
    txt_path.write_text("No sensitive data here at all.")

    json_path = temp_dir / "config.json"
    json_path.write_text(
        '{"api_key": "sk_live_abc123def456ghi789jkl012mno345"}\n'
    )

    return temp_dir
