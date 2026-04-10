"""
©AngelaMos | 2026
test_file_scanner.py
"""


from pathlib import Path

import pytest

from dlp_scanner.config import ScanConfig
from dlp_scanner.detectors.registry import DetectorRegistry
from dlp_scanner.scanners.file_scanner import (
    FileScanner,
    _build_extension_map,
    _get_full_suffix,
)


@pytest.fixture
def file_scanner() -> FileScanner:
    """
    Provide a default FileScanner instance
    """
    config = ScanConfig()
    registry = DetectorRegistry()
    return FileScanner(config = config, registry = registry)


class TestFileScanner:
    def test_scan_directory_finds_pii(
        self,
        file_scanner: FileScanner,
        temp_dir_with_pii: Path,
    ) -> None:
        result = file_scanner.scan(str(temp_dir_with_pii))
        assert result.targets_scanned > 0
        assert len(result.findings) > 0

    def test_scan_single_file(
        self,
        file_scanner: FileScanner,
        temp_dir_with_pii: Path,
    ) -> None:
        csv_path = temp_dir_with_pii / "employees.csv"
        result = file_scanner.scan(str(csv_path))
        assert result.targets_scanned == 1
        assert len(result.findings) > 0

    def test_scan_clean_file_no_findings(
        self,
        file_scanner: FileScanner,
        temp_dir_with_pii: Path,
    ) -> None:
        txt_path = temp_dir_with_pii / "clean.txt"
        result = file_scanner.scan(str(txt_path))
        assert result.targets_scanned == 1
        assert len(result.findings) == 0

    def test_scan_nonexistent_target(
        self,
        file_scanner: FileScanner,
    ) -> None:
        result = file_scanner.scan("/nonexistent/path")
        assert len(result.errors) > 0

    def test_scan_empty_directory(
        self,
        file_scanner: FileScanner,
        temp_dir: Path,
    ) -> None:
        result = file_scanner.scan(str(temp_dir))
        assert result.targets_scanned == 0
        assert len(result.findings) == 0

    def test_scan_respects_exclude_patterns(
        self,
        temp_dir: Path,
    ) -> None:
        secret = temp_dir / "secret.log"
        secret.write_text("SSN: 123-45-6789")

        config = ScanConfig()
        config.file.exclude_patterns = ["*.log"]
        registry = DetectorRegistry()
        scanner = FileScanner(config = config, registry = registry)

        result = scanner.scan(str(temp_dir))
        assert result.targets_scanned == 0

    def test_scan_respects_max_file_size(
        self,
        temp_dir: Path,
    ) -> None:
        large = temp_dir / "large.txt"
        large.write_text("SSN: 123-45-6789\n" * 100)

        config = ScanConfig()
        config.file.max_file_size_mb = 0
        registry = DetectorRegistry()
        scanner = FileScanner(config = config, registry = registry)

        result = scanner.scan(str(temp_dir))
        assert result.targets_scanned == 0

    def test_scan_completed_at_is_set(
        self,
        file_scanner: FileScanner,
        temp_dir: Path,
    ) -> None:
        result = file_scanner.scan(str(temp_dir))
        assert result.scan_completed_at is not None

    def test_findings_have_compliance_frameworks(
        self,
        file_scanner: FileScanner,
        temp_dir_with_pii: Path,
    ) -> None:
        result = file_scanner.scan(str(temp_dir_with_pii))
        ssn_findings = [
            f for f in result.findings if f.rule_id == "PII_SSN"
        ]
        for finding in ssn_findings:
            assert len(finding.compliance_frameworks) > 0

    def test_findings_have_redacted_snippets(
        self,
        file_scanner: FileScanner,
        temp_dir_with_pii: Path,
    ) -> None:
        result = file_scanner.scan(str(temp_dir_with_pii))
        for finding in result.findings:
            assert finding.redacted_snippet

    def test_findings_have_severity(
        self,
        file_scanner: FileScanner,
        temp_dir_with_pii: Path,
    ) -> None:
        result = file_scanner.scan(str(temp_dir_with_pii))
        valid_severities = {
            "critical",
            "high",
            "medium",
            "low",
        }
        for finding in result.findings:
            assert finding.severity in valid_severities

    def test_scan_json_finds_api_key(
        self,
        file_scanner: FileScanner,
        temp_dir_with_pii: Path,
    ) -> None:
        result = file_scanner.scan(str(temp_dir_with_pii))
        cred_findings = [
            f for f in result.findings if f.rule_id.startswith("CRED_")
        ]
        assert len(cred_findings) > 0


class TestExtensionMap:
    def test_has_common_text_types(self) -> None:
        ext_map = _build_extension_map()
        assert ".txt" in ext_map
        assert ".csv" in ext_map
        assert ".json" in ext_map
        assert ".xml" in ext_map
        assert ".yaml" in ext_map

    def test_has_office_types(self) -> None:
        ext_map = _build_extension_map()
        assert ".pdf" in ext_map
        assert ".docx" in ext_map
        assert ".xlsx" in ext_map
        assert ".xls" in ext_map

    def test_has_archive_types(self) -> None:
        ext_map = _build_extension_map()
        assert ".zip" in ext_map
        assert ".tar" in ext_map
        assert ".tar.gz" in ext_map

    def test_has_email_types(self) -> None:
        ext_map = _build_extension_map()
        assert ".eml" in ext_map
        assert ".msg" in ext_map


class TestGetFullSuffix:
    def test_simple_extension(self) -> None:
        assert _get_full_suffix(Path("f.txt")) == ".txt"

    def test_tar_gz(self) -> None:
        path = Path("archive.tar.gz")
        assert _get_full_suffix(path) == ".tar.gz"

    def test_tar_bz2(self) -> None:
        path = Path("archive.tar.bz2")
        assert _get_full_suffix(path) == ".tar.bz2"

    def test_uppercase_normalized(self) -> None:
        assert _get_full_suffix(Path("F.TXT")) == ".txt"

    def test_no_extension(self) -> None:
        assert _get_full_suffix(Path("Makefile")) == ""

    def test_dotfile(self) -> None:
        result = _get_full_suffix(Path(".gitignore"))
        assert result == ""
