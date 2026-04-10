"""
©AngelaMos | 2026
test_config.py
"""


from pathlib import Path

from dlp_scanner.config import ScanConfig, load_config
from dlp_scanner.constants import (
    DEFAULT_DB_SAMPLE_PERCENTAGE,
    DEFAULT_ENTROPY_THRESHOLD,
    DEFAULT_MAX_FILE_SIZE_MB,
    DEFAULT_MIN_CONFIDENCE,
)


class TestScanConfig:
    def test_defaults(self) -> None:
        config = ScanConfig()
        assert config.file.max_file_size_mb == DEFAULT_MAX_FILE_SIZE_MB
        assert config.file.recursive is True
        assert config.database.sample_percentage == DEFAULT_DB_SAMPLE_PERCENTAGE
        assert config.network.entropy_threshold == DEFAULT_ENTROPY_THRESHOLD
        assert config.detection.min_confidence == DEFAULT_MIN_CONFIDENCE
        assert config.output.format == "console"
        assert config.output.redaction_style == "partial"

    def test_exclude_patterns_populated(self) -> None:
        config = ScanConfig()
        assert "*.pyc" in config.file.exclude_patterns
        assert ".git" in config.file.exclude_patterns

    def test_include_extensions_populated(self) -> None:
        config = ScanConfig()
        assert ".pdf" in config.file.include_extensions
        assert ".csv" in config.file.include_extensions

    def test_default_frameworks(self) -> None:
        config = ScanConfig()
        assert "HIPAA" in config.compliance.frameworks
        assert "PCI_DSS" in config.compliance.frameworks


class TestLoadConfig:
    def test_load_missing_file_returns_defaults(self) -> None:
        config = load_config(Path("/nonexistent/config.yml"))
        assert config == ScanConfig()

    def test_load_none_returns_defaults(self) -> None:
        config = load_config(None)
        assert isinstance(config, ScanConfig)

    def test_load_yaml_config(self, tmp_path: Path) -> None:
        config_path = tmp_path / ".dlp-scanner.yml"
        config_path.write_text(
            "scan:\n"
            "  file:\n"
            "    max_file_size_mb: 50\n"
            "    recursive: false\n"
            "detection:\n"
            "  min_confidence: 0.5\n"
            "output:\n"
            "  format: json\n"
        )
        config = load_config(config_path)
        assert config.file.max_file_size_mb == 50
        assert config.file.recursive is False
        assert config.detection.min_confidence == 0.5
        assert config.output.format == "json"

    def test_load_partial_config_fills_defaults(
        self,
        tmp_path: Path
    ) -> None:
        config_path = tmp_path / ".dlp-scanner.yml"
        config_path.write_text("output:\n  format: sarif\n")
        config = load_config(config_path)
        assert config.output.format == "sarif"
        assert config.file.max_file_size_mb == DEFAULT_MAX_FILE_SIZE_MB
        assert config.detection.min_confidence == DEFAULT_MIN_CONFIDENCE
