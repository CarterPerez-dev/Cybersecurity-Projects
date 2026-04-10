"""
©AngelaMos | 2026
engine.py
"""


import structlog

from dlp_scanner.config import ScanConfig
from dlp_scanner.constants import OutputFormat
from dlp_scanner.detectors.registry import (
    DetectorRegistry,
)
from dlp_scanner.models import ScanResult
from dlp_scanner.reporters.console import (
    ConsoleReporter,
)
from dlp_scanner.reporters.csv_report import (
    CsvReporter,
)
from dlp_scanner.reporters.json_report import (
    JsonReporter,
)
from dlp_scanner.reporters.sarif import SarifReporter
from dlp_scanner.scanners.db_scanner import (
    DatabaseScanner,
)
from dlp_scanner.scanners.file_scanner import (
    FileScanner,
)
from dlp_scanner.scanners.network_scanner import (
    NetworkScanner,
)


log = structlog.get_logger()

REPORTER_MAP: dict[str,
                   type] = {
                       "console": ConsoleReporter,
                       "json": JsonReporter,
                       "sarif": SarifReporter,
                       "csv": CsvReporter,
                   }


class ScanEngine:
    """
    Orchestrates the full scan pipeline
    """
    def __init__(self, config: ScanConfig) -> None:
        self._config = config
        detection = config.detection
        allowlist_vals = detection.allowlists.values
        self._registry = DetectorRegistry(
            enable_patterns = detection.enable_rules,
            disable_patterns = detection.disable_rules,
            allowlist_values = (
                frozenset(allowlist_vals) if allowlist_vals else None
            ),
            context_window_tokens = (detection.context_window_tokens),
        )

    def scan_files(self, target: str) -> ScanResult:
        """
        Scan filesystem target for sensitive data
        """
        scanner = FileScanner(self._config, self._registry)
        result = scanner.scan(target)
        log.info(
            "file_scan_complete",
            target = target,
            findings = len(result.findings),
            targets = result.targets_scanned,
        )
        return result

    def scan_database(self, target: str) -> ScanResult:
        """
        Scan database target for sensitive data
        """
        scanner = DatabaseScanner(self._config, self._registry)
        result = scanner.scan(target)
        log.info(
            "database_scan_complete",
            target = target,
            findings = len(result.findings),
            targets = result.targets_scanned,
        )
        return result

    def scan_network(self, target: str) -> ScanResult:
        """
        Scan network capture file for sensitive data
        """
        scanner = NetworkScanner(self._config, self._registry)
        result = scanner.scan(target)
        log.info(
            "network_scan_complete",
            target = target,
            findings = len(result.findings),
            targets = result.targets_scanned,
        )
        return result

    def generate_report(
        self,
        result: ScanResult,
        output_format: OutputFormat | None = None,
    ) -> str:
        """
        Generate report string in the requested format
        """
        fmt = output_format or self._config.output.format
        reporter_cls = REPORTER_MAP[fmt]
        reporter = reporter_cls()
        output: str = reporter.generate(result)
        return output

    def display_console(
        self,
        result: ScanResult,
    ) -> None:
        """
        Display Rich-formatted results to console
        """
        reporter = ConsoleReporter()
        reporter.display(result)

    def write_report(
        self,
        result: ScanResult,
        output_path: str,
        output_format: OutputFormat | None = None,
    ) -> None:
        """
        Generate report and write to file
        """
        content = self.generate_report(result, output_format)
        with open(output_path, "w") as f:
            f.write(content)
        log.info(
            "report_written",
            path = output_path,
            format = output_format or self._config.output.format,
        )
