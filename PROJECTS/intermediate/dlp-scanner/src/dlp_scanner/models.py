"""
©AngelaMos | 2026
models.py
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, UTC

from dlp_scanner.constants import Severity


@dataclass(frozen = True, slots = True)
class Location:
    """
    Where a finding was detected
    """
    source_type: str
    uri: str
    line: int | None = None
    column: int | None = None
    byte_offset: int | None = None
    table_name: str | None = None
    column_name: str | None = None
    sheet_name: str | None = None


@dataclass(slots = True)
class Finding:
    """
    A fully scored and classified detection result
    """
    finding_id: str = field(
        default_factory = lambda: uuid.uuid4().hex[: 12]
    )
    rule_id: str = ""
    rule_name: str = ""
    severity: Severity = "low"
    confidence: float = 0.0
    location: Location = field(
        default_factory = lambda: Location(
            source_type = "unknown",
            uri = "",)
    )
    redacted_snippet: str = ""
    compliance_frameworks: list[str] = field(default_factory = list)
    remediation: str = ""
    detected_at: datetime = field(
        default_factory = lambda: datetime.now(UTC)
    )


@dataclass(slots = True)
class ScanResult:
    """
    Aggregated results from a complete scan run
    """
    scan_id: str = field(default_factory = lambda: uuid.uuid4().hex[: 16])
    tool_version: str = "0.1.0"
    scan_started_at: datetime = field(
        default_factory = lambda: datetime.now(UTC)
    )
    scan_completed_at: datetime | None = None
    targets_scanned: int = 0
    findings: list[Finding] = field(default_factory = list)
    errors: list[str] = field(default_factory = list)

    @property
    def findings_by_severity(self) -> dict[str, int]:
        """
        Count findings grouped by severity level
        """
        counts: dict[str,
                     int] = {
                         "critical": 0,
                         "high": 0,
                         "medium": 0,
                         "low": 0,
                     }
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    @property
    def findings_by_rule(self) -> dict[str, int]:
        """
        Count findings grouped by rule ID
        """
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.rule_id] = counts.get(f.rule_id, 0) + 1
        return counts

    @property
    def findings_by_framework(self) -> dict[str, int]:
        """
        Count findings grouped by compliance framework
        """
        counts: dict[str, int] = {}
        for f in self.findings:
            for fw in f.compliance_frameworks:
                counts[fw] = counts.get(fw, 0) + 1
        return counts


@dataclass(frozen = True, slots = True)
class TextChunk:
    """
    A piece of extracted text with its source location
    """
    text: str
    location: Location
