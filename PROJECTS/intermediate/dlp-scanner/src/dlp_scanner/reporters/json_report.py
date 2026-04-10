"""
©AngelaMos | 2026
json_report.py
"""


from typing import Any

import orjson

from dlp_scanner.models import ScanResult


class JsonReporter:
    """
    Structured JSON report with metadata and summary
    """
    def generate(self, result: ScanResult) -> str:
        """
        Generate JSON report as a formatted string
        """
        report = _build_report(result)
        return orjson.dumps(
            report,
            option = (orjson.OPT_INDENT_2
                      | orjson.OPT_NON_STR_KEYS),
        ).decode("utf-8")


def _build_report(
    result: ScanResult,
) -> dict[str,
          Any]:
    """
    Build the complete report structure
    """
    return {
        "scan_metadata": _build_metadata(result),
        "findings": [_serialize_finding(f) for f in result.findings],
        "summary": _build_summary(result),
    }


def _build_metadata(
    result: ScanResult,
) -> dict[str,
          Any]:
    """
    Build scan metadata section
    """
    return {
        "scan_id":
        result.scan_id,
        "tool_version":
        result.tool_version,
        "scan_started_at": (result.scan_started_at.isoformat()),
        "scan_completed_at": (
            result.scan_completed_at.isoformat()
            if result.scan_completed_at else None
        ),
        "targets_scanned":
        result.targets_scanned,
        "total_findings":
        len(result.findings),
        "errors":
        result.errors,
    }


def _serialize_finding(
    finding: Any,
) -> dict[str,
          Any]:
    """
    Serialize a single finding to dict
    """
    return {
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
        "rule_name": finding.rule_name,
        "severity": finding.severity,
        "confidence": round(finding.confidence,
                            4),
        "location": {
            "source_type": (finding.location.source_type),
            "uri": finding.location.uri,
            "line": finding.location.line,
            "column": finding.location.column,
            "table_name": (finding.location.table_name),
            "column_name": (finding.location.column_name),
        },
        "redacted_snippet": (finding.redacted_snippet),
        "compliance_frameworks": (finding.compliance_frameworks),
        "remediation": finding.remediation,
        "detected_at": (finding.detected_at.isoformat()),
    }


def _build_summary(
    result: ScanResult,
) -> dict[str,
          Any]:
    """
    Build summary statistics section
    """
    return {
        "by_severity": result.findings_by_severity,
        "by_rule": result.findings_by_rule,
        "by_framework": result.findings_by_framework,
    }
