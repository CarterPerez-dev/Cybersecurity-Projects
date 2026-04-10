"""
©AngelaMos | 2026
csv_report.py
"""


import csv
import io

from dlp_scanner.models import ScanResult


CSV_COLUMNS: list[str] = [
    "finding_id",
    "scan_date",
    "severity",
    "confidence",
    "rule_id",
    "rule_name",
    "source_type",
    "uri",
    "line",
    "column",
    "table_name",
    "redacted_snippet",
    "compliance_frameworks",
    "remediation",
]


class CsvReporter:
    """
    CSV export for compliance team consumption
    """
    def generate(self, result: ScanResult) -> str:
        """
        Generate CSV report as a string
        """
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(CSV_COLUMNS)

        for finding in result.findings:
            frameworks = ";".join(finding.compliance_frameworks)
            writer.writerow(
                [
                    finding.finding_id,
                    finding.detected_at.isoformat(),
                    finding.severity,
                    f"{finding.confidence:.4f}",
                    finding.rule_id,
                    finding.rule_name,
                    finding.location.source_type,
                    finding.location.uri,
                    finding.location.line or "",
                    finding.location.column or "",
                    finding.location.table_name or "",
                    finding.redacted_snippet,
                    frameworks,
                    finding.remediation,
                ]
            )

        return output.getvalue()
