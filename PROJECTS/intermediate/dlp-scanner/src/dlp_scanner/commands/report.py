"""
©AngelaMos | 2026
report.py
"""


from datetime import datetime
from pathlib import Path
from typing import Annotated, Any

import orjson
import typer

from dlp_scanner.models import (
    Finding,
    Location,
    ScanResult,
)


report_app = typer.Typer(help = "Report conversion and summary")

VALID_FORMATS: frozenset[str] = frozenset(
    {
        "console",
        "json",
        "sarif",
        "csv",
    }
)


@report_app.command("convert")
def convert(
    input_file: Annotated[
        str,
        typer.Argument(help = "JSON scan results file"),
    ],
    output_format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help = "Target format (json, sarif, csv)",
        ),
    ] = "sarif",
    output_file: Annotated[
        str,
        typer.Option(
            "--output",
            "-o",
            help = "Write converted report to file",
        ),
    ] = "",
) -> None:
    """
    Convert a JSON scan result to another format
    """
    from dlp_scanner.config import ScanConfig
    from dlp_scanner.engine import ScanEngine

    if output_format not in VALID_FORMATS:
        typer.echo(
            f"Invalid format: {output_format}",
            err = True,
        )
        raise typer.Exit(code = 1)

    path = Path(input_file)
    if not path.exists():
        typer.echo(
            f"File not found: {input_file}",
            err = True,
        )
        raise typer.Exit(code = 1)

    raw = path.read_bytes()
    data = orjson.loads(raw)
    result = _rebuild_result(data)

    config = ScanConfig()
    engine = ScanEngine(config)

    output = engine.generate_report(result, output_format)

    if output_file:
        Path(output_file).write_text(output)
        typer.echo(f"Converted report written to "
                   f"{output_file}")
    else:
        typer.echo(output)


@report_app.command("summary")
def summary(
    input_file: Annotated[
        str,
        typer.Argument(help = "JSON scan results file"),
    ],
) -> None:
    """
    Print summary statistics from a scan result file
    """
    path = Path(input_file)
    if not path.exists():
        typer.echo(
            f"File not found: {input_file}",
            err = True,
        )
        raise typer.Exit(code = 1)

    raw = path.read_bytes()
    data = orjson.loads(raw)
    result = _rebuild_result(data)

    from dlp_scanner.reporters.console import (
        ConsoleReporter,
    )

    reporter = ConsoleReporter()
    reporter.display(result)


def _rebuild_result(
    data: dict[str,
               Any],
) -> ScanResult:
    """
    Rebuild a ScanResult from deserialized JSON report
    """
    meta = data.get("scan_metadata", {})
    result = ScanResult(
        targets_scanned = meta.get("targets_scanned",
                                   0),
    )
    result.scan_id = meta.get("scan_id", result.scan_id)

    if meta.get("scan_completed_at"):
        result.scan_completed_at = (
            datetime.fromisoformat(meta["scan_completed_at"])
        )

    result.errors = meta.get("errors", [])

    for f_data in data.get("findings", []):
        loc_data = f_data.get("location", {})
        location = Location(
            source_type = loc_data.get("source_type",
                                       "file"),
            uri = loc_data.get("uri",
                               ""),
            line = loc_data.get("line"),
            column = loc_data.get("column"),
            table_name = loc_data.get("table_name"),
            column_name = loc_data.get("column_name"),
        )

        finding = Finding(
            rule_id = f_data.get("rule_id",
                                 ""),
            rule_name = f_data.get("rule_name",
                                   ""),
            severity = f_data.get("severity",
                                  "low"),
            confidence = f_data.get("confidence",
                                    0.0),
            location = location,
            redacted_snippet = f_data.get("redacted_snippet",
                                          ""),
            compliance_frameworks = f_data.get(
                "compliance_frameworks",
                []
            ),
            remediation = f_data.get("remediation",
                                     ""),
        )

        if f_data.get("finding_id"):
            finding.finding_id = f_data["finding_id"]
        if f_data.get("detected_at"):
            finding.detected_at = (
                datetime.fromisoformat(f_data["detected_at"])
            )

        result.findings.append(finding)

    return result
