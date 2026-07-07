"""
output.py

Turns decoded tokens and audit reports into console tables or JSON.

The rendering lives here so the checks stay pure data. Colors map to
severity the way you would expect: red for critical, yellow for medium,
dim for info. The JSON builders return plain dicts so the CLI can dump
them and so tests can assert on structure without scraping terminal text.

Key exports:
  decoded_to_dict - JSON friendly view of a DecodedToken
  report_to_dict - JSON friendly view of an AuditReport
  render_decoded - print a decoded token to a Rich console
  render_report - print an audit report to a Rich console

Connects to:
  main.py - the CLI calls these to display results
  models.py - reads AuditReport and Finding
  decoder.py - reads DecodedToken
"""

import json
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from jwt_auditor.decoder import DecodedToken
from jwt_auditor.models import AuditReport, Finding, Severity


_SEVERITY_STYLE: dict[Severity,
                      str] = {
                          Severity.CRITICAL: "bold red",
                          Severity.HIGH: "red",
                          Severity.MEDIUM: "yellow",
                          Severity.LOW: "cyan",
                          Severity.INFO: "dim",
                      }


def decoded_to_dict(token: DecodedToken) -> dict[str, Any]:
    """Build a JSON friendly representation of a decoded token."""
    return {
        "header": token.header,
        "payload": token.payload,
        "signature": {
            "algorithm": token.algorithm,
            "present": bool(token.signature),
            "length_bytes": len(token.signature),
            "value_base64url": token.signature_b64,
        },
    }


def report_to_dict(report: AuditReport) -> dict[str, Any]:
    """Build a JSON friendly representation of an audit report."""
    counts = {
        severity.label: count
        for severity, count in report.counts_by_severity().items()
    }
    highest = report.highest_severity
    return {
        "algorithm": report.token.algorithm,
        "risk_score": report.risk_score,
        "highest_severity": highest.label if highest else "none",
        "finding_counts": counts,
        "findings": [_finding_to_dict(f) for f in report.sorted_findings],
        "decoded": decoded_to_dict(report.token),
    }


def _finding_to_dict(finding: Finding) -> dict[str, Any]:
    """Serialize one finding to a plain dict."""
    return {
        "id": finding.check_id,
        "title": finding.title,
        "severity": finding.severity.label,
        "detail": finding.detail,
        "evidence": finding.evidence,
        "recommendation": finding.recommendation,
    }


def _pretty_json(value: dict[str, Any]) -> str:
    """Format a dict as indented JSON for display."""
    return json.dumps(value, indent = 2, sort_keys = False, default = str)


def render_decoded(console: Console, token: DecodedToken) -> None:
    """Print the decoded header, payload, and signature summary."""
    console.print(
        Panel(
            _pretty_json(token.header),
            title = "Header",
            border_style = "cyan",
            expand = False,
        )
    )
    console.print(
        Panel(
            _pretty_json(token.payload),
            title = "Payload",
            border_style = "green",
            expand = False,
        )
    )
    sig_summary = (
        f"algorithm : {token.algorithm or '(none declared)'}\n"
        f"present   : {bool(token.signature)}\n"
        f"bytes     : {len(token.signature)}"
    )
    console.print(
        Panel(
            sig_summary,
            title = "Signature",
            border_style = "magenta",
            expand = False
        )
    )


def render_report(console: Console, report: AuditReport) -> None:
    """Print the risk summary panel and the findings table."""
    console.print(_summary_panel(report))

    if not report.findings:
        console.print("[green]No issues found by the checks that ran.[/green]")
        return

    table = Table(title = "Findings", show_lines = True, expand = False)
    table.add_column("Severity", justify = "left", no_wrap = True)
    table.add_column("Issue", justify = "left")
    table.add_column("Evidence", justify = "left", overflow = "fold")

    for finding in report.sorted_findings:
        style = _SEVERITY_STYLE[finding.severity]
        severity_cell = Text(finding.severity.label.upper(), style = style)
        issue_cell = Text(finding.title)
        issue_cell.append(f"\n{finding.detail}", style = "dim")
        if finding.recommendation:
            issue_cell.append(
                f"\nFix: {finding.recommendation}",
                style = "italic"
            )
        table.add_row(severity_cell, issue_cell, finding.evidence or "-")

    console.print(table)


def _summary_panel(report: AuditReport) -> Panel:
    """Build the top panel with algorithm, risk score, and counts."""
    highest = report.highest_severity
    score_style = _SEVERITY_STYLE.get(highest, "green") if highest else "green"
    lines = [
        f"algorithm    : {report.token.algorithm or '(none declared)'}",
        f"risk score   : {report.risk_score} / 10",
        f"worst finding: {highest.label if highest else 'none'}",
        "",
    ]
    counts = report.counts_by_severity()
    for severity in Severity:
        lines.append(f"{severity.label:>8} : {counts[severity]}")
    body = Text("\n".join(lines), style = score_style)
    return Panel(
        body,
        title = "JWT Audit Summary",
        border_style = score_style,
        expand = False
    )
