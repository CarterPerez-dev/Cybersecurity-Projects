"""
©AngelaMos | 2026
console.py
"""


from rich.console import Console
from rich.table import Table

from dlp_scanner.constants import SEVERITY_COLORS
from dlp_scanner.models import ScanResult


TRUNCATE_SNIPPET: int = 60


class ConsoleReporter:
    """
    Rich console output with severity-colored tables
    """
    def __init__(
        self,
        console: Console | None = None,
    ) -> None:
        self._console = console or Console()

    def generate(self, result: ScanResult) -> str:
        """
        Generate plain-text table for piping
        """
        lines: list[str] = []
        lines.append(
            f"Scan {result.scan_id} | "
            f"{len(result.findings)} findings | "
            f"{result.targets_scanned} targets"
        )
        lines.append("")

        for finding in result.findings:
            loc = finding.location.uri
            if finding.location.line is not None:
                loc += f":{finding.location.line}"
            if finding.location.table_name:
                loc += (f" [{finding.location.table_name}]")

            snippet = finding.redacted_snippet
            if len(snippet) > TRUNCATE_SNIPPET:
                snippet = (snippet[: TRUNCATE_SNIPPET] + "...")

            frameworks = ", ".join(finding.compliance_frameworks)

            lines.append(
                f"[{finding.severity.upper()}] "
                f"{finding.rule_name} | "
                f"{loc} | "
                f"{finding.confidence:.0%} | "
                f"{snippet} | "
                f"{frameworks}"
            )

        lines.append("")
        lines.append(_format_summary(result))
        return "\n".join(lines)

    def display(self, result: ScanResult) -> None:
        """
        Print Rich-formatted table to console
        """
        self._console.print()

        if not result.findings:
            self._console.print("[green]No findings detected.[/green]")
            _print_summary(self._console, result)
            return

        table = Table(
            title = (
                f"DLP Scan Results "
                f"({len(result.findings)} findings)"
            ),
            show_lines = True,
        )

        table.add_column("Severity", width = 10, justify = "center")
        table.add_column("Rule", width = 25)
        table.add_column("Location", width = 30)
        table.add_column("Confidence", width = 10)
        table.add_column("Snippet", width = 40)
        table.add_column("Compliance", width = 20)

        for finding in result.findings:
            color = SEVERITY_COLORS.get(finding.severity, "white")

            loc = finding.location.uri
            if finding.location.line is not None:
                loc += f":{finding.location.line}"
            if finding.location.table_name:
                loc += (f"\n[{finding.location.table_name}]")

            snippet = finding.redacted_snippet
            if len(snippet) > TRUNCATE_SNIPPET:
                snippet = (snippet[: TRUNCATE_SNIPPET] + "...")

            frameworks = "\n".join(finding.compliance_frameworks)

            table.add_row(
                f"[{color}]{finding.severity.upper()}"
                f"[/{color}]",
                finding.rule_name,
                loc,
                f"{finding.confidence:.0%}",
                snippet,
                frameworks,
            )

        self._console.print(table)
        _print_summary(self._console, result)

        if result.errors:
            self._console.print()
            self._console.print(
                f"[yellow]{len(result.errors)} "
                f"error(s) during scan[/yellow]"
            )


def _format_summary(result: ScanResult) -> str:
    """
    Format summary statistics as plain text
    """
    by_sev = result.findings_by_severity
    parts: list[str] = []
    for sev in ("critical", "high", "medium", "low"):
        count = by_sev.get(sev, 0)
        if count > 0:
            parts.append(f"{sev}: {count}")

    summary = " | ".join(parts) if parts else "clean"
    return (
        f"Summary: {summary} "
        f"({result.targets_scanned} targets scanned)"
    )


def _print_summary(console: Console, result: ScanResult) -> None:
    """
    Print formatted summary using Rich
    """
    console.print()
    by_sev = result.findings_by_severity
    parts: list[str] = []
    for sev in ("critical", "high", "medium", "low"):
        count = by_sev.get(sev, 0)
        if count > 0:
            color = SEVERITY_COLORS.get(sev, "white")
            parts.append(f"[{color}]{sev}: {count}[/{color}]")

    summary = (" | ".join(parts) if parts else "[green]clean")
    console.print(
        f"Summary: {summary} "
        f"({result.targets_scanned} targets)"
    )
