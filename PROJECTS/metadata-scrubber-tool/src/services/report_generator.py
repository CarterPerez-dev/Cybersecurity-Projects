"""
Report generator for metadata comparison and verification.

This module provides the ReportGenerator class which compares before/after
metadata states and generates rich table output showing what was removed,
preserved, or unchanged.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from rich.console import Console
from rich.table import Table


class PropertyStatus(Enum):
    """Status of a metadata property after scrubbing."""

    REMOVED = "removed"  # Was present, now None/empty
    PRESERVED = "preserved"  # Intentionally kept (created, modified, etc.)
    UNCHANGED = "unchanged"  # Had no value before and after
    WARNING = "warning"  # Should have been removed but wasn't


class VerificationStatus(Enum):
    """Overall verification status of a scrubbed file."""

    CLEAN = "clean"  # All sensitive metadata removed
    WARNING = "warning"  # Some metadata may still be present
    ERROR = "error"  # Verification failed


@dataclass
class PropertyComparison:
    """Comparison result for a single metadata property."""

    name: str
    before_value: Any
    after_value: Any
    status: PropertyStatus
    is_sensitive: bool = True  # Whether this property is considered sensitive


@dataclass
class ComparisonReport:
    """Complete comparison report between original and processed files."""

    original_file: str
    processed_file: str
    comparisons: list[PropertyComparison] = field(default_factory = list)
    status: VerificationStatus = VerificationStatus.CLEAN
    removed_count: int = 0
    preserved_count: int = 0
    warning_count: int = 0


class ReportGenerator:
    """
    Generates before/after metadata comparison reports.

    Compares metadata from original and processed files to verify
    that sensitive information has been properly removed.
    """

    # Properties that are intentionally preserved
    PRESERVED_PROPERTIES = {
        "created",
        "modified",
        "language",
        "last_printed",
        "revision",
        "JPEGInterchangeFormat",
        "JPEGInterchangeFormatLength",
    }

    def __init__(self):
        """Initialize the report generator."""
        self.console = Console()

    def compare(
        self,
        before: dict[str,
                     Any],
        after: dict[str,
                    Any],
        preserved_keys: set[str] | None = None,
    ) -> ComparisonReport:
        """
        Compare before and after metadata states.

        Args:
            before: Metadata dictionary from original file.
            after: Metadata dictionary from processed file.
            preserved_keys: Set of property names that should be preserved.

        Returns:
            ComparisonReport with detailed comparison results.
        """
        if preserved_keys is None:
            preserved_keys = self.PRESERVED_PROPERTIES

        report = ComparisonReport(
            original_file = "",
            processed_file = "",
        )

        # Get all unique keys from both dictionaries
        all_keys = set(before.keys()) | set(after.keys())

        for key in sorted(all_keys):
            before_value = before.get(key)
            after_value = after.get(key)

            # Determine property status
            status = self._determine_status(
                key,
                before_value,
                after_value,
                preserved_keys
            )

            is_sensitive = key not in preserved_keys

            comparison = PropertyComparison(
                name = key,
                before_value = before_value,
                after_value = after_value,
                status = status,
                is_sensitive = is_sensitive,
            )
            report.comparisons.append(comparison)

            # Update counts
            if status == PropertyStatus.REMOVED:
                report.removed_count += 1
            elif status == PropertyStatus.PRESERVED:
                report.preserved_count += 1
            elif status == PropertyStatus.WARNING:
                report.warning_count += 1

        # Determine overall status
        if report.warning_count > 0:
            report.status = VerificationStatus.WARNING
        else:
            report.status = VerificationStatus.CLEAN

        return report

    def _determine_status(
        self,
        key: str,
        before_value: Any,
        after_value: Any,
        preserved_keys: set[str],
    ) -> PropertyStatus:
        """
        Determine the status of a property based on before/after values.

        Args:
            key: Property name.
            before_value: Value before processing.
            after_value: Value after processing.
            preserved_keys: Set of keys that should be preserved.

        Returns:
            PropertyStatus indicating what happened to this property.
        """
        # Check if this is a preserved property
        if key in preserved_keys:
            return PropertyStatus.PRESERVED

        # Check if value was removed
        before_has_value = self._has_value(before_value)
        after_has_value = self._has_value(after_value)

        if before_has_value and not after_has_value:
            return PropertyStatus.REMOVED
        elif not before_has_value and not after_has_value:
            return PropertyStatus.UNCHANGED
        elif before_has_value and after_has_value:
            # Sensitive property still has value - warning
            return PropertyStatus.WARNING
        else:
            return PropertyStatus.UNCHANGED

    def _has_value(self, value: Any) -> bool:
        """
        Check if a value is considered "present" (not None/empty).

        Args:
            value: Value to check.

        Returns:
            True if value is present and meaningful.
        """
        if value is None:
            return False
        if isinstance(value, str) and value.strip() in ("", "-"):
            return False
        if value == 0 and not isinstance(value, bool):
            # 0 is typically not meaningful for metadata
            return False
        return True

    def render_table(self, report: ComparisonReport) -> None:
        """
        Render a comparison report as a rich table.

        Args:
            report: ComparisonReport to render.
        """
        # Create status emoji mapping
        status_icons = {
            PropertyStatus.REMOVED: "[green]✅ Removed[/green]",
            PropertyStatus.PRESERVED: "[dim]⚪ Preserved[/dim]",
            PropertyStatus.UNCHANGED: "[dim]— No change[/dim]",
            PropertyStatus.WARNING: "[yellow]⚠️ Still present[/yellow]",
        }

        table = Table(
            title = "[bold]Verification Report[/bold]",
            show_header = True,
            header_style = "bold",
        )

        table.add_column("Property", style = "cyan")
        table.add_column("Before", style = "dim")
        table.add_column("After", justify = "left")

        for comp in report.comparisons:
            before_str = self._format_value(comp.before_value)
            after_str = status_icons.get(comp.status, str(comp.after_value))

            table.add_row(comp.name, before_str, after_str)

        self.console.print(table)

        # Print summary
        self._print_summary(report)

    def _format_value(self, value: Any) -> str:
        """
        Format a metadata value for display.

        Args:
            value: Value to format.

        Returns:
            Formatted string representation.
        """
        if value is None:
            return "[dim]None[/dim]"
        if isinstance(value, str):
            if len(value) > 30:
                return value[: 27] + "..."
            return value if value.strip() else "[dim]-[/dim]"
        return str(value)

    def _print_summary(self, report: ComparisonReport) -> None:
        """
        Print summary statistics for the report.

        Args:
            report: ComparisonReport to summarize.
        """
        self.console.print()

        if report.status == VerificationStatus.CLEAN:
            self.console.print(
                "[bold green]✅ Status: CLEAN[/bold green] - "
                "All sensitive metadata removed"
            )
        elif report.status == VerificationStatus.WARNING:
            self.console.print(
                f"[bold yellow]⚠️ Status: WARNING[/bold yellow] - "
                f"{report.warning_count} properties may still contain data"
            )
        else:
            self.console.print("[bold red]❌ Status: ERROR[/bold red]")

        self.console.print(
            f"[dim]Removed: {report.removed_count} | "
            f"Preserved: {report.preserved_count}[/dim]"
        )

    def generate_report(
        self,
        original_file: str,
        processed_file: str,
        before_metadata: dict[str,
                              Any],
        after_metadata: dict[str,
                             Any],
    ) -> ComparisonReport:
        """
        Generate a full comparison report between two files.

        Args:
            original_file: Path to original file.
            processed_file: Path to processed file.
            before_metadata: Metadata from original file.
            after_metadata: Metadata from processed file.

        Returns:
            ComparisonReport with file paths and comparison data.
        """
        report = self.compare(before_metadata, after_metadata)
        report.original_file = original_file
        report.processed_file = processed_file
        return report
