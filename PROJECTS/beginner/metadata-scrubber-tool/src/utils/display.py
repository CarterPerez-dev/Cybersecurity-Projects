"""
Display utilities for rich terminal output.

This module provides functions for displaying metadata and batch processing
results in beautifully formatted tables and panels using the Rich library.
"""

from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.utils.formatter import clean_value


console = Console()


def print_metadata_table(metadata: dict[str, Any]):
    """
    Display metadata in a formatted table organized by logical groups.

    Organizes metadata into categories (Device Info, Exposure Settings,
    Image Data, Dates) and displays them in a Rich panel with color coding.

    Args:
        metadata: Dict of metadata key-value pairs to display.
    """

    # Define the groups using simple lists of keys
    groups = {
        "📄 Document Info": [
            "Author",
            "author",
            "/Author",
            "/Creator",
        ],
        "📸 Device Info": ["Make",
                          "Model",
                          "Software",
                          "ExifVersion"],
        "⚙️ Exposure Settings": [
            "ExposureTime",
            "FNumber",
            "ISOSpeedRatings",
            "ShutterSpeedValue",
            "ApertureValue",
            "Flash",
            "FocalLength",
        ],
        "🖼️ Image Data": [
            "ImageWidth",
            "ImageLength",
            "PixelXDimension",
            "PixelYDimension",
            "Orientation",
            "ResolutionUnit",
        ],
        "📅 Dates": [
            "DateTime",
            "DateTimeOriginal",
            "DateTimeDigitized",
            "OffsetTime",
            "created",
            "modified",
            "/CreationDate",
            "/ModDate",
        ],
    }

    # Create the main table
    table = Table(box = box.ROUNDED, show_header = True, header_style = "bold magenta")
    table.add_column("Property", style = "cyan")
    table.add_column("Value", style = "green")

    # Track which keys we have displayed to handle the "leftovers"
    displayed_keys = set()

    # Loop through the defined groups to create sections
    for section_name, keys in groups.items():
        # Check if we have any data for this section
        section_data = {k: metadata[k] for k in keys if k in metadata}

        if section_data:
            # Add a section row (acts as a sub-header)
            table.add_row(Text(section_name, style = "bold yellow"), "")

            for key, val in section_data.items():
                table.add_row(f"  {key}", clean_value(val))
                displayed_keys.add(key)

            # Add a blank row for spacing
            table.add_section()

    # Handle "Other" (Any keys that isn't in the groups)
    leftovers = {
        k: v
        for k, v in metadata.items()
        if k not in displayed_keys and k != "JPEGInterchangeFormat"
    }  # skip binary blobs
    if leftovers:
        table.add_row(Text("📝 Other", style = "bold yellow"), "")
        for key, val in leftovers.items():
            table.add_row(f"  {key}", clean_value(val))

    # Print nicely inside a panel
    console.print(
        Panel(table,
              title = "Metadata Report",
              border_style = "blue",
              expand = False)
    )


def print_batch_summary(summary) -> None:
    """
    Display batch processing results in a rich panel.

    Args:
        summary: BatchSummary object with processing statistics.
    """
    # Build the summary table
    table = Table(box = box.ROUNDED, show_header = False, expand = False)
    table.add_column("Metric", style = "cyan")
    table.add_column("Value", style = "green")

    if summary.dry_run:
        table.add_row("Mode", "[yellow]DRY-RUN (no changes made)[/yellow]")
        table.add_row("Would process", str(summary.success))
        table.add_row("Would skip", str(summary.skipped))
    else:
        table.add_row("Total processed", str(summary.total))
        table.add_row("✅ Success", f"[green]{summary.success}[/green]")
        table.add_row("⚠️ Skipped", f"[yellow]{summary.skipped}[/yellow]")
        if summary.output_dir:
            table.add_row("📁 Output", str(summary.output_dir.resolve()))

    # Show failed files if any
    failed = [r for r in summary.results if not r.success]
    if failed:
        table.add_section()
        table.add_row(Text("Failed files:", style = "bold red"), "")
        for result in failed[: 5]:  # Show max 5 failures
            table.add_row(f"  {result.filepath.name}", f"[dim]{result.error}[/dim]")
        if len(failed) > 5:
            table.add_row("", f"[dim]... and {len(failed) - 5} more[/dim]")

    # Determine panel title and style
    if summary.dry_run:
        title = "🔍 Dry-Run Summary"
        border_style = "yellow"
    elif summary.skipped == 0:
        title = "✅ Scrub Complete"
        border_style = "green"
    else:
        title = "⚠️ Scrub Complete (with warnings)"
        border_style = "yellow"

    console.print(
        Panel(table,
              title = title,
              border_style = border_style,
              expand = False)
    )
