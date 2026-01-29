"""
Verify command for comparing metadata between original and processed files.

This command reads metadata from both files and generates a comparison report
showing what was removed, preserved, or unchanged.
"""

import logging
from pathlib import Path

import typer
from rich.console import Console

from src.services.metadata_factory import MetadataFactory
from src.services.report_generator import ReportGenerator


console = Console()
log = logging.getLogger("metadata-scrubber")


def verify(
    original_path: Path = typer.Argument(
        exists = True,
        file_okay = True,
        dir_okay = False,
        readable = True,
        resolve_path = True,
        help = "Path to the original file (before scrubbing)",
    ),
    processed_path: Path = typer.Argument(
        exists = True,
        file_okay = True,
        dir_okay = False,
        readable = True,
        resolve_path = True,
        help = "Path to the processed file (after scrubbing)",
    ),
) -> None:
    """
    Verify that metadata was properly removed from a scrubbed file.

    Compares the original file with the processed version and shows
    a detailed report of what was removed, preserved, or still present.
    """
    if log.isEnabledFor(logging.DEBUG):
        log.info(f"Original: {original_path}")
        log.info(f"Processed: {processed_path}")

    try:
        # Read metadata from original file
        original_handler = MetadataFactory.get_handler(str(original_path))
        before_metadata = original_handler.read()

        # Read metadata from processed file
        processed_handler = MetadataFactory.get_handler(str(processed_path))
        after_metadata = processed_handler.read()

        # Generate comparison report
        generator = ReportGenerator()
        report = generator.generate_report(
            original_file = str(original_path),
            processed_file = str(processed_path),
            before_metadata = before_metadata,
            after_metadata = after_metadata,
        )

        # Render the report
        console.print(
            f"[bold]Comparing:[/bold] {original_path.name} → {processed_path.name}"
        )
        console.print()
        generator.render_table(report)

    except Exception as e:
        console.print(f"[red]Error during verification:[/red] {e}")
        if log.isEnabledFor(logging.DEBUG):
            console.print_exception()
        raise typer.Exit(code = 1)
