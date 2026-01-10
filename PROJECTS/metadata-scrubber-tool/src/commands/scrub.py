"""
Scrub command - Remove metadata from files.

This command processes files through the read→wipe→save pipeline,
removing privacy-sensitive metadata like EXIF, GPS, and author info.

Supports concurrent processing for efficient batch operations on large file sets.
"""

import logging
import os
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

from src.services.batch_processor import BatchProcessor
from src.utils.display import print_batch_summary
from src.utils.get_target_files import get_target_files


console = Console()
log = logging.getLogger("metadata-scrubber")


# fmt: off
def scrub(
    file_path: Path = typer.Argument(
        exists=True,
        file_okay=True,
        dir_okay=True,
        readable=True,
        writable=True,
        resolve_path=True,
        help="The file or directory to process.",
    ),
    recursive: bool = typer.Option(
        False, "--recursive", "-r",
        help="Recursively process files in the specified directory."
    ),
    ext: str = typer.Option(
        None, "--extension", "-ext",
        help="File extension to filter by (e.g., jpg, png)."
    ),
    output_dir: str = typer.Option(
        "./scrubbed", "--output", "-o",
        help="Directory to save processed files."
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", "-d",
        help="Preview what would be processed without making changes."
    ),
    workers: int = typer.Option(
        min(4, (os.cpu_count() or 1)),
        "--workers", "-w",
        help="Number of concurrent worker threads (default: 4 or CPU count)."
    ),
):
    # fmt: on
    """
    Remove metadata from files.

    Scrubs privacy-sensitive metadata (EXIF, GPS, author info) from images.
    Works with JPEG, PNG, and will support PDF/Office docs in future.

    Examples:

        scrub photo.jpg

        scrub ./photos/ -r -ext jpg --output ./cleaned

        scrub ./folder/ -r -ext png --dry-run

        scrub ./large_batch/ -r -ext jpg --workers 8
    """
    # Validate recursive/extension combo
    if recursive and not ext:
        raise typer.BadParameter(
            "If you provide --recursive or -r, you must also provide --extension or -ext."
        )
    if ext and not recursive:
        raise typer.BadParameter(
            "If you provide --extension or -ext, you must also provide --recursive or -r."
        )

    # Show dry-run banner
    if dry_run:
        console.print(
            "\n[bold yellow]🔍 DRY-RUN MODE[/bold yellow] - No files will be modified.\n"
        )

    # Collect files to process
    files = list(get_target_files(file_path, ext)) if recursive else [file_path]

    if not files:
        console.print("[yellow]No files found to process.[/yellow]")
        raise typer.Exit(0)

    # Show worker count for batch operations
    if len(files) > 1:
        console.print(
            f"[dim]Processing {len(files)} files with {workers} workers...[/dim]\n"
        )

    # Initialize processor with worker count
    processor = BatchProcessor(
        output_dir = output_dir,
        dry_run = dry_run,
        max_workers = workers
    )

    # Process with thread-safe progress bar
    with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console = console,
            refresh_per_second = 10,  # Smooth updates for concurrent processing
    ) as progress:
        task_id = progress.add_task(
            "[cyan]Scrubbing metadata...",
            total = len(files),
        )

        def on_file_complete(result):
            """Callback for progress updates from concurrent workers."""
            status = "✓" if result.success else "✗"
            progress.update(
                task_id,
                description = f"[cyan]{status} {result.filepath.name}",
                advance = 1,
            )

        # Use concurrent batch processing
        processor.process_batch(files, progress_callback = on_file_complete)

    # Display summary
    print_batch_summary(processor.get_summary())
