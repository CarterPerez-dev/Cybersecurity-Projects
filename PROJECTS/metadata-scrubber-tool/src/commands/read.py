"""
Read command - Display metadata from files.

This command reads and displays metadata from image files in a
formatted table view. Supports single files or recursive directory processing.
"""

import logging
from pathlib import Path

import typer
from rich.console import Console

from src.services.metadata_factory import MetadataFactory
from src.utils.display import print_metadata_table
from src.utils.get_target_files import get_target_files


console = Console()
log = logging.getLogger("metadata-scrubber")


# fmt: off
def read(
    file_path: Path = typer.Argument(
        exists=True,  # Must exist on the filesystem
        file_okay=True,  # Can be a file
        dir_okay=True,  # Can be a directory
        readable=True,  # Must be readable (permissions check)
        resolve_path=True,  # Auto-convert to absolute path
        help="The path to the file you want to process",
    ),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="Recursively process files in the specified directory."),
    ext: str = typer.Option(None,"--extension", "-ext", help="The file extension to filter by. eg: jpg, png, pdf"),
):
    if recursive and not ext:
        raise typer.BadParameter("If you provide --recursive or -r, you must also provide --extension or -ext.")
    if ext and not recursive:
        raise typer.BadParameter("If you provide --extension or -ext, you must also provide --recursive or -r.")

    for file in get_target_files(file_path, ext) if recursive else [file_path]:
        try:
            # Get the correct object from the factory
            handler = MetadataFactory.get_handler(str(file))

            # Read
            console.print(f"🔎 Reading [bold cyan]{file.name}[/bold cyan]...")
            current_data = handler.read()
            if log.isEnabledFor(logging.DEBUG):
                # if verbose mode is enabled, log the Info
                log.info(f"Successfully read metadata from {file.name}")
            print_metadata_table(current_data)

        except Exception as e:
            # display error in console
            console.print(f"❌ [bold red]Skipped[/bold red] [cyan]{file.name}[/cyan]: [dim]{e}[/dim]")

            # LOG: Full technical details (Stack trace) for you to debug

            if log.isEnabledFor(logging.DEBUG):
                # if verbose mode is enabled, log the traceback
                log.error(f"Failed to read metadata from {file}", exc_info=True)
