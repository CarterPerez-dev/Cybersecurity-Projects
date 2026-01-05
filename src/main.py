"""
Metadata Scrubber Tool - CLI Application Entry Point.

This module serves as the main entry point for the CLI application.
It initializes the Typer app, registers commands, and configures logging.

Commands:
    read: Display metadata from files.
    scrub: Remove metadata from files.
"""

import logging

import typer

from src.commands.read import get_metadata
from src.commands.scrub import scrub
from src.utils.logger import setup_logging

# Initialize the Typer app with helpful defaults
app = typer.Typer(no_args_is_help=True, pretty_exceptions_show_locals=False)
log = logging.getLogger("metadata-scrubber")


# fmt: off
@app.callback()
def main(
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show detailed debug logs for every file processed.",
    ),
):
    """
    Metadata Scrubber Tool - Clean your images privacy data.
    """
    # Initialize the logger based on the user's flag
    setup_logging(verbose)

    if verbose:
        log.debug("🐛 Verbose mode enabled. Detailed logs active.")
# fmt: on

# register commands
app.command(name="read")(get_metadata)
app.command(name="scrub")(scrub)

# run app
if __name__ == "__main__":
    app()
