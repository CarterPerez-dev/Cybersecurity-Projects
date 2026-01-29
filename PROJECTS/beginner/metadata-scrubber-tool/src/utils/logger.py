"""
Logging configuration for the metadata scrubber CLI.

This module provides the setup_logging function which configures the
application's logging with Rich handlers for beautiful terminal output.
"""

import logging

from rich.logging import RichHandler


def setup_logging(verbose: bool = False):
    """
    Configure application logging with Rich formatting.

    Sets up the logger with appropriate level and Rich handlers for
    beautiful terminal output including colorful stack traces.

    Args:
        verbose: If True, enables DEBUG level logging.
                If False (default), enables INFO level logging.

    Returns:
        Logger instance for 'metadata-scrubber'.
    """
    # Define the log level
    level = logging.DEBUG if verbose else logging.INFO

    # Configure the logger
    # Remove existing handlers to avoid duplicate lines if the app restarts
    logging.getLogger().handlers.clear()

    logging.basicConfig(
        level = level,
        format = "%(message)s",
        datefmt = "[%X]",
        handlers = [
            RichHandler(
                rich_tracebacks = True,  # Beautiful colorful stack traces
                markup = True,  # Allow [bold red] styles in logs
                show_path = False,  # Hide line number (cleaner for CLI tools)
            )
        ],
    )

    # Return the logger instance
    return logging.getLogger("metadata-scrubber")
