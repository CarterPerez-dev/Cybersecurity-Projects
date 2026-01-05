"""
Value formatting utilities for metadata display.

This module provides helper functions to convert raw EXIF data into
human-readable strings for display in the terminal.
"""

from typing import Any


def clean_value(value: Any) -> str:
    """
    Convert raw EXIF data into a human-readable string.

    Handles various EXIF value types including bytes, tuples, and empty values.

    Args:
        value: Raw EXIF value (bytes, tuple, str, int, etc.).

    Returns:
        Human-readable string representation of the value.
    """
    # Decode bytes (e.g., b'samsung' -> 'samsung')
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8").strip()
        except UnicodeDecodeError:
            return str(value)

    # Format Tuples (e.g., (1, 50) -> '1/50')
    if isinstance(value, tuple) or isinstance(value, list):
        return "/".join(map(str, value))

    # Handle empty values
    if value == "":
        return "-"

    return str(value)
