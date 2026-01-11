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

    if isinstance(value, str) and value.startswith("D:"):
        clean_iso = f"{value[2:6]}-{value[6:8]}-{value[8:10]}T{value[10:12]}:{value[12:14]}:{value[14:16]}"
        return clean_iso

    # Handle empty values
    if value == "":
        return "-"

    return str(value)
