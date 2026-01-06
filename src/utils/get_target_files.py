"""
File discovery utilities for batch processing.

This module provides functions to find and yield files for processing,
supporting recursive directory traversal with extension filtering.
"""

from pathlib import Path
from typing import Generator


def get_target_files(input_path_str: Path, ext: str) -> Generator[Path, None, None]:
    """
    Yield files to process based on input path and extension filter.

    Handles both directories (recursive search) and single files (defensive).

    Args:
        input_path_str: Path object pointing to a file or directory.
        ext: File extension to filter by (without dot, e.g., 'jpg').

    Yields:
        Path objects for each matching file found.
    """
    if input_path_str.is_dir():
        # Directory: recursively yield all files with the specified extension
        yield from input_path_str.rglob(f"*.{ext.lower()}")
    elif input_path_str.is_file():
        # Defensive: if a file is passed, yield it if extension matches
        if input_path_str.suffix.lstrip(".").lower() == ext.lower():
            yield input_path_str
