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

    Recursively searches the input directory for files matching the
    specified extension.

    Args:
        input_path_str: Path object pointing to the target directory.
        ext: File extension to filter by (without dot, e.g., 'jpg').

    Yields:
        Path objects for each matching file found.
    """
    # If input is a directory, yield all files with the specified extension
    if input_path_str.is_dir():
        yield from input_path_str.rglob(f"*.{ext}")
