"""
©AngelaMos | 2026
utils.py

Input/output helpers and key validation shared across CLI commands

Handles the three sources of input (positional argument, file, or stdin)
and routes output to either stdout or a file. Also validates that the
shift key is in the acceptable range before the cipher is constructed.

Connects to:
  main.py - imports read_input, write_output, validate_key
"""

import sys
from pathlib import Path


def read_input(text: str | None, input_file: Path | None) -> str:
    """
    Read input from text argument, file, or stdin
    """
    if text:
        return text

    if input_file:
        return input_file.read_text(encoding = "utf-8")

    if not sys.stdin.isatty():
        return sys.stdin.read()

    msg = "No input provided. Use TEXT argument, --input-file, or pipe to stdin"
    raise ValueError(msg)


def write_output(content: str, output_file: Path | None, quiet: bool = False) -> None:
    """
    Write output to file or stdout
    """
    if output_file:
        output_file.write_text(content, encoding = "utf-8")
        if not quiet:
            print(f"Output written to {output_file}")
    else:
        print(content)


def validate_key(key: int) -> None:
    """
    Validate Caesar cipher key is within acceptable range
    """
    if not 0 <= key <= 26:
        msg = f"Key must be between 0 and 26, got {key}"
        raise ValueError(msg)
