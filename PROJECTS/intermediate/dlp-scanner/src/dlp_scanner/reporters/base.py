"""
©AngelaMos | 2026
base.py
"""


from typing import Protocol

from dlp_scanner.models import ScanResult


class Reporter(Protocol):
    """
    Protocol for all report output formats
    """
    def generate(self, result: ScanResult) -> str:
        """
        Generate report content as a string
        """
        ...
