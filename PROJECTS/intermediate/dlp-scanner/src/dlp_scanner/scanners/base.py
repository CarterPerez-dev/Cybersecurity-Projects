"""
©AngelaMos | 2026
base.py
"""


from typing import Protocol

from dlp_scanner.models import ScanResult


class Scanner(Protocol):
    """
    Protocol for all scan strategies
    """
    def scan(self, target: str) -> ScanResult:
        """
        Scan the target and return aggregated results
        """
        ...
