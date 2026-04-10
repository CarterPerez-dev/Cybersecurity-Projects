"""
©AngelaMos | 2026
base.py
"""


from typing import Protocol

from dlp_scanner.models import TextChunk


class Extractor(Protocol):
    """
    Protocol for text extraction from different file formats
    """
    def extract(self, path: str) -> list[TextChunk]:
        """
        Extract text chunks from a file at the given path
        """
        ...

    @property
    def supported_extensions(self) -> frozenset[str]:
        """
        File extensions this extractor handles
        """
        ...
