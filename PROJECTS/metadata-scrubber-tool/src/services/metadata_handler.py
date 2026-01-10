"""
Abstract base class for metadata handlers.

This module defines the MetadataHandler ABC which establishes the interface
for all metadata handlers. Concrete implementations (ImageHandler, PDFHandler, etc.)
must implement the read, wipe, and save methods.
"""

from abc import ABC, abstractmethod
from typing import Any


class MetadataHandler(ABC):
    """
    Abstract base class for all metadata handlers.

    Defines the common interface for reading, modifying, and saving
    metadata across different file types. All concrete handlers must
    implement the abstract methods.

    Attributes:
        filepath: Path to the file being processed.
        metadata: Dictionary containing the extracted metadata.
        processed_metadata: Dictionary containing metadata after processing.
    """
    def __init__(self, filepath: str):
        """
        Initialize the metadata handler.

        Args:
            filepath: Path to the file to process.
        """
        self.filepath = filepath
        self.metadata: dict[str, Any] = {}
        self.processed_metadata: dict[str, Any] = {}

    @abstractmethod
    def read(self) -> dict[str, Any]:
        """
        Extract metadata from the file.

        Returns:
            Dict containing the extracted metadata with human-readable keys.

        Raises:
            MetadataNotFoundError: If no metadata is found in the file.
        """
        pass

    @abstractmethod
    def wipe(self) -> None:
        """
        Remove privacy-sensitive metadata from the file.

        Updates self.processed_metadata with the cleaned metadata state.

        Raises:
            MetadataProcessingError: If an error occurs during processing.
        """
        pass

    @abstractmethod
    def save(self, output_path: str) -> None:
        """
        Save the processed file with cleaned metadata.

        Args:
            output_path: Destination path for the processed file.
                        If None, uses a default location.
        """
        pass
