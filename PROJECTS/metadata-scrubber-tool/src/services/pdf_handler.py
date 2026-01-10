"""
PDF metadata handler for PDF files.

This module provides the PDFHandler class which implements the MetadataHandler
interface for PDF files. Uses pypdf library for reading and writing PDF
document information dictionary.

Note:
    Does not support encrypted/password-protected PDF files.
"""

import shutil
from pathlib import Path
from typing import Any

from pypdf import PdfReader, PdfWriter

from src.services.metadata_handler import MetadataHandler
from src.utils.exceptions import (
    MetadataNotFoundError,
    MetadataReadingError,
    UnsupportedFormatError,
)


class PDFHandler(MetadataHandler):
    """
    PDF metadata handler for PDF files.

    Handles extraction and removal of document information from PDF files
    including author, creator, title, subject, and other standard PDF metadata.

    Attributes:
        keys_to_delete: List of metadata keys to be wiped.
    """
    def __init__(self, filepath: str):
        """
        Initialize the PDF handler.

        Args:
            filepath: Path to the PDF file to process.
        """
        super().__init__(filepath)
        self.keys_to_delete: list[str] = []

    def _detect_format(self) -> str:
        """
        Validate that the file has a PDF extension.

        Returns:
            Normalized format string ('pdf').

        Raises:
            UnsupportedFormatError: If file extension is not .pdf.
        """
        ext = Path(self.filepath).suffix.lower()
        if ext != ".pdf":
            raise UnsupportedFormatError(f"Unsupported format: {ext}")

        return ext[1 :]  # Return 'pdf' without the dot

    def read(self) -> dict[str, Any]:
        """
        Extract metadata from the PDF document information dictionary.

        Returns:
            Dictionary of metadata keys to their values.

        Raises:
            MetadataReadingError: If the PDF is encrypted/password-protected.
            MetadataNotFoundError: If no metadata is found in the PDF.
        """
        self.metadata.clear()
        self.keys_to_delete.clear()
        with PdfReader(Path(self.filepath)) as reader:
            if reader.is_encrypted:
                raise MetadataReadingError("File is encrypted.")

            if reader.metadata is None:
                raise MetadataNotFoundError("No metadata found in the file.")

            for key, value in reader.metadata.items():
                self.metadata[key] = value
                self.keys_to_delete.append(key)

        return self.metadata

    def wipe(self) -> None:
        """
        Remove metadata entries from the PDF document.

        Clears all metadata keys identified during read().

        Raises:
            MetadataNotFoundError: If no metadata is found in the PDF.
        """
        self.processed_metadata.clear()
        with PdfReader(Path(self.filepath)) as reader:
            metadata = reader.metadata
            if metadata is None:
                raise MetadataNotFoundError("No metadata found in the file.")

            for key in list(metadata):
                if key in self.keys_to_delete:
                    del metadata[key]

            self.processed_metadata = metadata

    def save(self, output_path: str | None) -> None:
        """
        Save the PDF with cleaned metadata to the output path.

        Creates a copy of the original file and rebuilds the PDF
        with the wiped metadata.

        Args:
            output_path: Path where the cleaned PDF should be saved.

        Raises:
            ValueError: If output_path is None or empty.
        """
        if not output_path:
            raise ValueError("output_path is required")

        destination_file_path = Path(output_path)
        shutil.copy2(self.filepath, destination_file_path)

        with PdfReader(destination_file_path) as reader, PdfWriter() as writer:
            # Copy all pages
            for page in reader.pages:
                writer.add_page(page)

            writer.add_metadata(self.processed_metadata)
            writer.write(destination_file_path)
