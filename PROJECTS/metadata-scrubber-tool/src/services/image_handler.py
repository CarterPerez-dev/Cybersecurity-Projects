"""
Image metadata handler for JPEG and PNG files.

This module provides the ImageHandler class which implements the MetadataHandler
interface for image files. It delegates the actual metadata operations to
format-specific processors (JpegProcessor, PngProcessor).
"""

import shutil
from pathlib import Path
from typing import Any, cast

import piexif  # pyright: ignore[reportMissingTypeStubs]
from PIL import Image

from src.core.jpeg_metadata import JpegProcessor
from src.core.png_metadata import PngProcessor
from src.services.metadata_handler import MetadataHandler
from src.utils.exceptions import UnsupportedFormatError

# Map Pillow format names to processor keys
FORMAT_MAP = {
    "jpeg": "jpeg",
    "jpg": "jpeg",
    "png": "png",
}


class ImageHandler(MetadataHandler):
    """
    Metadata handler for image files (JPEG, PNG).

    Implements the MetadataHandler interface using format-specific processors
    to read, wipe, and save image metadata. Uses Pillow's format detection
    to handle files with incorrect extensions.

    Attributes:
        processors: Dict mapping format names to processor instances.
        tags_to_delete: List of EXIF tags to remove during wipe operation.
        detected_format: Actual image format detected by Pillow.
    """
    def __init__(self, filepath: str):
        """
        Initialize the image handler.

        Args:
            filepath: Path to the image file to process.
        """
        super().__init__(filepath)
        self.processors: dict[str,
                              JpegProcessor | PngProcessor] = {
                                  "jpeg": JpegProcessor(),
                                  "png": PngProcessor(),
                              }
        self.tags_to_delete: list[int] = []
        self.detected_format: str | None = None
        self.text_keys_to_delete: list[str] = []

    def _detect_format(self) -> str:
        """
        Detect actual image format using Pillow, not file extension.

        This protects against misnamed files (e.g., a PNG saved as .jpg).

        Returns:
            Normalized format string ('jpeg' or 'png').

        Raises:
            UnsupportedFormatError: If format is not supported or undetectable.
        """
        with Image.open(Path(self.filepath)) as img:
            if img.format is None:
                raise UnsupportedFormatError(
                    f"Could not detect format for: {self.filepath}"
                )

            pillow_format = img.format.lower()
            normalized = FORMAT_MAP.get(pillow_format)

            if normalized is None:
                raise UnsupportedFormatError(
                    f"Unsupported format: {pillow_format} (file: {self.filepath})"
                )

            return normalized

    def read(self):
        """
        Extract metadata from the file.

        Uses actual format detection to select the appropriate processor.
        """
        self.metadata.clear()
        self.text_keys_to_delete.clear()
        self.tags_to_delete.clear()

        self.detected_format = self._detect_format()
        processor = self.processors.get(self.detected_format)

        if not processor:
            raise UnsupportedFormatError(f"Unsupported format: {self.detected_format}")

        with Image.open(Path(self.filepath)) as img:
            result = processor.get_metadata(img)
            self.metadata = result["data"]
            self.tags_to_delete = result["tags_to_delete"]
            # Store text keys for PNG processing
            if isinstance(result, PngProcessor):
                self.text_keys_to_delete = result.get("text_keys", [])
            return self.metadata

    def wipe(self) -> None:
        """
        Remove privacy-sensitive metadata from the file.

        Uses actual format detection to select the appropriate processor.
        """
        self.processed_metadata.clear()
        self.clean_pnginfo = None
        # Use cached format if available, otherwise detect
        if not self.detected_format:
            self.detected_format = self._detect_format()

        processor = self.processors.get(self.detected_format)

        if not processor:
            raise UnsupportedFormatError(f"Unsupported format: {self.detected_format}")

        with Image.open(Path(self.filepath)) as img:
            self.processed_metadata = cast(
                dict[str,
                     Any],
                processor.delete_metadata(img,
                                          self.tags_to_delete)
            )
            # For PNG, also get clean PngInfo
            if isinstance(processor, PngProcessor):
                self.clean_pnginfo = processor.get_clean_pnginfo(
                    img,
                    self.text_keys_to_delete
                )

    def save(self, output_path: str | Path | None = None) -> None:
        """
        Writes the changes to a copy of the original file.

        Handles format-specific saving:
        - JPEG: Uses piexif to write cleaned EXIF data
        - PNG: Saves without EXIF and strips textual metadata

        Args:
            output_path: Full path to the destination file.
        """
        destination_file_path = Path(output_path) if output_path else None

        if not destination_file_path:
            raise ValueError("output_path is required")

        # Use detected format (falls back to extension if not detected)
        actual_format = self.detected_format or self._detect_format()

        if actual_format == "jpeg":
            # JPEG: Copy then write cleaned EXIF data
            shutil.copy2(self.filepath, destination_file_path)
            with Image.open(destination_file_path) as img:
                exif_bytes = piexif.dump(self.processed_metadata)
                img.save(destination_file_path, exif = exif_bytes)

        elif actual_format == "png":
            # PNG: Open original, save fresh copy without metadata
            with Image.open(Path(self.filepath)) as img:
                # Save without exif and without pnginfo to strip all metadata
                # Preserve image mode and data integrity
                img.save(
                    destination_file_path,
                    format = "PNG",
                    exif = None,
                    pnginfo = getattr(self,
                                      "clean_pnginfo",
                                      None),
                )
