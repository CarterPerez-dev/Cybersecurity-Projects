"""
Image metadata handler for JPEG and PNG files.

This module provides the ImageHandler class which implements the MetadataHandler
interface for image files. It delegates the actual metadata operations to
format-specific processors (JpegProcessor, PngProcessor).
"""

import shutil
from pathlib import Path
from typing import Optional

import piexif  # pyright: ignore[reportMissingTypeStubs]
from PIL import Image

from src.core.jpeg_metadata import JpegProcessor
from src.core.png_metadata import PngProcessor
from src.services.metadata_handler import MetadataHandler


class ImageHandler(MetadataHandler):
    """
    Metadata handler for image files (JPEG, PNG).

    Implements the MetadataHandler interface using format-specific processors
    to read, wipe, and save image metadata. Uses piexif for EXIF manipulation.

    Attributes:
        processors: Dict mapping file extensions to processor instances.
        tags_to_delete: List of EXIF tags to remove during wipe operation.
    """

    def __init__(self, filepath: str):
        """
        Initialize the image handler.

        Args:
            filepath: Path to the image file to process.
        """
        super().__init__(filepath)
        self.processors = {
            ".jpeg": JpegProcessor(),
            ".jpg": JpegProcessor(),
            ".png": PngProcessor(),
        }
        self.tags_to_delete = []

    def read(self):
        """Extract metadata from the file."""
        with Image.open(Path(self.filepath)) as img:
            extension = Path(self.filepath).suffix
            processor = self.processors.get(extension)

            if not processor:
                raise ValueError(f"Unsupported format: {extension}")

            self.metadata = processor.get_metadata(img)["data"]
            self.tags_to_delete = processor.get_metadata(img)["tags_to_delete"]
            return self.metadata

    def wipe(self) -> None:
        """Wipes internal metadata state."""
        with Image.open(Path(self.filepath)) as img:
            extension = Path(self.filepath).suffix
            processor = self.processors.get(extension)

            if not processor:
                raise ValueError(f"Unsupported format: {extension}")

            self.processed_metadata = processor.delete_metadata(
                img, self.tags_to_delete
            )

    def save(self, output_path: Optional[str] = None) -> None:
        """
        Writes the changes to a copy of the original file.

        Args:
            output_path: Can be a directory path (legacy behavior) or a full file path.
                        If a directory, generates filename as 'processed_{original_name}'.
                        If a file path, uses it directly.
        """
        destination_file_path = ""
        if output_path:
            # setup the destination directory.
            # which was created by the batch_processor
            destination_file_path = Path(output_path)

        # copies the original file to the destination directory
        shutil.copy2(self.filepath, destination_file_path)

        # writes the processed metadata to the image in the destination directory
        with Image.open(destination_file_path) as img:
            exif_bytes = piexif.dump(self.processed_metadata)
            img.save(destination_file_path, exif=exif_bytes)
