"""
PNG metadata processor using PIL.

This module provides the PngProcessor class which handles metadata
extraction and manipulation for PNG images, including both EXIF data
and PNG textual metadata (PngInfo chunks).
"""

from typing import Any

from PIL import ExifTags, PngImagePlugin
from PIL.Image import Exif, Image

from src.utils.exceptions import MetadataNotFoundError, MetadataProcessingError


class PngProcessor:
    """
    Processor for PNG image metadata.

    Handles reading, extracting, and deleting metadata from PNG files.
    Processes both EXIF data and PNG textual chunks (PngInfo).

    Attributes:
        tags_to_delete: List of EXIF tag IDs to remove.
        text_keys_to_delete: List of PngInfo text keys to remove.
        data: Dict of extracted metadata with human-readable keys.
    """

    # Privacy-sensitive PNG text keys to remove
    SENSITIVE_TEXT_KEYS = {
        "Author",
        "Comment",
        "Copyright",
        "Creation Time",
        "Description",
        "Disclaimer",
        "Software",
        "Source",
        "Title",
        "Warning",
        "XML:com.adobe.xmp",  # XMP metadata
    }

    def __init__(self):
        """Initialize the PNG processor with empty data structures."""
        self.tags_to_delete: list[int] = []
        self.text_keys_to_delete: list[str] = []
        self.data: dict[str, Any] = {}

    def get_metadata(self, img: Image) -> dict[str, Any]:
        """
        Extract metadata from a PNG image.

        Extracts both EXIF data (if present) and PNG textual chunks (PngInfo).

        Args:
            img: PIL Image object.

        Returns:
            Dict with 'data' (metadata dict), 'tags_to_delete' (EXIF tag IDs),
            and 'text_keys' (PngInfo keys to remove).

        Raises:
            MetadataNotFoundError: If no metadata is found in the image.
        """
        img.load()
        found_metadata = False

        # Extract EXIF data (if present)
        exif = img.getexif()
        if exif:
            found_metadata = True
            # Main IFD
            for tag, value in exif.items():
                tag_name = ExifTags.TAGS.get(tag, f"Tag_{tag}")
                self.tags_to_delete.append(tag)
                self.data[f"EXIF:{tag_name}"] = value

            # GPS IFD
            gps_ifd = exif.get_ifd(ExifTags.IFD.GPSInfo)
            for tag, value in gps_ifd.items():
                tag_name = ExifTags.GPSTAGS.get(tag, f"GPSTag_{tag}")
                self.tags_to_delete.append(tag)
                self.data[f"GPS:{tag_name}"] = value

        # Extract PNG textual metadata (PngInfo chunks)
        if hasattr(img, "info") and img.info:
            for key, value in img.info.items():
                # Skip binary/internal data
                if key in ("icc_profile", "exif", "transparency", "gamma"):
                    continue

                if isinstance(value, (str, bytes)):
                    found_metadata = True
                    if isinstance(value, bytes):
                        try:
                            value = value.decode("utf-8", errors = "replace")
                        except Exception:
                            value = str(value)

                    self.data[f"PNG:{key}"] = value
                    if isinstance(key, str):  # Only add string keys
                        self.text_keys_to_delete.append(key)

        if not found_metadata:
            raise MetadataNotFoundError("No metadata found in the PNG image.")

        return {
            "data": self.data,
            "tags_to_delete": self.tags_to_delete,
            "text_keys": self.text_keys_to_delete,
        }

    def delete_metadata(self, img: Image, tags_to_delete: list[int]) -> Exif:
        """
        Remove EXIF tags from a PNG image.

        Args:
            img: PIL Image object.
            tags_to_delete: List of EXIF tag IDs to remove.

        Returns:
            Mutated Exif object with specified tags removed.

        Raises:
            MetadataProcessingError: If an error occurs during processing.
        """
        img.load()
        exif = img.getexif()
        try:
            # Delete tags from main IFD (iterate over copy of keys)
            for tag_id in list(exif.keys()):
                if tag_id in tags_to_delete:
                    del exif[tag_id]

            # Clear GPS IFD entirely (privacy-sensitive)
            gps_ifd = exif.get_ifd(ExifTags.IFD.GPSInfo)
            gps_ifd.clear()

            return exif
        except Exception as e:
            raise MetadataProcessingError(f"Error processing PNG EXIF: {str(e)}")

    def get_clean_pnginfo(
        self,
        img: Image,
        keys_to_remove: list[str] | None = None
    ) -> PngImagePlugin.PngInfo | None:
        """
        Create a new PngInfo with sensitive keys removed.

        Args:
            img: PIL Image object.
            keys_to_remove: Specific keys to remove. If None, removes all sensitive keys.

        Returns:
            New PngInfo object with only safe metadata, or None if no safe metadata.
        """
        if not hasattr(img, "info") or not img.info:
            return None

        keys_to_remove = keys_to_remove or list(self.text_keys_to_delete)

        # Create new PngInfo with only safe keys
        pnginfo = PngImagePlugin.PngInfo()
        has_safe_data = False

        for key, value in img.info.items():
            # Skip keys to remove
            if key in keys_to_remove:
                continue

            # Skip binary/internal data
            if key in ("icc_profile", "exif", "transparency", "gamma"):
                continue

            # Only include text data with string keys
            if isinstance(key, str) and isinstance(value, str):
                pnginfo.add_text(key, value)
                has_safe_data = True

        return pnginfo if has_safe_data else None
