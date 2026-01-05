"""
JPEG metadata processor using piexif.

This module provides the JpegProcessor class which handles EXIF metadata
extraction and manipulation for JPEG images using the piexif library.
"""

import piexif  # pyright: ignore[reportMissingTypeStubs]

from src.utils.exceptions import MetadataNotFoundError, MetadataProcessingError


class JpegProcessor:
    """
    Processor for JPEG image metadata.

    Handles reading, extracting, and deleting EXIF metadata from JPEG files.
    Preserves essential tags (Orientation, ColorSpace) needed for proper display.

    Attributes:
        tags_to_delete: List of EXIF tag IDs to remove.
        data: Dict of extracted metadata with human-readable keys.
    """

    def __init__(self):
        """Initialize the JPEG processor with empty data structures."""
        self.tags_to_delete = []
        self.data = {}

    def get_metadata(self, img):
        """
        Extract EXIF metadata from a JPEG image.

        Args:
            img: PIL Image object with EXIF data.

        Returns:
            Dict with 'data' (metadata dict) and 'tags_to_delete' (tag IDs list).

        Raises:
            MetadataNotFoundError: If no EXIF data is found in the image.
        """
        if "exif" not in img.info:
            raise MetadataNotFoundError("No EXIF data found in the image.")

        exif_dict = piexif.load(img.info["exif"])
        for ifd, value in exif_dict.items():
            # Exclude thumbnail IFD (blob data that slows loading if removed)
            if not isinstance(exif_dict[ifd], dict):
                continue

            # Iterate through the IFD
            for tag, tag_value in exif_dict[ifd].items():
                tag_info = piexif.TAGS[ifd].get(tag, {})

                # Get the human-readable name for the tag
                tag_name = (
                    tag_info.get("name", "Unknown Tag") if tag_info else "Unknown Tag"
                )

                # Exclude tags necessary for image display integrity
                if (
                    tag_name == "Orientation"
                    or tag_name == "ColorSpace"
                    or tag_name == "ExifTag"
                ):
                    continue

                # Save to list and dict
                self.tags_to_delete.append(tag)
                self.data[tag_name] = tag_value

        return {"data": self.data, "tags_to_delete": self.tags_to_delete}

    def delete_metadata(self, img, tags_to_delete):
        """
        Remove specified EXIF tags from a JPEG image.

        Args:
            img: PIL Image object with EXIF data.
            tags_to_delete: List of tag IDs to remove.

        Returns:
            Modified EXIF dictionary with specified tags removed.

        Raises:
            MetadataProcessingError: If an error occurs during processing.
        """
        try:
            exif_dict = piexif.load(img.info["exif"])
            for ifd, value in exif_dict.items():
                # Exclude thumbnail IFD
                if not isinstance(exif_dict[ifd], dict):
                    continue

                # Iterate through and delete tags
                for tag in list(exif_dict[ifd]):
                    if tag in tags_to_delete:
                        del exif_dict[ifd][tag]

            return exif_dict
        except Exception as e:
            raise MetadataProcessingError(f"Error Processing: {str(e)}")
