"""
PNG metadata processor using PIL.

This module provides the PngProcessor class which handles EXIF metadata
extraction and manipulation for PNG images using PIL's built-in EXIF support.
"""

from PIL import ExifTags

from src.utils.exceptions import MetadataNotFoundError, MetadataProcessingError


class PngProcessor:
    """
    Processor for PNG image metadata.

    Handles reading, extracting, and deleting EXIF metadata from PNG files.
    Processes both standard EXIF tags and GPS IFD data.

    Attributes:
        tags_to_delete: List of EXIF tag IDs to remove.
        data: Dict of extracted metadata with human-readable keys.
    """

    def __init__(self):
        """Initialize the PNG processor with empty data structures."""
        self.tags_to_delete = []
        self.data = {}

    def get_metadata(self, img):
        """
        Extract EXIF metadata from a PNG image.

        Args:
            img: PIL Image object.

        Returns:
            Dict with 'data' (metadata dict) and 'tags_to_delete' (tag IDs list).

        Raises:
            MetadataNotFoundError: If no EXIF data is found in the image.
        """
        img.load()
        exif = img.getexif()

        if not exif:
            raise MetadataNotFoundError("No EXIF data found in the image.")

        # Iterate through the (0th) IFD
        for tag, value in exif.items():
            # Get the human-readable name for the tag
            tag_name = ExifTags.TAGS.get(tag, tag)

            # Save to list and dict
            self.tags_to_delete.append(tag)
            self.data[tag_name] = value
            print(f"{tag_name}: {value}")

        # Iterate through the (GPS) IFD
        gps_ifd = exif.get_ifd(ExifTags.IFD.GPSInfo)
        for tag, value in gps_ifd.items():
            # Get the human-readable name for the tag
            tag_name = ExifTags.GPSTAGS.get(tag, tag)

            # Save to list and dict
            self.tags_to_delete.append(tag)
            self.data[tag_name] = value
            print(f"{tag_name}: {value}")

        return {"data": self.data, "tags_to_delete": self.tags_to_delete}

    def delete_metadata(self, img, tags_to_delete):
        """
        Remove specified EXIF tags from a PNG image.

        Args:
            img: PIL Image object.
            tags_to_delete: List of tag IDs to remove.

        Returns:
            Modified EXIF data with specified tags removed.

        Raises:
            MetadataProcessingError: If an error occurs during processing.
        """
        img.load()
        exif = img.getexif()
        try:
            # Iterate through the (0th) IFD
            for tag_id, value in exif.items():
                if tag_id in tags_to_delete:
                    del exif[tag_id]

            # Iterate through the (GPS) IFD
            gps_ifd = exif.get_ifd(ExifTags.IFD.GPSInfo)
            for tag_id, value in gps_ifd.items():
                if tag_id in tags_to_delete:
                    del gps_ifd[tag_id]

            return exif + gps_ifd
        except Exception as e:
            raise MetadataProcessingError(f"Error Processing image: {str(e)}")
