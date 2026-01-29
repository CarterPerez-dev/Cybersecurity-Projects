"""
Custom exceptions for metadata processing operations.

This module defines a hierarchy of exceptions used throughout the
metadata scrubber tool for handling various error conditions.
"""


class MetadataException(Exception):
    """Base class for all metadata-related exceptions."""


class UnsupportedFormatError(MetadataException):
    """Raised when attempting to process an unsupported file format."""


class MetadataNotFoundError(MetadataException):
    """Raised when no metadata is found in a file."""


class MetadataProcessingError(MetadataException):
    """Raised when an error occurs during metadata processing."""


class MetadataReadingError(MetadataException):
    """Raised when an error occurs during metadata reading."""
