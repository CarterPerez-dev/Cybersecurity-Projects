"""
Custom exceptions for metadata processing operations.

This module defines a hierarchy of exceptions used throughout the
metadata scrubber tool for handling various error conditions.
"""


class MetadataException(Exception):
    """Base class for all metadata-related exceptions."""

    pass


class UnsupportedFormatError(MetadataException):
    """Raised when attempting to process an unsupported file format."""

    pass


class MetadataNotFoundError(MetadataException):
    """Raised when no metadata is found in a file."""

    pass


class MetadataProcessingError(MetadataException):
    """Raised when an error occurs during metadata processing."""

    pass
