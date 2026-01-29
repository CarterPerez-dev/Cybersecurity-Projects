"""
Factory for creating metadata handlers.

This module provides the MetadataFactory class which uses the factory pattern
to create appropriate handler instances based on file type. It enables
extensibility for supporting new file formats (PDF, Office docs, etc.).
"""

from pathlib import Path

from src.services.excel_handler import ExcelHandler
from src.services.image_handler import ImageHandler
from src.services.pdf_handler import PDFHandler
from src.services.powerpoint_handler import PowerpointHandler
from src.services.worddoc_handler import WorddocHandler
from src.utils.exceptions import UnsupportedFormatError


class MetadataFactory:
    """
    Factory class for creating metadata handlers.

    Uses the factory pattern to return the appropriate handler instance
    based on file extension. This design allows easy extension to support
    new file types without modifying existing code.

    Supported formats:
        - Images: .jpg, .jpeg, .png
        - Future: .pdf, .docx, .xlsx, .pptx
    """
    @staticmethod
    def get_handler(filepath: str):
        """
        Create and return the appropriate metadata handler for a file.

        Args:
            filepath: Path to the file to process.

        Returns:
            MetadataHandler: An instance of the appropriate handler subclass.

        Raises:
            UnsupportedFormatError: If no handler is defined for the file type.
            ValueError: If the path is not a valid file.
        """
        supported_extensions = ".jpg, .jpeg, .png, .pdf, .docx, .xlsx, .xlsm, .xltx, .xltm, .pptx, .pptm, .potx, .potm"
        ext = Path(filepath).suffix.lower()
        if Path(filepath).is_file():
            if ext in [".jpg", ".jpeg", ".png"]:
                return ImageHandler(filepath)
            elif ext == ".pdf":
                return PDFHandler(filepath)
            elif ext in [".xlsx", ".xlsm", ".xltx", ".xltm"]:
                return ExcelHandler(filepath)
            elif ext in [".pptx", ".pptm", ".potx", ".potm"]:
                return PowerpointHandler(filepath)
            elif ext == ".docx":
                return WorddocHandler(filepath)
            else:
                raise UnsupportedFormatError(
                    f"No handler defined for {ext} files. we curently only support {supported_extensions} files."
                )
        else:
            raise ValueError(
                f"{filepath} is not a file. if you want to process a directory, use the --recursive or -r flag."
            )
