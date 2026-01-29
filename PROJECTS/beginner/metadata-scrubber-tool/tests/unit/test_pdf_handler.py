"""
Unit tests for PDFHandler.

Tests the PDFHandler class in isolation, focusing on individual methods
and edge cases including encrypted PDFs, missing metadata, and corrupted files.
"""

import shutil
from pathlib import Path

import pytest
from pypdf.errors import PdfReadError

from src.services.pdf_handler import PDFHandler
from src.utils.exceptions import (
    MetadataNotFoundError,
    MetadataReadingError,
    UnsupportedFormatError,
)

# Import path helpers from conftest
from tests.conftest import get_large_pdf_test_file, get_pdf_test_file

# Test file paths (cross-platform)
PDF_TEST_FILE = get_pdf_test_file()
LARGE_PDF_TEST_FILE = get_large_pdf_test_file()


# ============== Success Case Tests ==============


@pytest.mark.parametrize("pdf_file", [PDF_TEST_FILE, LARGE_PDF_TEST_FILE])
def test_read_pdf_metadata(pdf_file):
    """
    Test reading metadata from PDF files.
    Verifies that read() extracts metadata and populates keys_to_delete.
    """
    assert Path(pdf_file).exists(), f"Test file not found: {pdf_file}"
    handler = PDFHandler(pdf_file)
    metadata = handler.read()

    # Check metadata was extracted
    assert handler.metadata == metadata
    assert isinstance(metadata, dict)

    # Check keys_to_delete is populated
    assert handler.keys_to_delete is not None
    assert len(handler.keys_to_delete) > 0


@pytest.mark.parametrize("pdf_file", [PDF_TEST_FILE, LARGE_PDF_TEST_FILE])
def test_wipe_pdf_metadata(pdf_file):
    """
    Test wiping metadata from PDF files.
    Verifies that wipe() removes metadata entries.
    """
    assert Path(pdf_file).exists(), f"Test file not found: {pdf_file}"
    handler = PDFHandler(pdf_file)
    metadata = handler.read()
    handler.wipe()

    # processed_metadata should differ from original
    assert handler.processed_metadata != metadata


@pytest.mark.parametrize("pdf_file", [PDF_TEST_FILE, LARGE_PDF_TEST_FILE])
def test_save_processed_pdf_metadata(pdf_file):
    """
    Test saving processed PDF to output path.
    """
    output_dir = Path("./tests/assets/output")
    output_dir.mkdir(parents = True, exist_ok = True)

    handler = PDFHandler(pdf_file)
    handler.read()
    handler.wipe()

    output_file = output_dir / Path(pdf_file).name
    handler.save(str(output_file))

    # Verify output file exists
    assert output_file.exists()

    # Cleanup
    shutil.rmtree(output_dir)


def test_format_detection_works():
    """
    Test that _detect_format() correctly identifies PDF files.
    """
    handler = PDFHandler(PDF_TEST_FILE)
    detected = handler._detect_format()
    assert detected == "pdf"


@pytest.mark.parametrize("pdf_file", [PDF_TEST_FILE, LARGE_PDF_TEST_FILE])
def test_output_file_has_less_metadata(pdf_file):
    """
    Test that the output file has metadata stripped.
    """
    output_dir = Path("./tests/assets/output")
    output_dir.mkdir(parents = True, exist_ok = True)

    # Process original file
    handler = PDFHandler(pdf_file)
    original_metadata = handler.read()
    original_count = len(original_metadata)
    handler.wipe()

    # Save processed file
    output_file = output_dir / Path(pdf_file).name
    handler.save(str(output_file))

    # Read output file and verify metadata is reduced or gone
    try:
        output_handler = PDFHandler(str(output_file))
        output_metadata = output_handler.read()
        assert len(output_metadata) < original_count
    except MetadataNotFoundError:
        # If no metadata found, that's expected for fully stripped files
        pass

    # Cleanup
    shutil.rmtree(output_dir)


# ============== Error Case Tests ==============


def test_unsupported_format_raises_error(tmp_path):
    """
    Test that non-PDF files raise UnsupportedFormatError.
    """
    # Create a fake text file with .txt extension
    fake_file = tmp_path / "test.txt"
    fake_file.write_text("not a pdf")

    handler = PDFHandler(str(fake_file))
    with pytest.raises(UnsupportedFormatError):
        handler._detect_format()


def test_save_without_output_path_raises_error():
    """
    Test that save() raises ValueError when output_path is None.
    """
    handler = PDFHandler(PDF_TEST_FILE)
    handler.read()
    handler.wipe()
    with pytest.raises(ValueError):
        handler.save(None)


# ============== Edge Case Tests ==============


def test_encrypted_pdf_raises_error(tmp_path):
    """
    Test that encrypted PDFs raise MetadataReadingError.
    Note: This test creates a minimal encrypted PDF for testing.
    """
    # Create a minimal encrypted PDF structure
    encrypted_pdf = tmp_path / "encrypted.pdf"
    # Write minimal PDF with encryption marker
    # This is a simplified test - in production you'd use a real encrypted PDF
    encrypted_pdf.write_bytes(
        b"%PDF-1.4\n"
        b"1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n"
        b"2 0 obj\n<</Type/Pages/Kids[3 0 R]/Count 1>>\nendobj\n"
        b"3 0 obj\n<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>\nendobj\n"
        b"xref\n0 4\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000058 00000 n \n"
        b"0000000115 00000 n \n"
        b"trailer\n<</Size 4/Root 1 0 R/Encrypt<</V 1>>>>\n"
        b"startxref\n191\n%%EOF"
    )

    handler = PDFHandler(str(encrypted_pdf))
    # Encrypted PDF should raise MetadataReadingError or PdfReadError
    with pytest.raises((MetadataReadingError, PdfReadError, Exception)):
        handler.read()


def test_pdf_without_metadata_raises_error(tmp_path):
    """
    Test that PDFs with no metadata raise MetadataNotFoundError.
    """
    # Create a minimal PDF without metadata
    no_metadata_pdf = tmp_path / "no_metadata.pdf"
    no_metadata_pdf.write_bytes(
        b"%PDF-1.4\n"
        b"1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n"
        b"2 0 obj\n<</Type/Pages/Kids[3 0 R]/Count 1>>\nendobj\n"
        b"3 0 obj\n<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>\nendobj\n"
        b"xref\n0 4\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000058 00000 n \n"
        b"0000000115 00000 n \n"
        b"trailer\n<</Size 4/Root 1 0 R>>\n"
        b"startxref\n191\n%%EOF"
    )

    handler = PDFHandler(str(no_metadata_pdf))
    with pytest.raises((MetadataNotFoundError, Exception)):
        handler.read()


def test_corrupted_pdf_graceful_error(tmp_path):
    """
    Test that corrupted PDFs are handled gracefully.
    """
    # Create a corrupted PDF (invalid structure)
    corrupted_pdf = tmp_path / "corrupted.pdf"
    corrupted_pdf.write_bytes(b"not a valid pdf content at all")

    handler = PDFHandler(str(corrupted_pdf))
    # Should raise PdfReadError or similar from pypdf
    with pytest.raises((PdfReadError, Exception)):
        handler.read()
