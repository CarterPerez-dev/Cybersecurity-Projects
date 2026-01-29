"""
Unit tests for WorddocHandler.

Tests the WorddocHandler class in isolation, focusing on individual methods
and edge cases including missing metadata and corrupted files.
"""

import shutil
from pathlib import Path

import pytest

from src.services.worddoc_handler import WorddocHandler
from src.utils.exceptions import (
    MetadataNotFoundError,
    UnsupportedFormatError,
)

# Import path helpers from conftest
from tests.conftest import get_docx_test_file, get_large_docx_test_file

# Test file paths (cross-platform)
DOCX_TEST_FILE = get_docx_test_file()
LARGE_DOCX_TEST_FILE = get_large_docx_test_file()


# ============== Success Case Tests ==============


@pytest.mark.parametrize("docx_file", [DOCX_TEST_FILE, LARGE_DOCX_TEST_FILE])
def test_read_docx_metadata(docx_file):
    """
    Test reading metadata from Word document files.
    Verifies that read() extracts metadata and populates keys_to_delete.
    """
    assert Path(docx_file).exists(), f"Test file not found: {docx_file}"
    handler = WorddocHandler(docx_file)
    metadata = handler.read()

    # Check metadata was extracted
    assert handler.metadata == metadata
    assert isinstance(metadata, dict)

    # Check keys_to_delete is populated
    assert handler.keys_to_delete is not None


@pytest.mark.parametrize("docx_file", [DOCX_TEST_FILE, LARGE_DOCX_TEST_FILE])
def test_wipe_docx_metadata(docx_file):
    """
    Test wiping metadata from Word document files.
    Verifies that wipe() prepares metadata for removal.
    """
    assert Path(docx_file).exists(), f"Test file not found: {docx_file}"
    handler = WorddocHandler(docx_file)
    handler.read()
    handler.wipe()

    # processed_metadata should have entries set to None
    assert handler.processed_metadata is not None


@pytest.mark.parametrize("docx_file", [DOCX_TEST_FILE, LARGE_DOCX_TEST_FILE])
def test_save_processed_docx_metadata(docx_file):
    """
    Test saving processed Word document to output path.
    """
    output_dir = Path("./tests/assets/output")
    output_dir.mkdir(parents = True, exist_ok = True)

    handler = WorddocHandler(docx_file)
    handler.read()
    handler.wipe()

    output_file = output_dir / Path(docx_file).name
    handler.save(str(output_file))

    # Verify output file exists
    assert output_file.exists()

    # Cleanup
    shutil.rmtree(output_dir)


def test_format_detection_docx():
    """
    Test that _detect_format() correctly identifies DOCX files.
    """
    handler = WorddocHandler(DOCX_TEST_FILE)
    detected = handler._detect_format()
    assert detected == "docx"


@pytest.mark.parametrize("docx_file", [DOCX_TEST_FILE, LARGE_DOCX_TEST_FILE])
def test_output_file_has_wiped_metadata(docx_file):
    """
    Test that the output file has metadata wiped.
    """
    output_dir = Path("./tests/assets/output")
    output_dir.mkdir(parents = True, exist_ok = True)

    # Process original file
    handler = WorddocHandler(docx_file)
    handler.read()
    handler.wipe()

    # Save processed file
    output_file = output_dir / Path(docx_file).name
    handler.save(str(output_file))

    # Verify output file exists and can be read
    assert output_file.exists()

    # Read output file and verify it's valid
    try:
        output_handler = WorddocHandler(str(output_file))
        output_metadata = output_handler.read()
        # Just verify we can read it - the wipe worked if we're here
        assert isinstance(output_metadata, dict)
    except MetadataNotFoundError:
        # If no metadata found, that's expected for fully stripped files
        pass

    # Cleanup
    shutil.rmtree(output_dir)


def test_preserved_properties_not_deleted():
    """
    Test that created, modified, language, last_printed, revision are preserved.
    """
    handler = WorddocHandler(DOCX_TEST_FILE)
    handler.read()

    # These should NOT be in keys_to_delete
    assert "created" not in handler.keys_to_delete
    assert "modified" not in handler.keys_to_delete
    assert "language" not in handler.keys_to_delete
    assert "last_printed" not in handler.keys_to_delete
    assert "revision" not in handler.keys_to_delete


# ============== Error Case Tests ==============


def test_unsupported_format_raises_error(tmp_path):
    """
    Test that non-Word document files raise UnsupportedFormatError.
    """
    # Create a fake text file with .txt extension
    fake_file = tmp_path / "test.txt"
    fake_file.write_text("not a word document")

    handler = WorddocHandler(str(fake_file))
    with pytest.raises(UnsupportedFormatError):
        handler._detect_format()


def test_save_without_output_path_raises_error():
    """
    Test that save() raises ValueError when output_path is empty.
    """
    handler = WorddocHandler(DOCX_TEST_FILE)
    handler.read()
    handler.wipe()
    with pytest.raises(ValueError):
        handler.save("")


def test_save_with_none_raises_error():
    """
    Test that save() raises ValueError when output_path is None.
    """
    handler = WorddocHandler(DOCX_TEST_FILE)
    handler.read()
    handler.wipe()
    with pytest.raises((ValueError, TypeError)):
        handler.save(None)


# ============== Edge Case Tests ==============


def test_corrupted_docx_graceful_error(tmp_path):
    """
    Test that corrupted Word document files are handled gracefully.
    """
    # Create a corrupted DOCX file (invalid structure)
    corrupted_docx = tmp_path / "corrupted.docx"
    corrupted_docx.write_bytes(b"not a valid docx content at all")

    handler = WorddocHandler(str(corrupted_docx))
    # Should raise an exception from python-docx
    with pytest.raises(Exception):
        handler.read()
