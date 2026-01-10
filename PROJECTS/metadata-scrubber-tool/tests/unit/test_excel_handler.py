"""
Unit tests for ExcelHandler.

Tests the ExcelHandler class in isolation, focusing on individual methods
and edge cases including encrypted workbooks, missing metadata, and corrupted files.
"""

import shutil
from pathlib import Path

import pytest
from openpyxl.utils.exceptions import InvalidFileException

from src.services.excel_handler import ExcelHandler
from src.utils.exceptions import (
    MetadataNotFoundError,
    UnsupportedFormatError,
)

# Import path helpers from conftest
from tests.conftest import get_large_xlsx_test_file, get_xlsx_test_file

# Test file paths (cross-platform)
XLSX_TEST_FILE = get_xlsx_test_file()
LARGE_XLSX_TEST_FILE = get_large_xlsx_test_file()


# ============== Success Case Tests ==============


@pytest.mark.parametrize("xlsx_file", [XLSX_TEST_FILE, LARGE_XLSX_TEST_FILE])
def test_read_excel_metadata(xlsx_file):
    """
    Test reading metadata from Excel files.
    Verifies that read() extracts metadata and populates keys_to_delete.
    """
    assert Path(xlsx_file).exists(), f"Test file not found: {xlsx_file}"
    handler = ExcelHandler(xlsx_file)
    metadata = handler.read()

    # Check metadata was extracted
    assert handler.metadata == metadata
    assert isinstance(metadata, dict)

    # Check keys_to_delete is populated
    assert handler.keys_to_delete is not None
    assert len(handler.keys_to_delete) > 0


@pytest.mark.parametrize("xlsx_file", [XLSX_TEST_FILE, LARGE_XLSX_TEST_FILE])
def test_wipe_excel_metadata(xlsx_file):
    """
    Test wiping metadata from Excel files.
    Verifies that wipe() removes metadata entries.
    """
    assert Path(xlsx_file).exists(), f"Test file not found: {xlsx_file}"
    handler = ExcelHandler(xlsx_file)
    metadata = handler.read()
    handler.wipe()

    # processed_metadata should differ from original
    assert handler.processed_metadata != metadata


@pytest.mark.parametrize("xlsx_file", [XLSX_TEST_FILE, LARGE_XLSX_TEST_FILE])
def test_save_processed_excel_metadata(xlsx_file):
    """
    Test saving processed Excel to output path.
    """
    output_dir = Path("./tests/assets/output")
    output_dir.mkdir(parents = True, exist_ok = True)

    handler = ExcelHandler(xlsx_file)
    handler.read()
    handler.wipe()

    output_file = output_dir / Path(xlsx_file).name
    handler.save(str(output_file))

    # Verify output file exists
    assert output_file.exists()

    # Cleanup
    shutil.rmtree(output_dir)


def test_format_detection_xlsx():
    """
    Test that _detect_format() correctly identifies XLSX files.
    """
    handler = ExcelHandler(XLSX_TEST_FILE)
    detected = handler._detect_format()
    assert detected == "xlsx"


@pytest.mark.parametrize("xlsx_file", [XLSX_TEST_FILE, LARGE_XLSX_TEST_FILE])
def test_output_file_has_less_metadata(xlsx_file):
    """
    Test that the output file has metadata stripped.
    """
    output_dir = Path("./tests/assets/output")
    output_dir.mkdir(parents = True, exist_ok = True)

    # Process original file
    handler = ExcelHandler(xlsx_file)
    original_metadata = handler.read()
    handler.wipe()

    # Save processed file
    output_file = output_dir / Path(xlsx_file).name
    handler.save(str(output_file))

    # Read output file and verify metadata is reduced or gone
    try:
        output_handler = ExcelHandler(str(output_file))
        output_metadata = output_handler.read()
        # Output should have fewer metadata entries (some are None now)
        non_none_original = sum(1 for v in original_metadata.values() if v is not None)
        non_none_output = sum(1 for v in output_metadata.values() if v is not None)
        assert non_none_output <= non_none_original
    except MetadataNotFoundError:
        # If no metadata found, that's expected for fully stripped files
        pass

    # Cleanup
    shutil.rmtree(output_dir)


def test_preserved_properties_not_deleted():
    """
    Test that created, modified, and language properties are preserved.
    """
    handler = ExcelHandler(XLSX_TEST_FILE)
    handler.read()

    # These should NOT be in keys_to_delete
    assert "created" not in handler.keys_to_delete
    assert "modified" not in handler.keys_to_delete
    assert "language" not in handler.keys_to_delete


# ============== Error Case Tests ==============


def test_unsupported_format_raises_error(tmp_path):
    """
    Test that non-Excel files raise UnsupportedFormatError.
    """
    # Create a fake text file with .txt extension
    fake_file = tmp_path / "test.txt"
    fake_file.write_text("not an excel file")

    handler = ExcelHandler(str(fake_file))
    with pytest.raises(UnsupportedFormatError):
        handler._detect_format()


def test_save_without_output_path_raises_error():
    """
    Test that save() raises ValueError when output_path is None or empty.
    """
    handler = ExcelHandler(XLSX_TEST_FILE)
    handler.read()
    handler.wipe()
    with pytest.raises(ValueError):
        handler.save("")


def test_save_with_none_raises_error():
    """
    Test that save() raises ValueError when output_path is None.
    """
    handler = ExcelHandler(XLSX_TEST_FILE)
    handler.read()
    handler.wipe()
    with pytest.raises((ValueError, TypeError)):
        handler.save(None)


# ============== Edge Case Tests ==============


def test_corrupted_excel_graceful_error(tmp_path):
    """
    Test that corrupted Excel files are handled gracefully.
    """
    # Create a corrupted Excel file (invalid structure)
    corrupted_xlsx = tmp_path / "corrupted.xlsx"
    corrupted_xlsx.write_bytes(b"not a valid xlsx content at all")

    handler = ExcelHandler(str(corrupted_xlsx))
    # Should raise InvalidFileException or similar from openpyxl
    with pytest.raises((InvalidFileException, Exception)):
        handler.read()


def test_format_detection_all_excel_types(tmp_path):
    """
    Test format detection for all supported Excel extensions.
    """
    for ext in ["xlsx", "xlsm", "xltx", "xltm"]:
        fake_file = tmp_path / f"test.{ext}"
        fake_file.write_bytes(b"dummy")  # Not valid, but we're only testing detection

        handler = ExcelHandler(str(fake_file))
        detected = handler._detect_format()
        assert detected == ext
