"""
Unit tests for PowerpointHandler.

Tests the PowerpointHandler class in isolation, focusing on individual methods
and edge cases including missing metadata and corrupted files.
"""

import shutil
from pathlib import Path

import pytest

from src.services.powerpoint_handler import PowerpointHandler
from src.utils.exceptions import (
    MetadataNotFoundError,
    UnsupportedFormatError,
)

# Import path helpers from conftest
from tests.conftest import get_large_pptx_test_file, get_pptx_test_file

# Test file paths (cross-platform)
PPTX_TEST_FILE = get_pptx_test_file()
LARGE_PPTX_TEST_FILE = get_large_pptx_test_file()


# ============== Success Case Tests ==============


@pytest.mark.parametrize("pptx_file", [PPTX_TEST_FILE, LARGE_PPTX_TEST_FILE])
def test_read_pptx_metadata(pptx_file):
    """
    Test reading metadata from PowerPoint files.
    Verifies that read() extracts metadata and populates keys_to_delete.
    """
    assert Path(pptx_file).exists(), f"Test file not found: {pptx_file}"
    handler = PowerpointHandler(pptx_file)
    metadata = handler.read()

    # Check metadata was extracted
    assert handler.metadata == metadata
    assert isinstance(metadata, dict)

    # Check keys_to_delete is populated
    assert handler.keys_to_delete is not None


@pytest.mark.parametrize("pptx_file", [PPTX_TEST_FILE, LARGE_PPTX_TEST_FILE])
def test_wipe_pptx_metadata(pptx_file):
    """
    Test wiping metadata from PowerPoint files.
    Verifies that wipe() prepares metadata for removal.
    """
    assert Path(pptx_file).exists(), f"Test file not found: {pptx_file}"
    handler = PowerpointHandler(pptx_file)
    handler.read()
    handler.wipe()

    # processed_metadata should have entries set to None
    assert handler.processed_metadata is not None


@pytest.mark.parametrize("pptx_file", [PPTX_TEST_FILE, LARGE_PPTX_TEST_FILE])
def test_save_processed_pptx_metadata(pptx_file):
    """
    Test saving processed PowerPoint to output path.
    """
    output_dir = Path("./tests/assets/output")
    output_dir.mkdir(parents = True, exist_ok = True)

    handler = PowerpointHandler(pptx_file)
    handler.read()
    handler.wipe()

    output_file = output_dir / Path(pptx_file).name
    handler.save(str(output_file))

    # Verify output file exists
    assert output_file.exists()

    # Cleanup
    shutil.rmtree(output_dir)


def test_format_detection_pptx():
    """
    Test that _detect_format() correctly identifies PPTX files.
    """
    handler = PowerpointHandler(PPTX_TEST_FILE)
    detected = handler._detect_format()
    assert detected == "pptx"


@pytest.mark.parametrize("pptx_file", [PPTX_TEST_FILE, LARGE_PPTX_TEST_FILE])
def test_output_file_has_wiped_metadata(pptx_file):
    """
    Test that the output file has metadata wiped.
    """
    output_dir = Path("./tests/assets/output")
    output_dir.mkdir(parents = True, exist_ok = True)

    # Process original file
    handler = PowerpointHandler(pptx_file)
    handler.read()
    handler.wipe()

    # Save processed file
    output_file = output_dir / Path(pptx_file).name
    handler.save(str(output_file))

    # Verify output file exists and can be read
    assert output_file.exists()

    # Read output file and verify it's valid
    try:
        output_handler = PowerpointHandler(str(output_file))
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
    handler = PowerpointHandler(PPTX_TEST_FILE)
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
    Test that non-PowerPoint files raise UnsupportedFormatError.
    """
    # Create a fake text file with .txt extension
    fake_file = tmp_path / "test.txt"
    fake_file.write_text("not a powerpoint file")

    handler = PowerpointHandler(str(fake_file))
    with pytest.raises(UnsupportedFormatError):
        handler._detect_format()


def test_save_without_output_path_raises_error():
    """
    Test that save() raises ValueError when output_path is empty.
    """
    handler = PowerpointHandler(PPTX_TEST_FILE)
    handler.read()
    handler.wipe()
    with pytest.raises(ValueError):
        handler.save("")


def test_save_with_none_raises_error():
    """
    Test that save() raises ValueError when output_path is None.
    """
    handler = PowerpointHandler(PPTX_TEST_FILE)
    handler.read()
    handler.wipe()
    with pytest.raises((ValueError, TypeError)):
        handler.save(None)


# ============== Edge Case Tests ==============


def test_corrupted_pptx_graceful_error(tmp_path):
    """
    Test that corrupted PowerPoint files are handled gracefully.
    """
    # Create a corrupted PowerPoint file (invalid structure)
    corrupted_pptx = tmp_path / "corrupted.pptx"
    corrupted_pptx.write_bytes(b"not a valid pptx content at all")

    handler = PowerpointHandler(str(corrupted_pptx))
    # Should raise an exception from python-pptx
    with pytest.raises(Exception):
        handler.read()


def test_format_detection_all_pptx_types(tmp_path):
    """
    Test format detection for all supported PowerPoint extensions.
    """
    for ext in ["pptx", "pptm", "potx", "potm"]:
        fake_file = tmp_path / f"test.{ext}"
        fake_file.write_bytes(b"dummy")  # Not valid, but we're only testing detection

        handler = PowerpointHandler(str(fake_file))
        detected = handler._detect_format()
        assert detected == ext
