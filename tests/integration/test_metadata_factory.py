import shutil
from pathlib import Path

import pytest

from src.services.metadata_factory import MetadataFactory
from src.utils.exceptions import MetadataNotFoundError, UnsupportedFormatError

# Import path helpers from conftest
from tests.conftest import get_jpg_test_file, get_png_test_file

# Test file paths (cross-platform)
JPG_TEST_FILE = get_jpg_test_file()
PNG_TEST_FILE = get_png_test_file()


# ============== Success Case Tests ==============


@pytest.mark.parametrize("x", [JPG_TEST_FILE, PNG_TEST_FILE])
def test_read_image_metadata(x):
    """
    test for reading image metadata
    """
    # checks if file exists
    assert Path(x).exists(), f"Test file not found: {x}"
    handler = MetadataFactory.get_handler(str(x))
    metadata = handler.read()

    # checks if metadata is not empty
    assert handler.metadata == metadata

    # checks if tags_to_delete or text_keys_to_delete is not empty
    assert handler.tags_to_delete is not None or handler.text_keys_to_delete is not None

    # checks if metadata is a dictionary
    assert isinstance(metadata, dict)


@pytest.mark.parametrize("x", [JPG_TEST_FILE, PNG_TEST_FILE])
def test_wipe_image_metadata(x):
    """
    test for wiping image metadata
    """
    # checks if file exists
    assert Path(x).exists(), f"Test file not found: {x}"
    handler = MetadataFactory.get_handler(str(x))
    metadata = handler.read()
    handler.wipe()

    # checks if processed_metadata is not equal to metadata
    assert handler.processed_metadata != metadata


@pytest.mark.parametrize("x", [JPG_TEST_FILE, PNG_TEST_FILE])
def test_save_processed_image_metadata(x):
    """
    test for saving image processed metadata to a copy of the file
    """
    # creates output directory
    output_dir = Path("./tests/assets/output")
    output_dir.mkdir(parents=True, exist_ok=True)

    handler = MetadataFactory.get_handler(str(x))
    metadata = handler.read()
    handler.wipe()

    # checks if processed_metadata is not equal to metadata
    assert handler.processed_metadata != metadata

    # Pass full file path
    output_file = output_dir / Path(x).name
    handler.save(str(output_file))

    # checks if output file exists and then deletes it
    assert output_file.exists()
    shutil.rmtree(output_dir)


@pytest.mark.parametrize("x", [JPG_TEST_FILE, PNG_TEST_FILE])
def test_output_file_has_less_metadata(x):
    """
    Test that the output file has metadata stripped
    """
    output_dir = Path("./tests/assets/output")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Process original file
    handler = MetadataFactory.get_handler(str(x))
    original_metadata = handler.read()
    original_count = len(original_metadata)
    handler.wipe()

    # Save processed file
    output_file = output_dir / Path(x).name
    handler.save(str(output_file))

    # Read output file and verify metadata is reduced or gone
    try:
        output_processor = MetadataFactory.get_handler(str(output_file))
        output_metadata = output_processor.read()
        # Output should have fewer metadata entries
        assert len(output_metadata) < original_count
    except MetadataNotFoundError:
        # If no metadata found, that's expected for fully stripped files
        pass
    # clean up
    shutil.rmtree(output_dir)


def test_format_detection_works():
    """
    Test that format detection uses Pillow, not file extension
    """
    handler = MetadataFactory.get_handler(JPG_TEST_FILE)
    detected = handler._detect_format()
    assert detected == "jpeg"

    handler_png = MetadataFactory.get_handler(PNG_TEST_FILE)
    detected_png = handler_png._detect_format()
    assert detected_png == "png"


# ============== Error Case Tests ==============


def test_unsupported_format_raises_error(tmp_path):
    """
    Test that unsupported file formats raise an error
    """
    # Create a fake text file
    fake_file = tmp_path / "test.txt"
    fake_file.write_text("not an image")

    # MetadataFactory.get_handler() raises UnsupportedFormatError for .txt files
    with pytest.raises(UnsupportedFormatError):
        MetadataFactory.get_handler(str(fake_file))


def test_save_without_output_path_raises_error():
    """
    Test that save() raises ValueError when output_path is None
    """
    handler = MetadataFactory.get_handler(JPG_TEST_FILE)
    handler.read()
    handler.wipe()
    with pytest.raises(ValueError):
        handler.save(None)
