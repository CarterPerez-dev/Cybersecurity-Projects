from pathlib import Path

import pytest
from typer.testing import CliRunner

from src.main import app

# Import path helpers from conftest
from tests.conftest import get_jpg_test_file, get_png_test_file, get_test_images_dir

runner = CliRunner()

# Test file paths (cross-platform)
JPG_TEST_FILE = get_jpg_test_file()
PNG_TEST_FILE = get_png_test_file()
TEST_DIR = get_test_images_dir()


# ============== Success Case Tests ==============


@pytest.mark.parametrize("x", [JPG_TEST_FILE, PNG_TEST_FILE])
def test_read_command_single_file_success(x):
    """
    Test the 'read' command with a single file (JPG and PNG).
    """
    result = runner.invoke(app, ["read", str(x)])

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    assert "Reading" in result.stdout
    assert Path(x).name in result.stdout


@pytest.mark.parametrize("ext", ["jpg", "png"])
def test_read_command_recursive_directory_success(ext):
    """
    Test the 'read' command with recursive directory processing.
    """
    result = runner.invoke(app, ["read", TEST_DIR, "-r", "-ext", ext])

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    assert "Reading" in result.stdout


def test_read_command_requires_ext_with_recursive():
    """
    Test that --recursive requires --extension flag.
    """
    result = runner.invoke(app, ["read", TEST_DIR, "-r"])

    assert result.exit_code != 0
    # Should fail with bad parameter error


def test_read_command_requires_recursive_with_ext():
    """
    Test that --extension requires --recursive flag.
    """
    result = runner.invoke(app, ["read", JPG_TEST_FILE, "-ext", "jpg"])

    assert result.exit_code != 0


# ============== Error Case Tests ==============


def test_read_command_file_not_found():
    """
    Test that the app handles missing files gracefully.
    """
    result = runner.invoke(app, ["read", "ghost_file.jpg"])

    # Typer returns exit code 2 (Usage Error) for bad arguments
    assert result.exit_code == 2
    assert "Invalid value for 'FILE_PATH'" in result.stderr
    assert "does not exist" in result.stderr
