"""
E2E tests for the 'scrub' command.

Tests the full CLI flow for scrubbing metadata from files.
"""

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
EXAMPLES_DIR = get_test_images_dir()


@pytest.fixture
def output_dir(tmp_path):
    """Create isolated output directory for each test using tmp_path."""
    output = tmp_path / "output"
    output.mkdir(parents=True, exist_ok=True)
    return output


# ============== Success Case Tests ==============


@pytest.mark.parametrize("x", [JPG_TEST_FILE, PNG_TEST_FILE])
def test_scrub_command_single_file_success(x, output_dir):
    """
    Test the 'scrub' command with a single file.
    """
    result = runner.invoke(app, ["scrub", x, "--output", str(output_dir)])

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    # Check output file was created (has processed_ prefix)
    output_file = output_dir / f"processed_{Path(x).name}"
    assert output_file.exists()


def test_scrub_command_recursive_jpg_success(output_dir):
    """
    Test the 'scrub' command with recursive directory processing for JPG.
    Uses examples folder (smaller) for faster tests.
    """
    result = runner.invoke(
        app, ["scrub", EXAMPLES_DIR, "-r", "-ext", "jpg", "--output", str(output_dir)]
    )

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    # Check at least one output file was created
    output_files = list(output_dir.glob("processed_*.jpg"))
    assert len(output_files) > 0


def test_scrub_command_dry_run(output_dir):
    """
    Test that --dry-run doesn't create files.
    """
    result = runner.invoke(
        app, ["scrub", JPG_TEST_FILE, "--output", str(output_dir), "--dry-run"]
    )

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    assert "DRY-RUN" in result.stdout
    # No files should be created in dry-run mode
    output_file = output_dir / f"processed_{Path(JPG_TEST_FILE).name}"
    assert not output_file.exists()


def test_scrub_command_with_workers(output_dir):
    """
    Test the --workers option for concurrent processing.
    """
    result = runner.invoke(
        app,
        [
            "scrub",
            EXAMPLES_DIR,
            "-r",
            "-ext",
            "jpg",
            "--output",
            str(output_dir),
            "--workers",
            "2",
        ],
    )

    assert result.exit_code == 0, f"Failed with: {result.stdout}"


# ============== Error Case Tests ==============


def test_scrub_command_file_not_found():
    """
    Test that the app handles missing files gracefully.
    """
    result = runner.invoke(app, ["scrub", "ghost_file.jpg"])

    assert result.exit_code == 2
    assert "Invalid value" in result.stderr


def test_scrub_command_requires_ext_with_recursive():
    """
    Test that --recursive requires --extension flag.
    """
    result = runner.invoke(app, ["scrub", EXAMPLES_DIR, "-r"])

    assert result.exit_code != 0


def test_scrub_command_requires_recursive_with_ext():
    """
    Test that --extension requires --recursive flag.
    """
    result = runner.invoke(app, ["scrub", JPG_TEST_FILE, "-ext", "jpg"])

    assert result.exit_code != 0
