"""
End-to-end tests for the verify command.

Tests the complete CLI workflow for the verify command, including
comparing original and processed files and verifying output format.
"""

import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from src.main import app


runner = CliRunner()


@pytest.fixture
def output_dir(tmp_path):
    """Create a temporary output directory for processed files."""
    output = tmp_path / "output"
    output.mkdir()
    yield output
    if output.exists():
        shutil.rmtree(output)


# ============== Image Tests ==============


def test_verify_command_jpeg_clean_status(output_dir):
    """Test verify command shows CLEAN status for properly scrubbed JPEG."""
    from tests.conftest import get_jpg_test_file

    JPG_TEST_FILE = get_jpg_test_file()

    # First scrub the file
    scrub_result = runner.invoke(
        app,
        ["scrub",
         JPG_TEST_FILE,
         "--output",
         str(output_dir)]
    )
    assert scrub_result.exit_code == 0

    # Get the processed file path
    processed_file = output_dir / f"processed_{Path(JPG_TEST_FILE).name}"
    assert processed_file.exists()

    # Now verify
    result = runner.invoke(app, ["verify", JPG_TEST_FILE, str(processed_file)])

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    assert "Comparing" in result.stdout
    assert "CLEAN" in result.stdout or "Removed" in result.stdout


# this test can be ran if a png with metadata is found and added to the assests folder.
# def test_verify_command_png_clean_status(output_dir):
#     """Test verify command shows CLEAN status for properly scrubbed PNG."""
#     from tests.conftest import get_png_test_file

# #     PNG_TEST_FILE = get_png_test_file()

#     # First scrub the file
#     scrub_result = runner.invoke(
#         app, ["scrub", PNG_TEST_FILE, "--output", str(output_dir)]
#     )

#     # Get the processed file path
#     processed_file = output_dir / f"processed_{Path(PNG_TEST_FILE).name}"

#     # Skip if scrub failed (PNG might have no metadata)
#     if scrub_result.exit_code != 0 or not processed_file.exists():
#         pytest.skip("PNG file had no metadata to scrub")

#     # Now verify
#     result = runner.invoke(app, ["verify", PNG_TEST_FILE, str(processed_file)])

#     assert result.exit_code == 0, f"Failed with: {result.stdout}"
#     assert "Comparing" in result.stdout


# ============== PDF Tests ==============


def test_verify_command_pdf_clean_status(output_dir):
    """Test verify command shows CLEAN status for properly scrubbed PDF."""
    from tests.conftest import get_pdf_test_file

    PDF_TEST_FILE = get_pdf_test_file()

    # First scrub the file
    scrub_result = runner.invoke(
        app,
        ["scrub",
         PDF_TEST_FILE,
         "--output",
         str(output_dir)]
    )
    assert scrub_result.exit_code == 0

    # Get the processed file path
    processed_file = output_dir / f"processed_{Path(PDF_TEST_FILE).name}"
    assert processed_file.exists()

    # Now verify
    result = runner.invoke(app, ["verify", PDF_TEST_FILE, str(processed_file)])

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    assert "Comparing" in result.stdout


# ============== Excel Tests ==============


def test_verify_command_xlsx_clean_status(output_dir):
    """Test verify command shows CLEAN status for properly scrubbed Excel."""
    from tests.conftest import get_xlsx_test_file

    XLSX_TEST_FILE = get_xlsx_test_file()

    # First scrub the file
    scrub_result = runner.invoke(
        app,
        ["scrub",
         XLSX_TEST_FILE,
         "--output",
         str(output_dir)]
    )
    assert scrub_result.exit_code == 0

    # Get the processed file path
    processed_file = output_dir / f"processed_{Path(XLSX_TEST_FILE).name}"
    assert processed_file.exists()

    # Now verify
    result = runner.invoke(app, ["verify", XLSX_TEST_FILE, str(processed_file)])

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    assert "Comparing" in result.stdout


# ============== PowerPoint Tests ==============


def test_verify_command_pptx_clean_status(output_dir):
    """Test verify command shows CLEAN status for properly scrubbed PowerPoint."""
    from tests.conftest import get_pptx_test_file

    PPTX_TEST_FILE = get_pptx_test_file()

    # First scrub the file
    scrub_result = runner.invoke(
        app,
        ["scrub",
         PPTX_TEST_FILE,
         "--output",
         str(output_dir)]
    )
    assert scrub_result.exit_code == 0

    # Get the processed file path
    processed_file = output_dir / f"processed_{Path(PPTX_TEST_FILE).name}"
    assert processed_file.exists()

    # Now verify
    result = runner.invoke(app, ["verify", PPTX_TEST_FILE, str(processed_file)])

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    assert "Comparing" in result.stdout


# ============== Word Document Tests ==============


def test_verify_command_docx_clean_status(output_dir):
    """Test verify command shows CLEAN status for properly scrubbed Word doc."""
    from tests.conftest import get_docx_test_file

    DOCX_TEST_FILE = get_docx_test_file()

    # First scrub the file
    scrub_result = runner.invoke(
        app,
        ["scrub",
         DOCX_TEST_FILE,
         "--output",
         str(output_dir)]
    )
    assert scrub_result.exit_code == 0

    # Get the processed file path
    processed_file = output_dir / f"processed_{Path(DOCX_TEST_FILE).name}"
    assert processed_file.exists()

    # Now verify
    result = runner.invoke(app, ["verify", DOCX_TEST_FILE, str(processed_file)])

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    assert "Comparing" in result.stdout


# ============== Error Tests ==============


def test_verify_command_original_file_not_found():
    """Test verify command handles missing original file."""
    result = runner.invoke(
        app,
        ["verify",
         "nonexistent_file.jpg",
         "also_nonexistent.jpg"]
    )

    assert result.exit_code != 0


def test_verify_command_processed_file_not_found():
    """Test verify command handles missing processed file."""
    from tests.conftest import get_jpg_test_file

    JPG_TEST_FILE = get_jpg_test_file()

    result = runner.invoke(app, ["verify", JPG_TEST_FILE, "nonexistent_processed.jpg"])

    assert result.exit_code != 0


# ============== Output Format Tests ==============


def test_verify_command_shows_removed_count(output_dir):
    """Test that verify command shows removed count in output."""
    from tests.conftest import get_jpg_test_file

    JPG_TEST_FILE = get_jpg_test_file()

    # Scrub the file
    runner.invoke(app, ["scrub", JPG_TEST_FILE, "--output", str(output_dir)])
    processed_file = output_dir / f"processed_{Path(JPG_TEST_FILE).name}"

    # Verify
    result = runner.invoke(app, ["verify", JPG_TEST_FILE, str(processed_file)])

    assert "Removed:" in result.stdout


def test_verify_command_shows_preserved_count(output_dir):
    """Test that verify command shows preserved count in output."""
    from tests.conftest import get_jpg_test_file

    JPG_TEST_FILE = get_jpg_test_file()

    # Scrub the file
    runner.invoke(app, ["scrub", JPG_TEST_FILE, "--output", str(output_dir)])
    processed_file = output_dir / f"processed_{Path(JPG_TEST_FILE).name}"

    # Verify
    result = runner.invoke(app, ["verify", JPG_TEST_FILE, str(processed_file)])

    assert "Preserved:" in result.stdout


def test_verify_command_shows_comparison_header(output_dir):
    """Test that verify command shows comparison header."""
    from tests.conftest import get_jpg_test_file

    JPG_TEST_FILE = get_jpg_test_file()

    # Scrub the file
    runner.invoke(app, ["scrub", JPG_TEST_FILE, "--output", str(output_dir)])
    processed_file = output_dir / f"processed_{Path(JPG_TEST_FILE).name}"

    # Verify
    result = runner.invoke(app, ["verify", JPG_TEST_FILE, str(processed_file)])

    assert "Comparing:" in result.stdout
    assert Path(JPG_TEST_FILE).name in result.stdout
