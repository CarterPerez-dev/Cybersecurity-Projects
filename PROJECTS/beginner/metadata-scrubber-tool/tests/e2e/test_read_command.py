"""
E2E tests for the 'read' command.

Tests the full CLI flow for reading metadata from files.
"""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from src.main import app

# Import path helpers from conftest
from tests.conftest import (
    get_jpg_test_file,
    get_pdf_test_file,
    get_png_test_file,
    get_test_images_dir,
    get_test_pdfs_dir,
    get_test_xlsx_dir,
    get_xlsx_test_file,
)


runner = CliRunner()

# Test file paths (cross-platform)
JPG_TEST_FILE = get_jpg_test_file()
PNG_TEST_FILE = get_png_test_file()
TEST_DIR = get_test_images_dir()
PDF_TEST_FILE = get_pdf_test_file()
PDF_DIR = get_test_pdfs_dir()
XLSX_TEST_FILE = get_xlsx_test_file()
XLSX_DIR = get_test_xlsx_dir()


# ============== Image Tests ==============


@pytest.mark.parametrize("x", [JPG_TEST_FILE, PNG_TEST_FILE])
def test_read_command_single_file_success(x):
    """Test the 'read' command with a single image file."""
    result = runner.invoke(app, ["read", str(x)])

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    assert "Reading" in result.stdout
    assert Path(x).name in result.stdout


@pytest.mark.parametrize("ext", ["jpg", "png"])
def test_read_command_recursive_directory_success(ext):
    """Test the 'read' command with recursive directory processing."""
    result = runner.invoke(app, ["read", TEST_DIR, "-r", "-ext", ext])

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    assert "Reading" in result.stdout


def test_read_command_requires_ext_with_recursive():
    """Test that --recursive requires --extension flag."""
    result = runner.invoke(app, ["read", TEST_DIR, "-r"])
    assert result.exit_code != 0


def test_read_command_requires_recursive_with_ext():
    """Test that --extension requires --recursive flag."""
    result = runner.invoke(app, ["read", JPG_TEST_FILE, "-ext", "jpg"])
    assert result.exit_code != 0


# ============== Error Tests ==============


def test_read_command_file_not_found():
    """Test that the app handles missing files gracefully."""
    result = runner.invoke(app, ["read", "ghost_file.jpg"])

    assert result.exit_code == 2
    assert "Invalid value for 'FILE_PATH'" in result.stderr
    assert "does not exist" in result.stderr


# ============== PDF Tests ==============


def test_read_command_pdf_single_file_success():
    """Test the 'read' command with a single PDF file."""
    result = runner.invoke(app, ["read", PDF_TEST_FILE])

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    assert "Reading" in result.stdout
    assert Path(PDF_TEST_FILE).name in result.stdout


def test_read_command_recursive_pdf_success():
    """Test the 'read' command with recursive PDF directory processing."""
    result = runner.invoke(app, ["read", PDF_DIR, "-r", "-ext", "pdf"])

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    assert "Reading" in result.stdout


# ============== Excel Tests ==============


def test_read_command_xlsx_single_file_success():
    """Test the 'read' command with a single Excel file."""
    result = runner.invoke(app, ["read", XLSX_TEST_FILE])

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    assert "Reading" in result.stdout
    assert Path(XLSX_TEST_FILE).name in result.stdout


def test_read_command_recursive_xlsx_success():
    """Test the 'read' command with recursive Excel directory processing."""
    result = runner.invoke(app, ["read", XLSX_DIR, "-r", "-ext", "xlsx"])

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    assert "Reading" in result.stdout


# ============== PowerPoint Tests ==============


def test_read_command_pptx_single_file_success():
    """Test the 'read' command with a single PowerPoint file."""
    from tests.conftest import get_pptx_test_file

    PPTX_TEST_FILE = get_pptx_test_file()
    result = runner.invoke(app, ["read", PPTX_TEST_FILE])

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    assert "Reading" in result.stdout
    assert Path(PPTX_TEST_FILE).name in result.stdout


def test_read_command_recursive_pptx_success():
    """Test the 'read' command with recursive PowerPoint directory processing."""
    from tests.conftest import get_test_pptx_dir

    PPTX_DIR = get_test_pptx_dir()
    result = runner.invoke(app, ["read", PPTX_DIR, "-r", "-ext", "pptx"])

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    assert "Reading" in result.stdout


# ============== Word Document Tests ==============


def test_read_command_docx_single_file_success():
    """Test the 'read' command with a single Word document file."""
    from tests.conftest import get_docx_test_file

    DOCX_TEST_FILE = get_docx_test_file()
    result = runner.invoke(app, ["read", DOCX_TEST_FILE])

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    assert "Reading" in result.stdout
    assert Path(DOCX_TEST_FILE).name in result.stdout


def test_read_command_recursive_docx_success():
    """Test the 'read' command with recursive Word document directory processing."""
    from tests.conftest import get_test_docx_dir

    DOCX_DIR = get_test_docx_dir()
    result = runner.invoke(app, ["read", DOCX_DIR, "-r", "-ext", "docx"])

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    assert "Reading" in result.stdout
