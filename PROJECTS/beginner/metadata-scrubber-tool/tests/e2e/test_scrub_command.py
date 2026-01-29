"""
E2E tests for the 'scrub' command.

Tests the full CLI flow for scrubbing metadata from files.
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
EXAMPLES_DIR = get_test_images_dir()
PDF_TEST_FILE = get_pdf_test_file()
PDF_DIR = get_test_pdfs_dir()
XLSX_TEST_FILE = get_xlsx_test_file()
XLSX_DIR = get_test_xlsx_dir()


@pytest.fixture
def output_dir(tmp_path):
    """Create isolated output directory for each test using tmp_path."""
    output = tmp_path / "output"
    output.mkdir(parents = True, exist_ok = True)
    return output


# ============== Image Tests ==============


@pytest.mark.parametrize("x", [JPG_TEST_FILE, PNG_TEST_FILE])
def test_scrub_command_single_file_success(x, output_dir):
    """Test the 'scrub' command with a single image file."""
    result = runner.invoke(app, ["scrub", x, "--output", str(output_dir)])

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    output_file = output_dir / f"processed_{Path(x).name}"
    assert output_file.exists()


def test_scrub_command_recursive_jpg_success(output_dir):
    """Test the 'scrub' command with recursive directory processing for JPG."""
    result = runner.invoke(
        app,
        ["scrub",
         EXAMPLES_DIR,
         "-r",
         "-ext",
         "jpg",
         "--output",
         str(output_dir)]
    )

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    output_files = list(output_dir.glob("processed_*.jpg"))
    assert len(output_files) > 0


def test_scrub_command_dry_run(output_dir):
    """Test that --dry-run doesn't create files."""
    result = runner.invoke(
        app,
        ["scrub",
         JPG_TEST_FILE,
         "--output",
         str(output_dir),
         "--dry-run"]
    )

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    assert "DRY-RUN" in result.stdout
    output_file = output_dir / f"processed_{Path(JPG_TEST_FILE).name}"
    assert not output_file.exists()


def test_scrub_command_with_workers(output_dir):
    """Test the --workers option for concurrent processing."""
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


# ============== Error Tests ==============


def test_scrub_command_file_not_found():
    """Test that the app handles missing files gracefully."""
    result = runner.invoke(app, ["scrub", "ghost_file.jpg"])

    assert result.exit_code == 2
    assert "Invalid value" in result.stderr


def test_scrub_command_requires_ext_with_recursive():
    """Test that --recursive requires --extension flag."""
    result = runner.invoke(app, ["scrub", EXAMPLES_DIR, "-r"])
    assert result.exit_code != 0


def test_scrub_command_requires_recursive_with_ext():
    """Test that --extension requires --recursive flag."""
    result = runner.invoke(app, ["scrub", JPG_TEST_FILE, "-ext", "jpg"])
    assert result.exit_code != 0


# ============== PDF Tests ==============


def test_scrub_command_pdf_single_file_success(output_dir):
    """Test the 'scrub' command with a single PDF file."""
    result = runner.invoke(app, ["scrub", PDF_TEST_FILE, "--output", str(output_dir)])

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    output_file = output_dir / f"processed_{Path(PDF_TEST_FILE).name}"
    assert output_file.exists()


def test_scrub_command_recursive_pdf_success(output_dir):
    """Test the 'scrub' command with recursive directory processing for PDF."""
    result = runner.invoke(
        app,
        ["scrub",
         PDF_DIR,
         "-r",
         "-ext",
         "pdf",
         "--output",
         str(output_dir)]
    )

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    output_files = list(output_dir.glob("processed_*.pdf"))
    assert len(output_files) > 0


def test_scrub_command_pdf_dry_run(output_dir):
    """Test that --dry-run doesn't create PDF files."""
    result = runner.invoke(
        app,
        ["scrub",
         PDF_TEST_FILE,
         "--output",
         str(output_dir),
         "--dry-run"]
    )

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    assert "DRY-RUN" in result.stdout
    output_file = output_dir / f"processed_{Path(PDF_TEST_FILE).name}"
    assert not output_file.exists()


# ============== Excel Tests ==============


def test_scrub_command_xlsx_single_file_success(output_dir):
    """Test the 'scrub' command with a single Excel file."""
    result = runner.invoke(app, ["scrub", XLSX_TEST_FILE, "--output", str(output_dir)])

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    output_file = output_dir / f"processed_{Path(XLSX_TEST_FILE).name}"
    assert output_file.exists()


def test_scrub_command_recursive_xlsx_success(output_dir):
    """Test the 'scrub' command with recursive directory processing for Excel."""
    result = runner.invoke(
        app,
        ["scrub",
         XLSX_DIR,
         "-r",
         "-ext",
         "xlsx",
         "--output",
         str(output_dir)]
    )

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    output_files = list(output_dir.glob("processed_*.xlsx"))
    assert len(output_files) > 0


def test_scrub_command_xlsx_dry_run(output_dir):
    """Test that --dry-run doesn't create Excel files."""
    result = runner.invoke(
        app,
        ["scrub",
         XLSX_TEST_FILE,
         "--output",
         str(output_dir),
         "--dry-run"]
    )

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    assert "DRY-RUN" in result.stdout
    output_file = output_dir / f"processed_{Path(XLSX_TEST_FILE).name}"
    assert not output_file.exists()


def test_scrub_command_xlsx_with_workers(output_dir):
    """Test the --workers option for concurrent Excel processing."""
    result = runner.invoke(
        app,
        [
            "scrub",
            XLSX_DIR,
            "-r",
            "-ext",
            "xlsx",
            "--output",
            str(output_dir),
            "--workers",
            "2",
        ],
    )

    assert result.exit_code == 0, f"Failed with: {result.stdout}"


# ============== PowerPoint Tests ==============


def test_scrub_command_pptx_single_file_success(output_dir):
    """Test the 'scrub' command with a single PowerPoint file."""
    from tests.conftest import get_pptx_test_file

    PPTX_TEST_FILE = get_pptx_test_file()
    result = runner.invoke(app, ["scrub", PPTX_TEST_FILE, "--output", str(output_dir)])

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    output_file = output_dir / f"processed_{Path(PPTX_TEST_FILE).name}"
    assert output_file.exists()


def test_scrub_command_recursive_pptx_success(output_dir):
    """Test the 'scrub' command with recursive directory processing for PowerPoint."""
    from tests.conftest import get_test_pptx_dir

    PPTX_DIR = get_test_pptx_dir()
    result = runner.invoke(
        app,
        ["scrub",
         PPTX_DIR,
         "-r",
         "-ext",
         "pptx",
         "--output",
         str(output_dir)]
    )

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    output_files = list(output_dir.glob("processed_*.pptx"))
    assert len(output_files) > 0


def test_scrub_command_pptx_dry_run(output_dir):
    """Test that --dry-run doesn't create PowerPoint files."""
    from tests.conftest import get_pptx_test_file

    PPTX_TEST_FILE = get_pptx_test_file()
    result = runner.invoke(
        app,
        ["scrub",
         PPTX_TEST_FILE,
         "--output",
         str(output_dir),
         "--dry-run"]
    )

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    assert "DRY-RUN" in result.stdout
    output_file = output_dir / f"processed_{Path(PPTX_TEST_FILE).name}"
    assert not output_file.exists()


def test_scrub_command_pptx_with_workers(output_dir):
    """Test the --workers option for concurrent PowerPoint processing."""
    from tests.conftest import get_test_pptx_dir

    PPTX_DIR = get_test_pptx_dir()
    result = runner.invoke(
        app,
        [
            "scrub",
            PPTX_DIR,
            "-r",
            "-ext",
            "pptx",
            "--output",
            str(output_dir),
            "--workers",
            "2",
        ],
    )

    assert result.exit_code == 0, f"Failed with: {result.stdout}"


# ============== Word Document Tests ==============


def test_scrub_command_docx_single_file_success(output_dir):
    """Test the 'scrub' command with a single Word document file."""
    from tests.conftest import get_docx_test_file

    DOCX_TEST_FILE = get_docx_test_file()
    result = runner.invoke(app, ["scrub", DOCX_TEST_FILE, "--output", str(output_dir)])

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    output_file = output_dir / f"processed_{Path(DOCX_TEST_FILE).name}"
    assert output_file.exists()


def test_scrub_command_recursive_docx_success(output_dir):
    """Test the 'scrub' command with recursive directory processing for Word documents."""
    from tests.conftest import get_test_docx_dir

    DOCX_DIR = get_test_docx_dir()
    result = runner.invoke(
        app,
        ["scrub",
         DOCX_DIR,
         "-r",
         "-ext",
         "docx",
         "--output",
         str(output_dir)]
    )

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    output_files = list(output_dir.glob("processed_*.docx"))
    assert len(output_files) > 0


def test_scrub_command_docx_dry_run(output_dir):
    """Test that --dry-run doesn't create Word document files."""
    from tests.conftest import get_docx_test_file

    DOCX_TEST_FILE = get_docx_test_file()
    result = runner.invoke(
        app,
        ["scrub",
         DOCX_TEST_FILE,
         "--output",
         str(output_dir),
         "--dry-run"]
    )

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
    assert "DRY-RUN" in result.stdout
    output_file = output_dir / f"processed_{Path(DOCX_TEST_FILE).name}"
    assert not output_file.exists()


def test_scrub_command_docx_with_workers(output_dir):
    """Test the --workers option for concurrent Word document processing."""
    from tests.conftest import get_test_docx_dir

    DOCX_DIR = get_test_docx_dir()
    result = runner.invoke(
        app,
        [
            "scrub",
            DOCX_DIR,
            "-r",
            "-ext",
            "docx",
            "--output",
            str(output_dir),
            "--workers",
            "2",
        ],
    )

    assert result.exit_code == 0, f"Failed with: {result.stdout}"
