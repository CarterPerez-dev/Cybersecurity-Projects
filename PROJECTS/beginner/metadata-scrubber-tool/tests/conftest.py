"""
Pytest configuration and shared fixtures.

Provides cross-platform test file paths that work on both Windows and Linux (CI).
"""

from pathlib import Path

import pytest

# Get the tests directory (this file's parent)
TESTS_DIR = Path(__file__).parent
ASSETS_DIR = TESTS_DIR / "assets"
TEST_IMAGES_DIR = ASSETS_DIR / "test_images"
TEST_PDFS_DIR = ASSETS_DIR / "test_pdfs"
TEST_XLSX_DIR = ASSETS_DIR / "test_xlsx"


@pytest.fixture
def jpg_test_file() -> Path:
    """Return path to a JPG test file."""
    return TEST_IMAGES_DIR / "test_fuji.jpg"


@pytest.fixture
def png_test_file() -> Path:
    """Return path to a PNG test file."""
    return TEST_IMAGES_DIR / "generated_test_03.png"


@pytest.fixture
def test_images_dir() -> Path:
    """Return path to test images directory."""
    return TEST_IMAGES_DIR


# String versions for parametrize (which doesn't support fixtures directly)
def get_jpg_test_file() -> str:
    """Get JPG test file path as string."""
    return str(TEST_IMAGES_DIR / "test_fuji.jpg")


def get_png_test_file() -> str:
    """Get PNG test file path as string."""
    return str(TEST_IMAGES_DIR / "generated_test_03.png")


def get_test_images_dir() -> str:
    """Get test images directory path as string."""
    return str(TEST_IMAGES_DIR)


@pytest.fixture
def pdf_test_file() -> Path:
    """Return path to a PDF test file with metadata."""
    return TEST_PDFS_DIR / "sample.pdf"


@pytest.fixture
def test_pdfs_dir() -> Path:
    """Return path to test PDFs directory."""
    return TEST_PDFS_DIR


# String versions for parametrize (PDF)
def get_pdf_test_file() -> str:
    """Get PDF test file path as string."""
    return str(TEST_PDFS_DIR / "sample.pdf")


def get_large_pdf_test_file() -> str:
    """Get large PDF test file path as string."""
    return str(TEST_PDFS_DIR / "file-example_PDF_1MB.pdf")


def get_test_pdfs_dir() -> str:
    """Get test PDFs directory path as string."""
    return str(TEST_PDFS_DIR)


# Excel fixtures
@pytest.fixture
def xlsx_test_file() -> Path:
    """Return path to an XLSX test file with metadata."""
    return TEST_XLSX_DIR / "file_example_XLSX_1000.xlsx"


@pytest.fixture
def test_xlsx_dir() -> Path:
    """Return path to test XLSX directory."""
    return TEST_XLSX_DIR


# String versions for parametrize (Excel)
def get_xlsx_test_file() -> str:
    """Get XLSX test file path as string."""
    return str(TEST_XLSX_DIR / "file_example_XLSX_1000.xlsx")


def get_large_xlsx_test_file() -> str:
    """Get large XLSX test file path as string."""
    return str(TEST_XLSX_DIR / "file_example_XLSX_5000.xlsx")


def get_test_xlsx_dir() -> str:
    """Get test XLSX directory path as string."""
    return str(TEST_XLSX_DIR)


# PowerPoint fixtures
TEST_PPTX_DIR = ASSETS_DIR / "test_pptx"


@pytest.fixture
def pptx_test_file() -> Path:
    """Return path to a PPTX test file with metadata."""
    return TEST_PPTX_DIR / "Extlst-test.pptx"


@pytest.fixture
def test_pptx_dir() -> Path:
    """Return path to test PPTX directory."""
    return TEST_PPTX_DIR


# String versions for parametrize (PowerPoint)
def get_pptx_test_file() -> str:
    """Get PPTX test file path as string."""
    return str(TEST_PPTX_DIR / "Extlst-test.pptx")


def get_large_pptx_test_file() -> str:
    """Get second PPTX test file path as string."""
    return str(TEST_PPTX_DIR / "sample3.pptx")


def get_test_pptx_dir() -> str:
    """Get test PPTX directory path as string."""
    return str(TEST_PPTX_DIR)


# Word document fixtures
TEST_DOCX_DIR = ASSETS_DIR / "test_docx"


@pytest.fixture
def docx_test_file() -> Path:
    """Return path to a DOCX test file with metadata."""
    return TEST_DOCX_DIR / "file-sample_500kB.docx"


@pytest.fixture
def test_docx_dir() -> Path:
    """Return path to test DOCX directory."""
    return TEST_DOCX_DIR


# String versions for parametrize (Word document)
def get_docx_test_file() -> str:
    """Get DOCX test file path as string."""
    return str(TEST_DOCX_DIR / "file-sample_500kB.docx")


def get_large_docx_test_file() -> str:
    """Get large DOCX test file path as string."""
    return str(TEST_DOCX_DIR / "file-sample_1MB.docx")


def get_test_docx_dir() -> str:
    """Get test DOCX directory path as string."""
    return str(TEST_DOCX_DIR)
