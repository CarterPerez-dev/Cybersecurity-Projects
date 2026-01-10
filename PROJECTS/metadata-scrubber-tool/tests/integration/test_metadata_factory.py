"""
Integration tests for MetadataFactory.

Tests the factory pattern integration with all handler types (Image, PDF, Excel).
"""

import shutil
from pathlib import Path

import pytest

from src.core.jpeg_metadata import JpegProcessor
from src.core.png_metadata import PngProcessor
from src.services.excel_handler import ExcelHandler
from src.services.metadata_factory import MetadataFactory
from src.services.pdf_handler import PDFHandler
from src.utils.exceptions import UnsupportedFormatError

# Import path helpers from conftest
from tests.conftest import (
    get_jpg_test_file,
    get_pdf_test_file,
    get_png_test_file,
    get_xlsx_test_file,
)

# Test file paths (cross-platform)
JPG_TEST_FILE = get_jpg_test_file()
PNG_TEST_FILE = get_png_test_file()
PDF_TEST_FILE = get_pdf_test_file()
XLSX_TEST_FILE = get_xlsx_test_file()


# ============== Image Tests ==============


@pytest.mark.parametrize("x", [JPG_TEST_FILE, PNG_TEST_FILE])
def test_read_image_metadata(x):
    """Test reading image metadata through factory."""
    assert Path(x).exists(), f"Test file not found: {x}"
    handler = MetadataFactory.get_handler(str(x))
    metadata = handler.read()

    assert handler.metadata == metadata
    assert isinstance(metadata, dict)

    if isinstance(handler, (JpegProcessor, PngProcessor)):
        assert (
            handler.tags_to_delete is not None or handler.text_keys_to_delete is not None
        )


@pytest.mark.parametrize("x", [JPG_TEST_FILE, PNG_TEST_FILE])
def test_wipe_image_metadata(x):
    """Test wiping image metadata through factory."""
    assert Path(x).exists(), f"Test file not found: {x}"
    handler = MetadataFactory.get_handler(str(x))
    metadata = handler.read()
    handler.wipe()

    assert handler.processed_metadata != metadata


@pytest.mark.parametrize("x", [JPG_TEST_FILE, PNG_TEST_FILE])
def test_save_processed_image_metadata(x):
    """Test saving processed image metadata through factory."""
    output_dir = Path("./tests/assets/output")
    output_dir.mkdir(parents = True, exist_ok = True)

    handler = MetadataFactory.get_handler(str(x))
    handler.read()
    handler.wipe()

    output_file = output_dir / Path(x).name
    handler.save(str(output_file))

    assert output_file.exists()
    shutil.rmtree(output_dir)


def test_image_format_detection():
    """Test format detection for images."""
    handler = MetadataFactory.get_handler(JPG_TEST_FILE)
    assert handler._detect_format() == "jpeg"

    handler_png = MetadataFactory.get_handler(PNG_TEST_FILE)
    assert handler_png._detect_format() == "png"


# ============== PDF Tests ==============


def test_read_pdf_metadata_via_factory():
    """Test reading PDF metadata through MetadataFactory."""
    assert Path(PDF_TEST_FILE).exists(), f"Test file not found: {PDF_TEST_FILE}"
    handler = MetadataFactory.get_handler(PDF_TEST_FILE)

    assert isinstance(handler, PDFHandler)

    metadata = handler.read()
    assert handler.metadata == metadata
    assert isinstance(metadata, dict)
    assert handler.keys_to_delete is not None


def test_wipe_pdf_metadata_via_factory():
    """Test wiping PDF metadata through MetadataFactory."""
    handler = MetadataFactory.get_handler(PDF_TEST_FILE)
    metadata = handler.read()
    handler.wipe()

    assert handler.processed_metadata != metadata


def test_save_processed_pdf_metadata_via_factory():
    """Test saving processed PDF metadata through MetadataFactory."""
    output_dir = Path("./tests/assets/output")
    output_dir.mkdir(parents = True, exist_ok = True)

    handler = MetadataFactory.get_handler(PDF_TEST_FILE)
    handler.read()
    handler.wipe()

    output_file = output_dir / Path(PDF_TEST_FILE).name
    handler.save(str(output_file))

    assert output_file.exists()
    shutil.rmtree(output_dir)


def test_pdf_format_detection():
    """Test format detection for PDF files."""
    handler = MetadataFactory.get_handler(PDF_TEST_FILE)
    assert handler._detect_format() == "pdf"


# ============== Excel Tests ==============


def test_read_excel_metadata_via_factory():
    """Test reading Excel metadata through MetadataFactory."""
    assert Path(XLSX_TEST_FILE).exists(), f"Test file not found: {XLSX_TEST_FILE}"
    handler = MetadataFactory.get_handler(XLSX_TEST_FILE)

    assert isinstance(handler, ExcelHandler)

    metadata = handler.read()
    assert handler.metadata == metadata
    assert isinstance(metadata, dict)
    assert handler.keys_to_delete is not None


def test_wipe_excel_metadata_via_factory():
    """Test wiping Excel metadata through MetadataFactory."""
    handler = MetadataFactory.get_handler(XLSX_TEST_FILE)
    metadata = handler.read()
    handler.wipe()

    assert handler.processed_metadata != metadata


def test_save_processed_excel_metadata_via_factory():
    """Test saving processed Excel metadata through MetadataFactory."""
    output_dir = Path("./tests/assets/output")
    output_dir.mkdir(parents = True, exist_ok = True)

    handler = MetadataFactory.get_handler(XLSX_TEST_FILE)
    handler.read()
    handler.wipe()

    output_file = output_dir / Path(XLSX_TEST_FILE).name
    handler.save(str(output_file))

    assert output_file.exists()
    shutil.rmtree(output_dir)


def test_excel_format_detection():
    """Test format detection for Excel files."""
    handler = MetadataFactory.get_handler(XLSX_TEST_FILE)
    assert handler._detect_format() == "xlsx"


# ============== PowerPoint Tests ==============


def test_read_pptx_metadata_via_factory():
    """Test reading PowerPoint metadata through MetadataFactory."""
    from tests.conftest import get_pptx_test_file

    PPTX_TEST_FILE = get_pptx_test_file()
    assert Path(PPTX_TEST_FILE).exists(), f"Test file not found: {PPTX_TEST_FILE}"

    from src.services.powerpoint_handler import PowerpointHandler

    handler = MetadataFactory.get_handler(PPTX_TEST_FILE)
    assert isinstance(handler, PowerpointHandler)

    metadata = handler.read()
    assert handler.metadata == metadata
    assert isinstance(metadata, dict)


def test_wipe_pptx_metadata_via_factory():
    """Test wiping PowerPoint metadata through MetadataFactory."""
    from tests.conftest import get_pptx_test_file

    PPTX_TEST_FILE = get_pptx_test_file()
    handler = MetadataFactory.get_handler(PPTX_TEST_FILE)
    handler.read()
    handler.wipe()

    assert handler.processed_metadata is not None


def test_save_processed_pptx_metadata_via_factory():
    """Test saving processed PowerPoint metadata through MetadataFactory."""
    from tests.conftest import get_pptx_test_file

    PPTX_TEST_FILE = get_pptx_test_file()
    output_dir = Path("./tests/assets/output")
    output_dir.mkdir(parents = True, exist_ok = True)

    handler = MetadataFactory.get_handler(PPTX_TEST_FILE)
    handler.read()
    handler.wipe()

    output_file = output_dir / Path(PPTX_TEST_FILE).name
    handler.save(str(output_file))

    assert output_file.exists()
    shutil.rmtree(output_dir)


def test_pptx_format_detection():
    """Test format detection for PowerPoint files."""
    from tests.conftest import get_pptx_test_file

    PPTX_TEST_FILE = get_pptx_test_file()
    handler = MetadataFactory.get_handler(PPTX_TEST_FILE)
    assert handler._detect_format() == "pptx"


# ============== Word Document Tests ==============


def test_read_docx_metadata_via_factory():
    """Test reading Word document metadata through MetadataFactory."""
    from src.services.worddoc_handler import WorddocHandler
    from tests.conftest import get_docx_test_file

    DOCX_TEST_FILE = get_docx_test_file()
    assert Path(DOCX_TEST_FILE).exists(), f"Test file not found: {DOCX_TEST_FILE}"

    handler = MetadataFactory.get_handler(DOCX_TEST_FILE)
    assert isinstance(handler, WorddocHandler)

    metadata = handler.read()
    assert handler.metadata == metadata
    assert isinstance(metadata, dict)


def test_wipe_docx_metadata_via_factory():
    """Test wiping Word document metadata through MetadataFactory."""
    from tests.conftest import get_docx_test_file

    DOCX_TEST_FILE = get_docx_test_file()
    handler = MetadataFactory.get_handler(DOCX_TEST_FILE)
    handler.read()
    handler.wipe()

    assert handler.processed_metadata is not None


def test_save_processed_docx_metadata_via_factory():
    """Test saving processed Word document metadata through MetadataFactory."""
    from tests.conftest import get_docx_test_file

    DOCX_TEST_FILE = get_docx_test_file()
    output_dir = Path("./tests/assets/output")
    output_dir.mkdir(parents = True, exist_ok = True)

    handler = MetadataFactory.get_handler(DOCX_TEST_FILE)
    handler.read()
    handler.wipe()

    output_file = output_dir / Path(DOCX_TEST_FILE).name
    handler.save(str(output_file))

    assert output_file.exists()
    shutil.rmtree(output_dir)


def test_docx_format_detection():
    """Test format detection for Word document files."""
    from tests.conftest import get_docx_test_file

    DOCX_TEST_FILE = get_docx_test_file()
    handler = MetadataFactory.get_handler(DOCX_TEST_FILE)
    assert handler._detect_format() == "docx"


# ============== Error Tests ==============


def test_unsupported_format_raises_error(tmp_path):
    """Test that unsupported file formats raise an error."""
    fake_file = tmp_path / "test.txt"
    fake_file.write_text("not an image")

    with pytest.raises(UnsupportedFormatError):
        MetadataFactory.get_handler(str(fake_file))


def test_save_without_output_path_raises_error():
    """Test that save() raises ValueError when output_path is empty."""
    handler = MetadataFactory.get_handler(JPG_TEST_FILE)
    handler.read()
    handler.wipe()
    with pytest.raises(ValueError):
        handler.save("")
