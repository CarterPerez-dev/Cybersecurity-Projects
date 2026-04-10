"""
©AngelaMos | 2026
pdf.py
"""


import structlog

from dlp_scanner.models import Location, TextChunk


log = structlog.get_logger()

PDF_EXTENSIONS: frozenset[str] = frozenset({".pdf"})


class PDFExtractor:
    """
    Extracts text from PDF files using PyMuPDF
    """
    @property
    def supported_extensions(self) -> frozenset[str]:
        """
        File extensions this extractor handles
        """
        return PDF_EXTENSIONS

    def extract(self, path: str) -> list[TextChunk]:
        """
        Extract text from each page of a PDF
        """
        import fitz

        chunks: list[TextChunk] = []

        try:
            doc = fitz.open(path)
            for page_num in range(len(doc)):
                page = doc[page_num]
                text = page.get_text("text")
                if text.strip():
                    chunks.append(
                        TextChunk(
                            text = text,
                            location = Location(
                                source_type = "file",
                                uri = path,
                                line = page_num + 1,
                            ),
                        )
                    )
            doc.close()
        except Exception:
            log.warning("pdf_extract_failed", path = path)

        return chunks
