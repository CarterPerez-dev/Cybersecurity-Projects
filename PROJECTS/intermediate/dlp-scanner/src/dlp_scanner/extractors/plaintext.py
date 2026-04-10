"""
©AngelaMos | 2026
plaintext.py
"""


import structlog

from dlp_scanner.models import Location, TextChunk


log = structlog.get_logger()

PLAINTEXT_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".txt",
        ".log",
        ".cfg",
        ".ini",
        ".conf",
        ".toml",
        ".md",
        ".rst",
        ".html",
        ".htm",
        ".tsv",
        ".env",
        ".sh",
        ".bat",
        ".ps1",
        ".py",
        ".js",
        ".ts",
        ".go",
        ".rb",
        ".java",
        ".c",
        ".cpp",
        ".h",
        ".hpp",
        ".rs",
        ".tf",
        ".hcl",
    }
)

CHUNK_MAX_LINES: int = 500


class PlaintextExtractor:
    """
    Extracts text from plaintext and source code files
    """
    @property
    def supported_extensions(self) -> frozenset[str]:
        """
        File extensions this extractor handles
        """
        return PLAINTEXT_EXTENSIONS

    def extract(self, path: str) -> list[TextChunk]:
        """
        Read a text file and return chunks
        """
        chunks: list[TextChunk] = []

        try:
            with open(
                    path,
                    encoding = "utf-8",
                    errors = "replace",
            ) as f:
                lines: list[str] = []
                line_number = 1
                chunk_start = 1

                for line in f:
                    lines.append(line)
                    if len(lines) >= CHUNK_MAX_LINES:
                        chunks.append(
                            TextChunk(
                                text = "".join(lines),
                                location = Location(
                                    source_type = "file",
                                    uri = path,
                                    line = chunk_start,
                                ),
                            )
                        )
                        chunk_start = line_number + 1
                        lines = []
                    line_number += 1

                if lines:
                    chunks.append(
                        TextChunk(
                            text = "".join(lines),
                            location = Location(
                                source_type = "file",
                                uri = path,
                                line = chunk_start,
                            ),
                        )
                    )

        except OSError:
            log.warning(
                "file_read_failed",
                path = path,
            )

        return chunks
