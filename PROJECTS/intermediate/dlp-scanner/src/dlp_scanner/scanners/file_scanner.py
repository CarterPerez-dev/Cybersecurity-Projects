"""
©AngelaMos | 2026
file_scanner.py
"""


import fnmatch
from datetime import datetime, UTC
from pathlib import Path

import structlog

from dlp_scanner.config import ScanConfig
from dlp_scanner.detectors.registry import DetectorRegistry
from dlp_scanner.extractors.archive import ArchiveExtractor
from dlp_scanner.extractors.base import Extractor
from dlp_scanner.extractors.email import (
    EmlExtractor,
    MsgExtractor,
)
from dlp_scanner.extractors.office import (
    DocxExtractor,
    XlsExtractor,
    XlsxExtractor,
)
from dlp_scanner.extractors.pdf import PDFExtractor
from dlp_scanner.extractors.plaintext import (
    PlaintextExtractor,
)
from dlp_scanner.extractors.structured import (
    AvroExtractor,
    CsvExtractor,
    JsonExtractor,
    ParquetExtractor,
    XmlExtractor,
    YamlExtractor,
)
from dlp_scanner.models import (
    ScanResult,
    TextChunk,
)
from dlp_scanner.scoring import match_to_finding


log = structlog.get_logger()

MB_BYTES: int = 1024 * 1024


class FileScanner:
    """
    Scans files in a directory tree for sensitive data
    """
    def __init__(
        self,
        config: ScanConfig,
        registry: DetectorRegistry,
    ) -> None:
        self._file_config = config.file
        self._detection_config = config.detection
        self._redaction_style = config.output.redaction_style
        self._registry = registry
        self._extension_map = _build_extension_map()
        self._allowed_extensions = frozenset(
            self._file_config.include_extensions
        )

    def scan(self, target: str) -> ScanResult:
        """
        Walk a directory and scan all matching files
        """
        result = ScanResult()
        target_path = Path(target)

        if target_path.is_file():
            self._scan_file(target_path, result)
            result.targets_scanned = 1
        elif target_path.is_dir():
            self._scan_directory(target_path, result)
        else:
            result.errors.append(f"Target not found: {target}")

        result.scan_completed_at = datetime.now(UTC)
        return result

    def _scan_directory(
        self,
        directory: Path,
        result: ScanResult,
    ) -> None:
        """
        Recursively walk a directory and scan matching files
        """
        max_bytes = (self._file_config.max_file_size_mb * MB_BYTES)
        iterator = (
            directory.rglob("*")
            if self._file_config.recursive else directory.glob("*")
        )

        for path in iterator:
            if not path.is_file():
                continue

            if self._is_excluded(path, directory):
                continue

            suffix = _get_full_suffix(path)
            if suffix not in self._allowed_extensions:
                continue

            try:
                file_size = path.stat().st_size
            except OSError:
                continue

            if file_size > max_bytes:
                log.debug(
                    "file_skipped_too_large",
                    path = str(path),
                    size = file_size,
                )
                continue

            if file_size == 0:
                continue

            self._scan_file(path, result)
            result.targets_scanned += 1

    def _scan_file(
        self,
        path: Path,
        result: ScanResult,
    ) -> None:
        """
        Extract text from a single file and run detection
        """
        suffix = _get_full_suffix(path)
        extractor = self._extension_map.get(suffix)

        if extractor is None:
            return

        try:
            chunks = extractor.extract(str(path))
        except Exception:
            log.warning("extraction_failed", path = str(path))
            result.errors.append(f"Extraction failed: {path}")
            return

        min_confidence = (self._detection_config.min_confidence)

        for chunk in chunks:
            matches = self._registry.detect(chunk.text)
            for match in matches:
                if match.score < min_confidence:
                    continue

                finding = match_to_finding(
                    match,
                    chunk.text,
                    chunk.location,
                    self._redaction_style,
                )
                result.findings.append(finding)

    def _is_excluded(
        self,
        path: Path,
        base: Path,
    ) -> bool:
        """
        Check if a path matches any exclude pattern
        """
        relative = str(path.relative_to(base))
        for pattern in self._file_config.exclude_patterns:
            if fnmatch.fnmatch(relative, pattern):
                return True
            if fnmatch.fnmatch(path.name, pattern):
                return True
            if any(fnmatch.fnmatch(part, pattern) for part in path.parts):
                return True
        return False


def _build_extension_map() -> dict[str, Extractor]:
    """
    Build a mapping from file extension to extractor instance
    """
    extractors: list[Extractor] = [
        PlaintextExtractor(),
        PDFExtractor(),
        DocxExtractor(),
        XlsxExtractor(),
        XlsExtractor(),
        CsvExtractor(),
        JsonExtractor(),
        XmlExtractor(),
        YamlExtractor(),
        ParquetExtractor(),
        AvroExtractor(),
        ArchiveExtractor(),
        EmlExtractor(),
        MsgExtractor(),
    ]

    ext_map: dict[str, Extractor] = {}
    for extractor in extractors:
        for ext in extractor.supported_extensions:
            ext_map[ext] = extractor

    return ext_map


def _get_full_suffix(path: Path) -> str:
    """
    Get full suffix including compound extensions
    """
    name = path.name
    if name.endswith(".tar.gz"):
        return ".tar.gz"
    if name.endswith(".tar.bz2"):
        return ".tar.bz2"
    return path.suffix.lower()
