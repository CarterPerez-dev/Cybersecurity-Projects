"""
©AngelaMos | 2026
archive.py
"""


import tarfile
import zipfile

import structlog

from dlp_scanner.constants import (
    MAX_ARCHIVE_DEPTH,
    MAX_ARCHIVE_MEMBER_SIZE_MB,
    ZIP_BOMB_RATIO_THRESHOLD,
)
from dlp_scanner.models import Location, TextChunk


log = structlog.get_logger()

ARCHIVE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".zip",
        ".tar",
        ".tar.gz",
        ".tgz",
        ".tar.bz2",
    }
)

MAX_MEMBER_BYTES: int = MAX_ARCHIVE_MEMBER_SIZE_MB * 1024 * 1024


class ArchiveExtractor:
    """
    Extracts text content from archive files with security guards
    """
    @property
    def supported_extensions(self) -> frozenset[str]:
        """
        File extensions this extractor handles
        """
        return ARCHIVE_EXTENSIONS

    def extract(
        self,
        path: str,
        depth: int = 0,
    ) -> list[TextChunk]:
        """
        Extract text from archive members
        """
        if depth >= MAX_ARCHIVE_DEPTH:
            log.warning(
                "archive_depth_exceeded",
                path = path,
                depth = depth,
            )
            return []

        if path.endswith(".zip"):
            return self._extract_zip(path, depth)

        if any(path.endswith(ext)
               for ext in (".tar", ".tar.gz", ".tgz", ".tar.bz2")):
            return self._extract_tar(path, depth)

        return []

    def _extract_zip(self, path: str, depth: int) -> list[TextChunk]:
        """
        Extract from ZIP with bomb and traversal protection
        """
        chunks: list[TextChunk] = []

        try:
            with zipfile.ZipFile(path, "r") as zf:
                for info in zf.infolist():
                    if not self._is_safe_zip_member(info):
                        continue

                    data = zf.read(info.filename)
                    if not data:
                        continue

                    try:
                        text = data.decode("utf-8", errors = "replace")
                    except Exception:
                        continue

                    if text.strip():
                        chunks.append(
                            TextChunk(
                                text = text,
                                location = Location(
                                    source_type = "archive",
                                    uri = f"{path}!{info.filename}",
                                ),
                            )
                        )

        except Exception:
            log.warning("zip_extract_failed", path = path)

        return chunks

    def _extract_tar(self, path: str, depth: int) -> list[TextChunk]:
        """
        Extract from TAR with traversal protection
        """
        chunks: list[TextChunk] = []

        try:
            with tarfile.open(path) as tf:
                for member in tf.getmembers():
                    if not member.isfile():
                        continue

                    if not self._is_safe_tar_member(member):
                        continue

                    if member.size > MAX_MEMBER_BYTES:
                        continue

                    extracted = tf.extractfile(member)
                    if extracted is None:
                        continue

                    data = extracted.read()
                    try:
                        text = data.decode("utf-8", errors = "replace")
                    except Exception:
                        continue

                    if text.strip():
                        chunks.append(
                            TextChunk(
                                text = text,
                                location = Location(
                                    source_type = "archive",
                                    uri = f"{path}!{member.name}",
                                ),
                            )
                        )

        except Exception:
            log.warning("tar_extract_failed", path = path)

        return chunks

    def _is_safe_zip_member(self, info: zipfile.ZipInfo) -> bool:
        """
        Check a ZIP member for path traversal and bomb indicators
        """
        if ".." in info.filename or info.filename.startswith("/"):
            log.warning(
                "zip_path_traversal_blocked",
                filename = info.filename,
            )
            return False

        if "\x00" in info.filename:
            return False

        if info.file_size > MAX_MEMBER_BYTES:
            return False

        if (info.compress_size > 0 and info.file_size / info.compress_size
                > ZIP_BOMB_RATIO_THRESHOLD):
            log.warning(
                "zip_bomb_detected",
                filename = info.filename,
                ratio = info.file_size / info.compress_size,
            )
            return False

        return True

    def _is_safe_tar_member(self, member: tarfile.TarInfo) -> bool:
        """
        Check a TAR member for path traversal
        """
        if ".." in member.name or member.name.startswith("/"):
            log.warning(
                "tar_path_traversal_blocked",
                filename = member.name,
            )
            return False

        return not (member.issym() or member.islnk())
