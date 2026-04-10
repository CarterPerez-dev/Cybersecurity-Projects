"""
©AngelaMos | 2026
email.py
"""


import email as email_lib
from email import policy

import structlog

from dlp_scanner.models import Location, TextChunk


log = structlog.get_logger()

EMAIL_EXTENSIONS: frozenset[str] = frozenset({
    ".eml",
    ".msg",
})


class EmlExtractor:
    """
    Extracts text from RFC 2822 EML files
    """
    @property
    def supported_extensions(self) -> frozenset[str]:
        """
        File extensions this extractor handles
        """
        return frozenset({".eml"})

    def extract(self, path: str) -> list[TextChunk]:
        """
        Parse EML and extract headers and body text
        """
        chunks: list[TextChunk] = []

        try:
            with open(path, "rb") as f:
                msg = email_lib.message_from_binary_file(
                    f,
                    policy = policy.default
                )

            parts: list[str] = []

            for header in ("From", "To", "Cc", "Subject"):
                value = msg.get(header)
                if value:
                    parts.append(f"{header}: {value}")

            body = msg.get_body(preferencelist = ("plain", "html"))
            if body is not None:
                content = body.get_content()
                if content:
                    parts.append(content)

            if parts:
                chunks.append(
                    TextChunk(
                        text = "\n".join(parts),
                        location = Location(
                            source_type = "file",
                            uri = path,
                        ),
                    )
                )

        except Exception:
            log.warning("eml_extract_failed", path = path)

        return chunks


class MsgExtractor:
    """
    Extracts text from Outlook MSG files
    """
    @property
    def supported_extensions(self) -> frozenset[str]:
        """
        File extensions this extractor handles
        """
        return frozenset({".msg"})

    def extract(self, path: str) -> list[TextChunk]:
        """
        Parse MSG and extract headers and body text
        """
        import extract_msg

        chunks: list[TextChunk] = []

        try:
            with extract_msg.Message(path) as msg:
                parts: list[str] = []

                if msg.sender:
                    parts.append(f"From: {msg.sender}")
                if msg.to:
                    parts.append(f"To: {msg.to}")
                if msg.subject:
                    parts.append(f"Subject: {msg.subject}")
                if msg.body:
                    parts.append(msg.body)

                if parts:
                    chunks.append(
                        TextChunk(
                            text = "\n".join(parts),
                            location = Location(
                                source_type = "file",
                                uri = path,
                            ),
                        )
                    )

        except Exception:
            log.warning("msg_extract_failed", path = path)

        return chunks
