"""
ⒸAngelaMos | 2025
headers.py
"""
from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from starlette.requests import Request


class HeadersExtractor:
    """
    Extract fingerprint data from HTTP headers

    Header ordering is browser-specific and not user-configurable,
    making it useful for fingerprinting even when other headers are spoofed.
    """
    FINGERPRINT_HEADERS: ClassVar[list[str]] = [
        "user-agent",
        "accept",
        "accept-language",
        "accept-encoding",
        "connection",
        "upgrade-insecure-requests",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-user",
        "sec-fetch-dest",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
    ]

    def __init__(
        self,
        use_header_order: bool = False,
        hash_length: int = 16,
    ) -> None:
        self.use_header_order = use_header_order
        self.hash_length = hash_length

    def extract_user_agent(self, request: Request) -> str | None:
        """
        Extract User-Agent header
        """
        return request.headers.get("user-agent")

    def extract_accept_language(self, request: Request) -> str | None:
        """
        Extract Accept-Language header
        """
        return request.headers.get("accept-language")

    def extract_accept_encoding(self, request: Request) -> str | None:
        """
        Extract Accept-Encoding header
        """
        return request.headers.get("accept-encoding")

    def compute_headers_hash(self, request: Request) -> str:
        """
        Compute hash of fingerprint-relevant headers

        Includes header ordering if configured, which is
        browser-specific and harder to spoof.
        """
        components: list[str] = []

        if self.use_header_order:
            header_keys = [k.lower() for k in request.headers]
            components.append("|".join(header_keys))

        for header_name in self.FINGERPRINT_HEADERS:
            value = request.headers.get(header_name, "")
            components.append(f"{header_name}={value}")

        fingerprint_string = "\n".join(components)
        hash_bytes = hashlib.sha256(fingerprint_string.encode()
                                    ).hexdigest()

        return hash_bytes[: self.hash_length]

    def extract_all(self, request: Request) -> dict[str, str | None]:
        """
        Extract all header-based fingerprint data
        """
        return {
            "user_agent": self.extract_user_agent(request),
            "accept_language": self.extract_accept_language(request),
            "accept_encoding": self.extract_accept_encoding(request),
            "headers_hash": self.compute_headers_hash(request),
        }
