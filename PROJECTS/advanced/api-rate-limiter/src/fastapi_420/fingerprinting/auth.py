"""
ⒸAngelaMos | 2025
auth.py
"""

from __future__ import annotations

import jwt
import json
import base64
import hashlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from starlette.requests import Request


class AuthExtractor:
    """
    Extract authentication identifiers from requests

    Supports JWT tokens, API keys in headers/query params,
    and session-based authentication.
    """
    def __init__(
        self,
        jwt_secret: str | None = None,
        jwt_algorithms: list[str] | None = None,
        api_key_header: str = "X-API-Key",
        api_key_query_param: str = "api_key",
        session_cookie: str = "session_id",
        hash_identifiers: bool = True,
        hash_length: int = 16,
    ) -> None:
        self.jwt_secret = jwt_secret
        self.jwt_algorithms = jwt_algorithms or ["HS256"]
        self.api_key_header = api_key_header
        self.api_key_query_param = api_key_query_param
        self.session_cookie = session_cookie
        self.hash_identifiers = hash_identifiers
        self.hash_length = hash_length

    def extract(self, request: Request) -> str | None:
        """
        Extract authentication identifier using fallback chain

        Order: JWT -> API Key (header) -> API Key (query) -> Session -> None
        """
        identifier = (
            self._extract_jwt_subject(request)
            or self._extract_api_key_header(request)
            or self._extract_api_key_query(request)
            or self._extract_session(request)
        )

        if identifier and self.hash_identifiers:
            return self._hash_identifier(identifier)

        return identifier

    def _extract_jwt_subject(self, request: Request) -> str | None:
        """
        Extract subject claim from JWT Bearer token
        """
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            return None

        token = auth_header[7 :]

        if not self.jwt_secret:
            return self._extract_jwt_subject_unsafe(token)

        try:
            payload = jwt.decode(
                token,
                self.jwt_secret,
                algorithms = self.jwt_algorithms,
            )
            return str(payload.get("sub", ""))
        except Exception:
            return None

    def _extract_jwt_subject_unsafe(self, token: str) -> str | None:
        """
        Extract subject from JWT without verification

        Used when jwt_secret is not configured - only extracts
        the claim for rate limiting purposes, does NOT validate.
        """
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None

            payload_b64 = parts[1]
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding

            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            payload = json.loads(payload_bytes)

            return str(payload.get("sub", ""))
        except Exception:
            return None

    def _extract_api_key_header(self, request: Request) -> str | None:
        """
        Extract API key from header
        """
        return request.headers.get(self.api_key_header)

    def _extract_api_key_query(self, request: Request) -> str | None:
        """
        Extract API key from query parameter
        """
        return request.query_params.get(self.api_key_query_param)

    def _extract_session(self, request: Request) -> str | None:
        """
        Extract session ID from cookie
        """
        return request.cookies.get(self.session_cookie)

    def _hash_identifier(self, identifier: str) -> str:
        """
        Hash identifier for privacy
        """
        hash_bytes = hashlib.sha256(identifier.encode()).hexdigest()
        return hash_bytes[: self.hash_length]

    def is_authenticated(self, request: Request) -> bool:
        """
        Check if request has any authentication
        """
        return self.extract(request) is not None
