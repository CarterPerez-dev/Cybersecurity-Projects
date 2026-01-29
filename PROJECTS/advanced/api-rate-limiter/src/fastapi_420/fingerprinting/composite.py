"""
ⒸAngelaMos | 2025
composite.py
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi_420.fingerprinting.auth import AuthExtractor
from fastapi_420.fingerprinting.headers import HeadersExtractor
from fastapi_420.fingerprinting.ip import IPExtractor
from fastapi_420.types import FingerprintData, FingerprintLevel

if TYPE_CHECKING:
    from starlette.requests import Request

    from fastapi_420.config import FingerprintSettings


class CompositeFingerprinter:  # pylint: disable=too-many-instance-attributes
    """
    Combines multiple fingerprinting methods based on configuration

    Preset levels determine which extractors are used:
    - strict: All methods (IP, headers, auth, TLS, geo)
    - normal: IP + User-Agent + Auth (default)
    - relaxed: IP + Auth only
    - custom: Configured via settings
    """
    def __init__(
        self,
        level: FingerprintLevel = FingerprintLevel.NORMAL,
        ip_extractor: IPExtractor | None = None,
        headers_extractor: HeadersExtractor | None = None,
        auth_extractor: AuthExtractor | None = None,
        use_ip: bool = True,
        use_user_agent: bool = True,
        use_accept_headers: bool = False,
        use_header_order: bool = False,
        use_auth: bool = True,
        use_tls: bool = False,
        use_geo: bool = False,
    ) -> None:
        self.level = level
        self._ip_extractor = ip_extractor or IPExtractor()
        self._headers_extractor = headers_extractor or HeadersExtractor(
            use_header_order = use_header_order,
        )
        self._auth_extractor = auth_extractor or AuthExtractor()

        if level == FingerprintLevel.STRICT:
            self.use_ip = True
            self.use_user_agent = True
            self.use_accept_headers = True
            self.use_header_order = True
            self.use_auth = True
            self.use_tls = True
            self.use_geo = True
        elif level == FingerprintLevel.RELAXED:
            self.use_ip = True
            self.use_user_agent = False
            self.use_accept_headers = False
            self.use_header_order = False
            self.use_auth = True
            self.use_tls = False
            self.use_geo = False
        elif level == FingerprintLevel.CUSTOM:
            self.use_ip = use_ip
            self.use_user_agent = use_user_agent
            self.use_accept_headers = use_accept_headers
            self.use_header_order = use_header_order
            self.use_auth = use_auth
            self.use_tls = use_tls
            self.use_geo = use_geo
        else:
            self.use_ip = True
            self.use_user_agent = True
            self.use_accept_headers = False
            self.use_header_order = False
            self.use_auth = True
            self.use_tls = False
            self.use_geo = False

    @classmethod
    def from_settings(
        cls,
        settings: FingerprintSettings
    ) -> CompositeFingerprinter:
        """
        Create fingerprinter from settings
        """
        ip_extractor = IPExtractor(
            ipv6_prefix_length = settings.IPV6_PREFIX_LENGTH,
            trusted_proxies = settings.TRUSTED_PROXIES,
            trust_x_forwarded_for = settings.TRUST_X_FORWARDED_FOR,
        )

        headers_extractor = HeadersExtractor(
            use_header_order = settings.USE_HEADER_ORDER,
        )

        return cls(
            level = settings.LEVEL,
            ip_extractor = ip_extractor,
            headers_extractor = headers_extractor,
            use_ip = settings.USE_IP,
            use_user_agent = settings.USE_USER_AGENT,
            use_accept_headers = settings.USE_ACCEPT_HEADERS,
            use_header_order = settings.USE_HEADER_ORDER,
            use_auth = settings.USE_AUTH,
            use_tls = settings.USE_TLS,
            use_geo = settings.USE_GEO,
        )

    async def extract(self, request: Request) -> FingerprintData:
        """
        Extract fingerprint data from request
        """
        raw_ip = ""
        normalized_ip = ""
        user_agent = None
        accept_language = None
        accept_encoding = None
        headers_hash = None
        auth_identifier = None
        tls_fingerprint = None
        geo_asn = None

        if self.use_ip:
            raw_ip, normalized_ip = self._ip_extractor.extract(request)

        if self.use_user_agent:
            user_agent = self._headers_extractor.extract_user_agent(
                request
            )

        if self.use_accept_headers:
            accept_language = self._headers_extractor.extract_accept_language(
                request
            )
            accept_encoding = self._headers_extractor.extract_accept_encoding(
                request
            )

        if self.use_header_order:
            headers_hash = self._headers_extractor.compute_headers_hash(
                request
            )

        if self.use_auth:
            auth_identifier = self._auth_extractor.extract(request)

        if self.use_tls:
            tls_fingerprint = self._extract_tls_fingerprint(request)

        if self.use_geo:
            geo_asn = self._extract_geo_asn(request)

        return FingerprintData(
            ip = raw_ip,
            ip_normalized = normalized_ip,
            user_agent = user_agent,
            accept_language = accept_language,
            accept_encoding = accept_encoding,
            headers_hash = headers_hash,
            auth_identifier = auth_identifier,
            tls_fingerprint = tls_fingerprint,
            geo_asn = geo_asn,
        )

    def _extract_tls_fingerprint(self, request: Request) -> str | None:
        """
        Extract TLS/JA3 fingerprint if available

        Requires proxy to pass fingerprint in header
        """
        return (
            request.headers.get("X-JA3-Fingerprint")
            or request.headers.get("X-TLS-Fingerprint")
        )

    def _extract_geo_asn(self, request: Request) -> str | None:
        """
        Extract geographic ASN if available

        Requires geo lookup service to populate header
        """
        return (
            request.headers.get("X-Client-ASN")
            or request.headers.get("CF-IPCountry")
        )

    def is_authenticated(self, request: Request) -> bool:
        """
        Check if request has authentication
        """
        return self._auth_extractor.is_authenticated(request)
