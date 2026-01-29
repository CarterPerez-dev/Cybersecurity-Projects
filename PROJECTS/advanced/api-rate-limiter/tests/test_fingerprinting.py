"""
ⒸAngelaMos | 2025
test_fingerprinting.py
"""
from __future__ import annotations

import pytest

from fastapi_420.fingerprinting.ip import IPExtractor
from fastapi_420.fingerprinting.headers import HeadersExtractor
from fastapi_420.fingerprinting.auth import AuthExtractor
from fastapi_420.fingerprinting.composite import CompositeFingerprinter
from fastapi_420.types import FingerprintLevel

from tests.conftest import (
    TEST_IP_V4,
    TEST_IP_V4_PRIVATE,
    TEST_IP_V6,
    TEST_IP_V6_NORMALIZED,
    TEST_IP_LOCALHOST,
    TEST_USER_AGENT,
    TEST_ACCEPT_LANGUAGE,
    TEST_ACCEPT_ENCODING,
    TEST_JWT_TOKEN,
    TEST_API_KEY,
    TEST_SESSION_ID,
    RequestFactory,
)


class TestIPExtractor:
    """
    Tests for IP address extraction and normalization
    """
    def test_extract_basic_ipv4(self) -> None:
        extractor = IPExtractor()
        request = RequestFactory.create(client_ip = TEST_IP_V4)
        raw_ip, normalized_ip = extractor.extract(request)

        assert raw_ip == TEST_IP_V4
        assert normalized_ip == TEST_IP_V4

    def test_extract_localhost(self) -> None:
        extractor = IPExtractor()
        request = RequestFactory.create(client_ip = TEST_IP_LOCALHOST)
        raw_ip, normalized_ip = extractor.extract(request)

        assert raw_ip == TEST_IP_LOCALHOST
        assert normalized_ip == TEST_IP_LOCALHOST

    def test_extract_private_ip(self) -> None:
        extractor = IPExtractor()
        request = RequestFactory.create(client_ip = TEST_IP_V4_PRIVATE)
        raw_ip, normalized_ip = extractor.extract(request)

        assert raw_ip == TEST_IP_V4_PRIVATE
        assert normalized_ip == TEST_IP_V4_PRIVATE

    def test_ipv6_normalization_to_64_prefix(self) -> None:
        extractor = IPExtractor(ipv6_prefix_length = 64)
        request = RequestFactory.create(client_ip = TEST_IP_V6)
        raw_ip, normalized_ip = extractor.extract(request)

        assert raw_ip == TEST_IP_V6
        assert normalized_ip == TEST_IP_V6_NORMALIZED

    def test_ipv6_custom_prefix_length(self) -> None:
        extractor = IPExtractor(ipv6_prefix_length = 48)
        request = RequestFactory.create(client_ip = TEST_IP_V6)
        raw_ip, normalized_ip = extractor.extract(request)

        assert "::" in normalized_ip or normalized_ip != TEST_IP_V6

    def test_ipv4_mapped_ipv6(self) -> None:
        extractor = IPExtractor()
        ipv4_mapped = "::ffff:192.168.1.100"
        request = RequestFactory.create(client_ip = ipv4_mapped)
        raw_ip, normalized_ip = extractor.extract(request)

        assert normalized_ip == "192.168.1.100"

    def test_invalid_ip_passthrough(self) -> None:
        extractor = IPExtractor()
        request = RequestFactory.create(client_ip = "invalid_ip")
        raw_ip, normalized_ip = extractor.extract(request)

        assert raw_ip == "invalid_ip"
        assert normalized_ip == "invalid_ip"

    def test_x_forwarded_for_disabled(self) -> None:
        extractor = IPExtractor(trust_x_forwarded_for = False)
        request = RequestFactory.with_forwarded_for(
            forwarded_ips = ["10.0.0.1",
                             "192.168.1.1"],
            client_ip = TEST_IP_V4,
        )
        raw_ip, _ = extractor.extract(request)

        assert raw_ip == TEST_IP_V4

    def test_x_forwarded_for_enabled(self) -> None:
        extractor = IPExtractor(trust_x_forwarded_for = True)
        request = RequestFactory.with_forwarded_for(
            forwarded_ips = ["10.0.0.1",
                             "192.168.1.1"],
            client_ip = TEST_IP_V4,
        )
        raw_ip, _ = extractor.extract(request)

        assert raw_ip == "10.0.0.1"

    def test_x_forwarded_for_with_trusted_proxies(self) -> None:
        extractor = IPExtractor(
            trust_x_forwarded_for = True,
            trusted_proxies = ["192.168.1.1"],
        )
        request = RequestFactory.with_forwarded_for(
            forwarded_ips = ["10.0.0.1",
                             "192.168.1.1"],
            client_ip = "172.16.0.1",
        )
        raw_ip, _ = extractor.extract(request)

        assert raw_ip == "10.0.0.1"

    def test_x_real_ip_header(self) -> None:
        extractor = IPExtractor(trusted_proxies = ["127.0.0.1"])
        request = RequestFactory.with_forwarded_for(
            forwarded_ips = [],
            real_ip = "203.0.113.50",
            client_ip = "127.0.0.1",
        )
        raw_ip, _ = extractor.extract(request)

        assert raw_ip == "203.0.113.50"

    def test_is_ipv6(self) -> None:
        extractor = IPExtractor()
        assert extractor.is_ipv6(TEST_IP_V6) is True
        assert extractor.is_ipv6(TEST_IP_V4) is False
        assert extractor.is_ipv6("invalid") is False

    def test_is_private(self) -> None:
        extractor = IPExtractor()
        assert extractor.is_private(TEST_IP_V4_PRIVATE) is True
        assert extractor.is_private(TEST_IP_LOCALHOST) is True
        assert extractor.is_private("8.8.8.8") is False
        assert extractor.is_private("invalid") is False


class TestHeadersExtractor:
    """
    Tests for HTTP header extraction and fingerprinting
    """
    def test_extract_user_agent(self) -> None:
        extractor = HeadersExtractor()
        request = RequestFactory.create()
        user_agent = extractor.extract_user_agent(request)

        assert user_agent == TEST_USER_AGENT

    def test_extract_user_agent_missing(self) -> None:
        extractor = HeadersExtractor()
        request = RequestFactory.create(headers = {"user-agent": ""})
        user_agent = extractor.extract_user_agent(request)

        assert user_agent == ""

    def test_extract_accept_language(self) -> None:
        extractor = HeadersExtractor()
        request = RequestFactory.create()
        accept_lang = extractor.extract_accept_language(request)

        assert accept_lang == TEST_ACCEPT_LANGUAGE

    def test_extract_accept_encoding(self) -> None:
        extractor = HeadersExtractor()
        request = RequestFactory.create()
        accept_enc = extractor.extract_accept_encoding(request)

        assert accept_enc == TEST_ACCEPT_ENCODING

    def test_compute_headers_hash(self) -> None:
        extractor = HeadersExtractor(hash_length = 16)
        request = RequestFactory.create()
        headers_hash = extractor.compute_headers_hash(request)

        assert len(headers_hash) == 16
        assert headers_hash.isalnum()

    def test_headers_hash_deterministic(self) -> None:
        extractor = HeadersExtractor()
        request1 = RequestFactory.create()
        request2 = RequestFactory.create()

        hash1 = extractor.compute_headers_hash(request1)
        hash2 = extractor.compute_headers_hash(request2)

        assert hash1 == hash2

    def test_headers_hash_different_headers(self) -> None:
        extractor = HeadersExtractor()
        request1 = RequestFactory.create(
            headers = {"user-agent": "Firefox/1.0"}
        )
        request2 = RequestFactory.create(
            headers = {"user-agent": "Chrome/1.0"}
        )

        hash1 = extractor.compute_headers_hash(request1)
        hash2 = extractor.compute_headers_hash(request2)

        assert hash1 != hash2

    def test_headers_hash_with_order(self) -> None:
        extractor = HeadersExtractor(use_header_order = True)
        request = RequestFactory.create()
        headers_hash = extractor.compute_headers_hash(request)

        assert len(headers_hash) == 16

    def test_extract_all(self) -> None:
        extractor = HeadersExtractor()
        request = RequestFactory.create()
        data = extractor.extract_all(request)

        assert "user_agent" in data
        assert "accept_language" in data
        assert "accept_encoding" in data
        assert "headers_hash" in data


class TestAuthExtractor:
    """
    Tests for authentication identifier extraction
    """
    def test_extract_jwt_bearer_token(self) -> None:
        extractor = AuthExtractor(hash_identifiers = False)
        request = RequestFactory.with_auth(
            auth_type = "bearer",
            token = TEST_JWT_TOKEN
        )
        identifier = extractor.extract(request)

        assert identifier == "user_123"

    def test_extract_jwt_bearer_token_hashed(self) -> None:
        extractor = AuthExtractor(
            hash_identifiers = True,
            hash_length = 16
        )
        request = RequestFactory.with_auth(
            auth_type = "bearer",
            token = TEST_JWT_TOKEN
        )
        identifier = extractor.extract(request)

        assert identifier is not None
        assert len(identifier) == 16
        assert identifier != "user_123"

    def test_extract_api_key_header(self) -> None:
        extractor = AuthExtractor(hash_identifiers = False)
        request = RequestFactory.with_auth(
            auth_type = "api_key",
            token = TEST_API_KEY
        )
        identifier = extractor.extract(request)

        assert identifier == TEST_API_KEY

    def test_extract_api_key_query_param(self) -> None:
        extractor = AuthExtractor(hash_identifiers = False)
        request = RequestFactory.create(
            query_params = {"api_key": TEST_API_KEY}
        )
        identifier = extractor.extract(request)

        assert identifier == TEST_API_KEY

    def test_extract_session_cookie(self) -> None:
        extractor = AuthExtractor(hash_identifiers = False)
        request = RequestFactory.create(
            cookies = {"session_id": TEST_SESSION_ID}
        )
        identifier = extractor.extract(request)

        assert identifier == TEST_SESSION_ID

    def test_extract_priority_jwt_over_api_key(self) -> None:
        extractor = AuthExtractor(hash_identifiers = False)
        request = RequestFactory.with_auth(
            auth_type = "bearer",
            token = TEST_JWT_TOKEN
        )
        identifier = extractor.extract(request)

        assert identifier == "user_123"

    def test_extract_no_auth(self) -> None:
        extractor = AuthExtractor()
        request = RequestFactory.create()
        identifier = extractor.extract(request)

        assert identifier is None

    def test_is_authenticated_true(self) -> None:
        extractor = AuthExtractor()
        request = RequestFactory.with_auth(
            auth_type = "bearer",
            token = TEST_JWT_TOKEN
        )

        assert extractor.is_authenticated(request) is True

    def test_is_authenticated_false(self) -> None:
        extractor = AuthExtractor()
        request = RequestFactory.create()

        assert extractor.is_authenticated(request) is False

    def test_invalid_jwt_format(self) -> None:
        extractor = AuthExtractor(hash_identifiers = False)
        request = RequestFactory.with_auth(
            auth_type = "bearer",
            token = "invalid"
        )
        identifier = extractor.extract(request)

        assert identifier is None

    def test_jwt_without_sub_claim(self) -> None:
        extractor = AuthExtractor(hash_identifiers = False)
        token_no_sub = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjk5OTk5OTk5OTl9.signature"
        request = RequestFactory.with_auth(
            auth_type = "bearer",
            token = token_no_sub
        )
        identifier = extractor.extract(request)

        assert identifier == "" or identifier is None


class TestCompositeFingerprinter:
    """
    Tests for composite fingerprint extraction
    """
    @pytest.mark.asyncio
    async def test_normal_level_extraction(self) -> None:
        fingerprinter = CompositeFingerprinter(
            level = FingerprintLevel.NORMAL
        )
        request = RequestFactory.with_auth()
        fp = await fingerprinter.extract(request)

        assert fp.ip == TEST_IP_V4
        assert fp.user_agent == TEST_USER_AGENT
        assert fp.auth_identifier is not None
        assert fp.accept_language is None
        assert fp.tls_fingerprint is None

    @pytest.mark.asyncio
    async def test_relaxed_level_extraction(self) -> None:
        fingerprinter = CompositeFingerprinter(
            level = FingerprintLevel.RELAXED
        )
        request = RequestFactory.with_auth()
        fp = await fingerprinter.extract(request)

        assert fp.ip == TEST_IP_V4
        assert fp.user_agent is None
        assert fp.auth_identifier is not None

    @pytest.mark.asyncio
    async def test_strict_level_extraction(self) -> None:
        fingerprinter = CompositeFingerprinter(
            level = FingerprintLevel.STRICT
        )
        request = RequestFactory.with_auth()
        fp = await fingerprinter.extract(request)

        assert fp.ip == TEST_IP_V4
        assert fp.user_agent == TEST_USER_AGENT
        assert fp.accept_language == TEST_ACCEPT_LANGUAGE
        assert fp.accept_encoding == TEST_ACCEPT_ENCODING
        assert fp.headers_hash is not None

    @pytest.mark.asyncio
    async def test_custom_level_ip_only(self) -> None:
        fingerprinter = CompositeFingerprinter(
            level = FingerprintLevel.CUSTOM,
            use_ip = True,
            use_user_agent = False,
            use_auth = False,
        )
        request = RequestFactory.with_auth()
        fp = await fingerprinter.extract(request)

        assert fp.ip == TEST_IP_V4
        assert fp.user_agent is None
        assert fp.auth_identifier is None

    @pytest.mark.asyncio
    async def test_tls_fingerprint_extraction(self) -> None:
        fingerprinter = CompositeFingerprinter(
            level = FingerprintLevel.STRICT
        )
        request = RequestFactory.create(
            headers = {"X-JA3-Fingerprint": "abc123hash"}
        )
        fp = await fingerprinter.extract(request)

        assert fp.tls_fingerprint == "abc123hash"

    @pytest.mark.asyncio
    async def test_geo_asn_extraction(self) -> None:
        fingerprinter = CompositeFingerprinter(
            level = FingerprintLevel.STRICT
        )
        request = RequestFactory.create(
            headers = {"X-Client-ASN": "AS12345"}
        )
        fp = await fingerprinter.extract(request)

        assert fp.geo_asn == "AS12345"

    @pytest.mark.asyncio
    async def test_cloudflare_country_header(self) -> None:
        fingerprinter = CompositeFingerprinter(
            level = FingerprintLevel.STRICT
        )
        request = RequestFactory.create(headers = {"CF-IPCountry": "US"})
        fp = await fingerprinter.extract(request)

        assert fp.geo_asn == "US"

    def test_is_authenticated_method(self) -> None:
        fingerprinter = CompositeFingerprinter(
            level = FingerprintLevel.NORMAL
        )
        auth_request = RequestFactory.with_auth()
        anon_request = RequestFactory.create()

        assert fingerprinter.is_authenticated(auth_request) is True
        assert fingerprinter.is_authenticated(anon_request) is False

    @pytest.mark.asyncio
    async def test_from_settings(self) -> None:
        from fastapi_420.config import FingerprintSettings

        settings = FingerprintSettings(
            LEVEL = FingerprintLevel.NORMAL,
            USE_IP = True,
            USE_USER_AGENT = True,
            USE_ACCEPT_HEADERS = False,
            USE_AUTH = True,
            IPV6_PREFIX_LENGTH = 64,
        )
        fingerprinter = CompositeFingerprinter.from_settings(settings)

        request = RequestFactory.with_auth()
        fp = await fingerprinter.extract(request)

        assert fp.ip is not None
        assert fp.user_agent is not None


class TestFingerprintDataCompositeKey:
    """
    Tests for composite key generation from fingerprint data
    """
    @pytest.mark.asyncio
    async def test_composite_key_relaxed_anonymous(self) -> None:
        fingerprinter = CompositeFingerprinter(
            level = FingerprintLevel.RELAXED
        )
        request = RequestFactory.create()
        fp = await fingerprinter.extract(request)

        key = fp.to_composite_key(FingerprintLevel.RELAXED)
        assert key == TEST_IP_V4

    @pytest.mark.asyncio
    async def test_composite_key_relaxed_authenticated(self) -> None:
        fingerprinter = CompositeFingerprinter(
            level = FingerprintLevel.RELAXED
        )
        request = RequestFactory.with_auth()
        fp = await fingerprinter.extract(request)

        key = fp.to_composite_key(FingerprintLevel.RELAXED)
        assert TEST_IP_V4 in key
        assert ":" in key

    @pytest.mark.asyncio
    async def test_composite_key_normal(self) -> None:
        fingerprinter = CompositeFingerprinter(
            level = FingerprintLevel.NORMAL
        )
        request = RequestFactory.with_auth()
        fp = await fingerprinter.extract(request)

        key = fp.to_composite_key(FingerprintLevel.NORMAL)
        parts = key.split(":")

        assert len(parts) == 3
        assert parts[0] == TEST_IP_V4
        assert TEST_USER_AGENT in parts[1]

    @pytest.mark.asyncio
    async def test_composite_key_strict(self) -> None:
        fingerprinter = CompositeFingerprinter(
            level = FingerprintLevel.STRICT
        )
        request = RequestFactory.with_auth()
        fp = await fingerprinter.extract(request)

        key = fp.to_composite_key(FingerprintLevel.STRICT)
        parts = key.split(":")

        assert len(parts) == 8

    @pytest.mark.asyncio
    async def test_composite_key_deterministic(self) -> None:
        fingerprinter = CompositeFingerprinter(
            level = FingerprintLevel.NORMAL
        )
        request = RequestFactory.with_auth()

        fp1 = await fingerprinter.extract(request)
        fp2 = await fingerprinter.extract(request)

        key1 = fp1.to_composite_key(FingerprintLevel.NORMAL)
        key2 = fp2.to_composite_key(FingerprintLevel.NORMAL)

        assert key1 == key2
