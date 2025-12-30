"""
ⒸAngelaMos | 2025
conftest.py
"""
from __future__ import annotations

import asyncio
import hashlib
import time
from collections.abc import AsyncGenerator, Generator
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient
from starlette.testclient import TestClient

from fastapi_420.algorithms import create_algorithm
from fastapi_420.algorithms.base import BaseAlgorithm
from fastapi_420.algorithms.fixed_window import FixedWindowAlgorithm
from fastapi_420.algorithms.sliding_window import SlidingWindowAlgorithm
from fastapi_420.algorithms.token_bucket import TokenBucketAlgorithm
from fastapi_420.config import (
    DefenseSettings,
    FingerprintSettings,
    RateLimiterSettings,
    StorageSettings,
)
from fastapi_420.defense.circuit_breaker import CircuitBreaker
from fastapi_420.defense.layers import LayeredDefense
from fastapi_420.dependencies import set_global_limiter
from fastapi_420.exceptions import HTTP_420_ENHANCE_YOUR_CALM
from fastapi_420.fingerprinting.auth import AuthExtractor
from fastapi_420.fingerprinting.composite import CompositeFingerprinter
from fastapi_420.fingerprinting.headers import HeadersExtractor
from fastapi_420.fingerprinting.ip import IPExtractor
from fastapi_420.limiter import RateLimiter
from fastapi_420.middleware import RateLimitMiddleware
from fastapi_420.storage import MemoryStorage
from fastapi_420.types import (
    Algorithm,
    CircuitState,
    DefenseContext,
    DefenseMode,
    FingerprintData,
    FingerprintLevel,
    Layer,
    RateLimitKey,
    RateLimitResult,
    RateLimitRule,
    StorageType,
    TokenBucketState,
    WindowState,
)


WINDOW_SECOND = 1
WINDOW_MINUTE = 60
WINDOW_HOUR = 3600
WINDOW_DAY = 86400

DEFAULT_LIMIT_REQUESTS = 100
DEFAULT_LIMIT_WINDOW = WINDOW_MINUTE
STRICT_LIMIT_REQUESTS = 10
STRICT_LIMIT_WINDOW = WINDOW_MINUTE

TEST_IP_V4 = "192.168.1.100"
TEST_IP_V4_PRIVATE = "10.0.0.1"
TEST_IP_V6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
TEST_IP_V6_NORMALIZED = "2001:db8:85a3::"
TEST_IP_LOCALHOST = "127.0.0.1"

TEST_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
TEST_ACCEPT_LANGUAGE = "en-US,en;q=0.9"
TEST_ACCEPT_ENCODING = "gzip, deflate, br"

TEST_JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEyMyIsImV4cCI6OTk5OTk5OTk5OX0.signature"
TEST_JWT_SUBJECT = "user_123"
TEST_API_KEY = "sk-test-api-key-12345"
TEST_SESSION_ID = "sess_abc123def456"

TEST_ENDPOINT = "/api/v1/test"
TEST_METHOD = "GET"

CIRCUIT_THRESHOLD = 1000
CIRCUIT_WINDOW = WINDOW_MINUTE
CIRCUIT_RECOVERY = 30

KEY_PREFIX = "ratelimit"
KEY_VERSION = "v1"


@dataclass
class MockScope:
    """
    Mock ASGI scope for request creation
    """
    type: str = "http"
    method: str = "GET"
    path: str = "/"
    query_string: bytes = b""
    headers: list[tuple[bytes, bytes]] = field(default_factory = list)
    client: tuple[str, int] | None = None
    route: Any = None


class MockRoute:
    """
    Mock route object for endpoint extraction
    """
    def __init__(self, path: str = TEST_ENDPOINT) -> None:
        self.path = path


class RequestFactory:
    """
    Factory for creating mock Starlette Request objects
    """
    @staticmethod
    def create(
        method: str = TEST_METHOD,
        path: str = TEST_ENDPOINT,
        client_ip: str = TEST_IP_V4,
        client_port: int = 12345,
        headers: dict[str,
                      str] | None = None,
        query_params: dict[str,
                           str] | None = None,
        cookies: dict[str,
                      str] | None = None,
        include_route: bool = True,
    ) -> Request:
        """
        Create a mock Request with configurable parameters
        """
        header_list: list[tuple[bytes, bytes]] = []

        default_headers = {
            "host": "localhost",
            "user-agent": TEST_USER_AGENT,
            "accept": "*/*",
            "accept-language": TEST_ACCEPT_LANGUAGE,
            "accept-encoding": TEST_ACCEPT_ENCODING,
        }

        if headers:
            default_headers.update(headers)

        for key, value in default_headers.items():
            header_list.append((key.lower().encode(), value.encode()))

        query_string = b""
        if query_params:
            query_string = "&".join(
                f"{k}={v}" for k, v in query_params.items()
            ).encode()

        scope = {
            "type": "http",
            "method": method,
            "path": path,
            "query_string": query_string,
            "headers": header_list,
            "client": (client_ip,
                       client_port),
        }

        if include_route:
            scope["route"] = MockRoute(path)

        request = Request(scope)

        if cookies:
            request._cookies = cookies

        return request

    @staticmethod
    def with_auth(
        auth_type: str = "bearer",
        token: str = TEST_JWT_TOKEN,
        **kwargs: Any,
    ) -> Request:
        """
        Create request with authentication header
        """
        headers = kwargs.pop("headers", {}) or {}

        if auth_type == "bearer":
            headers["authorization"] = f"Bearer {token}"
        elif auth_type == "api_key":
            headers["x-api-key"] = token
        elif auth_type == "basic":
            headers["authorization"] = f"Basic {token}"

        return RequestFactory.create(headers = headers, **kwargs)

    @staticmethod
    def with_forwarded_for(
        forwarded_ips: list[str],
        real_ip: str | None = None,
        **kwargs: Any,
    ) -> Request:
        """
        Create request with proxy headers
        """
        headers = kwargs.pop("headers", {}) or {}
        headers["x-forwarded-for"] = ", ".join(forwarded_ips)

        if real_ip:
            headers["x-real-ip"] = real_ip

        return RequestFactory.create(headers = headers, **kwargs)


class FingerprintFactory:
    """
    Factory for creating FingerprintData instances
    """
    @staticmethod
    def create(
        ip: str = TEST_IP_V4,
        ip_normalized: str | None = None,
        user_agent: str | None = TEST_USER_AGENT,
        accept_language: str | None = TEST_ACCEPT_LANGUAGE,
        accept_encoding: str | None = TEST_ACCEPT_ENCODING,
        headers_hash: str | None = None,
        auth_identifier: str | None = None,
        tls_fingerprint: str | None = None,
        geo_asn: str | None = None,
    ) -> FingerprintData:
        """
        Create FingerprintData with sensible defaults
        """
        return FingerprintData(
            ip = ip,
            ip_normalized = ip_normalized or ip,
            user_agent = user_agent,
            accept_language = accept_language,
            accept_encoding = accept_encoding,
            headers_hash = headers_hash,
            auth_identifier = auth_identifier,
            tls_fingerprint = tls_fingerprint,
            geo_asn = geo_asn,
        )

    @staticmethod
    def authenticated(
        auth_id: str = "user_123",
        hash_id: bool = True,
        **kwargs: Any,
    ) -> FingerprintData:
        """
        Create authenticated fingerprint
        """
        identifier = auth_id
        if hash_id:
            identifier = hashlib.sha256(auth_id.encode()).hexdigest()[: 16]

        return FingerprintFactory.create(
            auth_identifier = identifier,
            **kwargs
        )

    @staticmethod
    def anonymous(**kwargs: Any) -> FingerprintData:
        """
        Create anonymous fingerprint (no auth)
        """
        return FingerprintFactory.create(auth_identifier = None, **kwargs)

    @staticmethod
    def minimal(ip: str = TEST_IP_V4) -> FingerprintData:
        """
        Create minimal fingerprint (IP only)
        """
        return FingerprintData(
            ip = ip,
            ip_normalized = ip,
        )


class RuleFactory:
    """
    Factory for creating RateLimitRule instances
    """
    @staticmethod
    def create(
        requests: int = DEFAULT_LIMIT_REQUESTS,
        window_seconds: int = DEFAULT_LIMIT_WINDOW,
    ) -> RateLimitRule:
        """
        Create RateLimitRule with defaults
        """
        return RateLimitRule(
            requests = requests,
            window_seconds = window_seconds
        )

    @staticmethod
    def per_second(requests: int = 10) -> RateLimitRule:
        return RateLimitRule(
            requests = requests,
            window_seconds = WINDOW_SECOND
        )

    @staticmethod
    def per_minute(requests: int = 100) -> RateLimitRule:
        return RateLimitRule(
            requests = requests,
            window_seconds = WINDOW_MINUTE
        )

    @staticmethod
    def per_hour(requests: int = 1000) -> RateLimitRule:
        return RateLimitRule(
            requests = requests,
            window_seconds = WINDOW_HOUR
        )

    @staticmethod
    def per_day(requests: int = 10000) -> RateLimitRule:
        return RateLimitRule(
            requests = requests,
            window_seconds = WINDOW_DAY
        )

    @staticmethod
    def strict() -> RateLimitRule:
        return RateLimitRule(
            requests = STRICT_LIMIT_REQUESTS,
            window_seconds = STRICT_LIMIT_WINDOW,
        )

    @staticmethod
    def parse(rule_string: str) -> RateLimitRule:
        return RateLimitRule.parse(rule_string)


class ResultFactory:
    """
    Factory for creating RateLimitResult instances
    """
    @staticmethod
    def allowed(
        limit: int = DEFAULT_LIMIT_REQUESTS,
        remaining: int | None = None,
        reset_after: float = 60.0,
    ) -> RateLimitResult:
        """
        Create allowed result
        """
        return RateLimitResult(
            allowed = True,
            limit = limit,
            remaining = remaining if remaining is not None else limit - 1,
            reset_after = reset_after,
        )

    @staticmethod
    def denied(
        limit: int = DEFAULT_LIMIT_REQUESTS,
        reset_after: float = 60.0,
        retry_after: float | None = None,
    ) -> RateLimitResult:
        """
        Create denied result
        """
        return RateLimitResult(
            allowed = False,
            limit = limit,
            remaining = 0,
            reset_after = reset_after,
            retry_after = retry_after or reset_after,
        )

    @staticmethod
    def near_limit(
        limit: int = DEFAULT_LIMIT_REQUESTS,
        remaining: int = 1,
        reset_after: float = 30.0,
    ) -> RateLimitResult:
        """
        Create result near the limit
        """
        return RateLimitResult(
            allowed = True,
            limit = limit,
            remaining = remaining,
            reset_after = reset_after,
        )


class KeyFactory:
    """
    Factory for creating RateLimitKey instances
    """
    @staticmethod
    def create(
        prefix: str = KEY_PREFIX,
        version: str = KEY_VERSION,
        layer: Layer = Layer.USER,
        endpoint: str = TEST_ENDPOINT,
        identifier: str = TEST_IP_V4,
        window: int = WINDOW_MINUTE,
    ) -> RateLimitKey:
        """
        Create RateLimitKey with defaults
        """
        return RateLimitKey(
            prefix = prefix,
            version = version,
            layer = layer,
            endpoint = endpoint,
            identifier = identifier,
            window = window,
        )

    @staticmethod
    def user_key(
        endpoint: str = TEST_ENDPOINT,
        identifier: str = TEST_IP_V4,
        window: int = WINDOW_MINUTE,
    ) -> RateLimitKey:
        return KeyFactory.create(
            layer = Layer.USER,
            endpoint = endpoint,
            identifier = identifier,
            window = window,
        )

    @staticmethod
    def endpoint_key(
        endpoint: str = TEST_ENDPOINT,
        window: int = WINDOW_MINUTE,
    ) -> RateLimitKey:
        return KeyFactory.create(
            layer = Layer.ENDPOINT,
            endpoint = endpoint,
            identifier = "global",
            window = window,
        )

    @staticmethod
    def global_key(window: int = WINDOW_MINUTE) -> RateLimitKey:
        return KeyFactory.create(
            layer = Layer.GLOBAL,
            endpoint = "",
            identifier = "global",
            window = window,
        )


class WindowStateFactory:
    """
    Factory for creating WindowState instances
    """
    @staticmethod
    def create(
        current_count: int = 0,
        previous_count: int = 0,
        current_window: int | None = None,
        window_seconds: int = WINDOW_MINUTE,
    ) -> WindowState:
        """
        Create WindowState with defaults
        """
        if current_window is None:
            current_window = int(time.time() // window_seconds)

        return WindowState(
            current_count = current_count,
            previous_count = previous_count,
            current_window = current_window,
            window_seconds = window_seconds,
        )

    @staticmethod
    def empty() -> WindowState:
        return WindowStateFactory.create()

    @staticmethod
    def with_usage(current: int, previous: int = 0) -> WindowState:
        return WindowStateFactory.create(
            current_count = current,
            previous_count = previous,
        )


class TokenBucketStateFactory:
    """
    Factory for creating TokenBucketState instances
    """
    @staticmethod
    def create(
        tokens: float = 100.0,
        last_refill: float | None = None,
        capacity: int = 100,
        refill_rate: float = 1.67,
    ) -> TokenBucketState:
        """
        Create TokenBucketState with defaults
        """
        return TokenBucketState(
            tokens = tokens,
            last_refill = last_refill or time.time(),
            capacity = capacity,
            refill_rate = refill_rate,
        )

    @staticmethod
    def full(capacity: int = 100) -> TokenBucketState:
        return TokenBucketStateFactory.create(
            tokens = float(capacity),
            capacity = capacity,
        )

    @staticmethod
    def empty(capacity: int = 100) -> TokenBucketState:
        return TokenBucketStateFactory.create(
            tokens = 0.0,
            capacity = capacity
        )


class DefenseContextFactory:
    """
    Factory for creating DefenseContext instances
    """
    @staticmethod
    def create(
        fingerprint: FingerprintData | None = None,
        endpoint: str = TEST_ENDPOINT,
        method: str = TEST_METHOD,
        is_authenticated: bool = False,
        reputation_score: float = 1.0,
        request_count_last_minute: int = 0,
    ) -> DefenseContext:
        """
        Create DefenseContext with defaults
        """
        return DefenseContext(
            fingerprint = fingerprint or FingerprintFactory.create(),
            endpoint = endpoint,
            method = method,
            is_authenticated = is_authenticated,
            reputation_score = reputation_score,
            request_count_last_minute = request_count_last_minute,
        )

    @staticmethod
    def authenticated(**kwargs: Any) -> DefenseContext:
        fp = FingerprintFactory.authenticated()
        return DefenseContextFactory.create(
            fingerprint = fp,
            is_authenticated = True,
            **kwargs,
        )

    @staticmethod
    def suspicious(
        reputation_score: float = 0.3,
        request_count: int = 500,
    ) -> DefenseContext:
        return DefenseContextFactory.create(
            reputation_score = reputation_score,
            request_count_last_minute = request_count,
        )


class CircuitStateFactory:
    """
    Factory for creating CircuitState instances
    """
    @staticmethod
    def create(
        is_open: bool = False,
        failure_count: int = 0,
        last_failure_time: float = 0.0,
        half_open_requests: int = 0,
        total_requests_in_window: int = 0,
    ) -> CircuitState:
        """
        Create CircuitState with defaults
        """
        return CircuitState(
            is_open = is_open,
            failure_count = failure_count,
            last_failure_time = last_failure_time,
            half_open_requests = half_open_requests,
            total_requests_in_window = total_requests_in_window,
        )

    @staticmethod
    def closed() -> CircuitState:
        return CircuitStateFactory.create()

    @staticmethod
    def open(failure_time: float | None = None) -> CircuitState:
        return CircuitStateFactory.create(
            is_open = True,
            failure_count = 1,
            last_failure_time = failure_time or time.time(),
        )


@pytest.fixture
def storage_settings() -> StorageSettings:
    """
    Create test storage settings (memory backend)
    """
    return StorageSettings(
        REDIS_URL = None,
        MEMORY_MAX_KEYS = 10000,
        MEMORY_CLEANUP_INTERVAL = 60,
        FALLBACK_TO_MEMORY = True,
    )


@pytest.fixture
def fingerprint_settings() -> FingerprintSettings:
    """
    Create test fingerprint settings
    """
    return FingerprintSettings(
        LEVEL = FingerprintLevel.NORMAL,
        USE_IP = True,
        USE_USER_AGENT = True,
        USE_ACCEPT_HEADERS = False,
        USE_HEADER_ORDER = False,
        USE_AUTH = True,
        USE_TLS = False,
        USE_GEO = False,
        IPV6_PREFIX_LENGTH = 64,
        TRUSTED_PROXIES = [],
        TRUST_X_FORWARDED_FOR = False,
    )


@pytest.fixture
def defense_settings() -> DefenseSettings:
    """
    Create test defense settings
    """
    return DefenseSettings(
        MODE = DefenseMode.ADAPTIVE,
        GLOBAL_LIMIT = "50000/minute",
        CIRCUIT_THRESHOLD = CIRCUIT_THRESHOLD,
        CIRCUIT_WINDOW = CIRCUIT_WINDOW,
        CIRCUIT_RECOVERY_TIME = CIRCUIT_RECOVERY,
        ADAPTIVE_REDUCTION_FACTOR = 0.5,
        ENDPOINT_LIMIT_MULTIPLIER = 10,
        LOCKDOWN_ALLOW_AUTHENTICATED = True,
        LOCKDOWN_ALLOW_KNOWN_GOOD = True,
    )


@pytest.fixture
def rate_limiter_settings(
    storage_settings: StorageSettings,
    fingerprint_settings: FingerprintSettings,
    defense_settings: DefenseSettings,
) -> RateLimiterSettings:
    """
    Create test rate limiter settings
    """
    return RateLimiterSettings(
        ENABLED = True,
        ALGORITHM = Algorithm.SLIDING_WINDOW,
        DEFAULT_LIMIT = "100/minute",
        DEFAULT_LIMITS = ["100/minute",
                          "1000/hour"],
        FAIL_OPEN = True,
        KEY_PREFIX = KEY_PREFIX,
        KEY_VERSION = KEY_VERSION,
        INCLUDE_HEADERS = True,
        LOG_VIOLATIONS = False,
        ENVIRONMENT = "development",
        HTTP_420_MESSAGE = "Enhance your calm",
        HTTP_420_DETAIL = "Rate limit exceeded. Take a breather.",
        storage = storage_settings,
        fingerprint = fingerprint_settings,
        defense = defense_settings,
    )


@pytest.fixture
async def memory_storage() -> AsyncGenerator[MemoryStorage, None]:
    """
    Create and manage MemoryStorage instance
    """
    storage = MemoryStorage(max_keys = 10000, cleanup_interval = 60)
    await storage.start_cleanup_task()
    yield storage
    await storage.close()


@pytest.fixture
def sliding_window_algorithm() -> SlidingWindowAlgorithm:
    """
    Create sliding window algorithm instance
    """
    return SlidingWindowAlgorithm()


@pytest.fixture
def token_bucket_algorithm() -> TokenBucketAlgorithm:
    """
    Create token bucket algorithm instance
    """
    return TokenBucketAlgorithm()


@pytest.fixture
def fixed_window_algorithm() -> FixedWindowAlgorithm:
    """
    Create fixed window algorithm instance
    """
    return FixedWindowAlgorithm()


@pytest.fixture
def ip_extractor() -> IPExtractor:
    """
    Create IP extractor instance
    """
    return IPExtractor(
        ipv6_prefix_length = 64,
        trusted_proxies = [],
        trust_x_forwarded_for = False,
    )


@pytest.fixture
def headers_extractor() -> HeadersExtractor:
    """
    Create headers extractor instance
    """
    return HeadersExtractor(use_header_order = False, hash_length = 16)


@pytest.fixture
def auth_extractor() -> AuthExtractor:
    """
    Create auth extractor instance
    """
    return AuthExtractor(
        jwt_secret = None,
        jwt_algorithms = ["HS256"],
        api_key_header = "X-API-Key",
        api_key_query_param = "api_key",
        session_cookie = "session_id",
        hash_identifiers = True,
        hash_length = 16,
    )


@pytest.fixture
def composite_fingerprinter(
    ip_extractor: IPExtractor,
    headers_extractor: HeadersExtractor,
    auth_extractor: AuthExtractor,
) -> CompositeFingerprinter:
    """
    Create composite fingerprinter instance
    """
    return CompositeFingerprinter(
        level = FingerprintLevel.NORMAL,
        ip_extractor = ip_extractor,
        headers_extractor = headers_extractor,
        auth_extractor = auth_extractor,
    )


@pytest.fixture
async def circuit_breaker() -> CircuitBreaker:
    """
    Create circuit breaker instance
    """
    return CircuitBreaker(
        threshold = CIRCUIT_THRESHOLD,
        window_seconds = CIRCUIT_WINDOW,
        recovery_time = CIRCUIT_RECOVERY,
        defense_mode = DefenseMode.ADAPTIVE,
    )


@pytest.fixture
async def rate_limiter(
    rate_limiter_settings: RateLimiterSettings,
    memory_storage: MemoryStorage,
) -> AsyncGenerator[RateLimiter,
                    None]:
    """
    Create and manage RateLimiter instance
    """
    limiter = RateLimiter(
        settings = rate_limiter_settings,
        storage = memory_storage,
    )
    await limiter.init()
    yield limiter
    await limiter.close()


@pytest.fixture
async def layered_defense(
    memory_storage: MemoryStorage,
    rate_limiter_settings: RateLimiterSettings,
    circuit_breaker: CircuitBreaker,
) -> LayeredDefense:
    """
    Create layered defense instance
    """
    return LayeredDefense(
        storage = memory_storage,
        settings = rate_limiter_settings,
        circuit_breaker = circuit_breaker,
    )


@pytest.fixture
def test_request() -> Request:
    """
    Create a default test request
    """
    return RequestFactory.create()


@pytest.fixture
def authenticated_request() -> Request:
    """
    Create an authenticated test request
    """
    return RequestFactory.with_auth()


@pytest.fixture
def test_fingerprint() -> FingerprintData:
    """
    Create a default test fingerprint
    """
    return FingerprintFactory.create()


@pytest.fixture
def test_rule() -> RateLimitRule:
    """
    Create a default test rule
    """
    return RuleFactory.per_minute()


@pytest.fixture
def strict_rule() -> RateLimitRule:
    """
    Create a strict test rule
    """
    return RuleFactory.strict()


def create_test_app(
    limiter: RateLimiter | None = None,
    with_middleware: bool = False,
    default_limit: str = "100/minute",
) -> FastAPI:
    """
    Create a test FastAPI application
    """
    app = FastAPI(title = "Test API")

    @app.get("/")
    async def root() -> dict[str, str]:
        return {"message": "Hello World"}

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "healthy"}

    @app.get(TEST_ENDPOINT)
    async def test_endpoint() -> dict[str, str]:
        return {"endpoint": "test"}

    @app.post(TEST_ENDPOINT)
    async def test_endpoint_post() -> dict[str, str]:
        return {"created": "true"}

    @app.get("/api/v1/protected")
    async def protected_endpoint() -> dict[str, str]:
        return {"protected": "true"}

    if with_middleware and limiter:
        app.add_middleware(
            RateLimitMiddleware,
            limiter = limiter,
            default_limit = default_limit,
        )

    return app


@pytest.fixture
def test_app() -> FastAPI:
    """
    Create a basic test app without middleware
    """
    return create_test_app()


@pytest.fixture
async def test_app_with_limiter(
    rate_limiter: RateLimiter,
) -> FastAPI:
    """
    Create a test app with rate limiting middleware
    """
    app = create_test_app(limiter = rate_limiter, with_middleware = True)
    set_global_limiter(rate_limiter)
    return app


@pytest.fixture
async def async_client(test_app: FastAPI) -> AsyncGenerator[AsyncClient,
                                                            None]:
    """
    Create async HTTP client for testing
    """
    async with AsyncClient(
            transport = ASGITransport(app = test_app),
            base_url = "http://test",
    ) as client:
        yield client


@pytest.fixture
async def rate_limited_client(
    test_app_with_limiter: FastAPI,
) -> AsyncGenerator[AsyncClient,
                    None]:
    """
    Create async HTTP client with rate limiting
    """
    async with AsyncClient(
            transport = ASGITransport(app = test_app_with_limiter),
            base_url = "http://test",
    ) as client:
        yield client


@pytest.fixture
def sync_client(test_app: FastAPI) -> Generator[TestClient, None, None]:
    """
    Create sync test client
    """
    with TestClient(test_app) as client:
        yield client


def assert_rate_limit_headers(
    headers: dict[str,
                  str],
    expected_limit: int | None = None,
) -> None:
    """
    Assert rate limit headers are present and valid
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}

    assert "ratelimit-limit" in lower_headers
    assert "ratelimit-remaining" in lower_headers
    assert "ratelimit-reset" in lower_headers

    if expected_limit is not None:
        assert int(lower_headers["ratelimit-limit"]) == expected_limit

    assert int(lower_headers["ratelimit-remaining"]) >= 0
    assert int(lower_headers["ratelimit-reset"]) >= 0


def assert_420_response(
    response: Any,
    check_headers: bool = True,
) -> None:
    """
    Assert response is HTTP 420 with proper structure
    """
    assert response.status_code == HTTP_420_ENHANCE_YOUR_CALM

    if check_headers:
        lower_headers = {k.lower(): v for k, v in response.headers.items()}
        assert "retry-after" in lower_headers or "ratelimit-reset" in lower_headers


async def exhaust_rate_limit(
    storage: MemoryStorage,
    key: str,
    limit: int,
    window_seconds: int = WINDOW_MINUTE,
) -> None:
    """
    Helper to exhaust a rate limit by making requests
    """
    for _ in range(limit):
        await storage.increment(
            key = key,
            window_seconds = window_seconds,
            limit = limit,
        )


async def wait_for_window_reset(window_seconds: int = 1) -> None:
    """
    Helper to wait for a window to reset
    """
    await asyncio.sleep(window_seconds + 0.1)
