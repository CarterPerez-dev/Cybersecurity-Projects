"""
ⒸAngelaMos | 2025
test_limiter.py
"""
from __future__ import annotations

import pytest

from fastapi_420.config import RateLimiterSettings
from fastapi_420.exceptions import EnhanceYourCalm, HTTP_420_ENHANCE_YOUR_CALM
from fastapi_420.limiter import RateLimiter
from fastapi_420.storage import MemoryStorage
from fastapi_420.types import Algorithm, FingerprintLevel

from tests.conftest import (
    WINDOW_MINUTE,
    DEFAULT_LIMIT_REQUESTS,
    RequestFactory,
)


class TestRateLimiterInit:
    """
    Tests for RateLimiter initialization
    """
    @pytest.mark.asyncio
    async def test_init_with_defaults(self) -> None:
        limiter = RateLimiter()
        assert limiter.is_initialized is False
        await limiter.init()
        assert limiter.is_initialized is True
        await limiter.close()

    @pytest.mark.asyncio
    async def test_init_with_custom_settings(self) -> None:
        settings = RateLimiterSettings(
            ALGORITHM = Algorithm.TOKEN_BUCKET,
            DEFAULT_LIMIT = "50/minute",
        )
        limiter = RateLimiter(settings = settings)
        await limiter.init()

        assert limiter.settings.ALGORITHM == Algorithm.TOKEN_BUCKET
        assert limiter.settings.DEFAULT_LIMIT == "50/minute"

        await limiter.close()

    @pytest.mark.asyncio
    async def test_init_with_provided_storage(self) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()

        assert limiter.is_initialized is True

        await limiter.close()

    @pytest.mark.asyncio
    async def test_init_idempotent(self) -> None:
        limiter = RateLimiter()
        await limiter.init()
        await limiter.init()
        await limiter.init()

        assert limiter.is_initialized is True

        await limiter.close()

    @pytest.mark.asyncio
    async def test_close_resets_initialized(self) -> None:
        limiter = RateLimiter()
        await limiter.init()
        assert limiter.is_initialized is True

        await limiter.close()
        assert limiter.is_initialized is False


class TestRateLimiterCheck:
    """
    Tests for RateLimiter.check() method
    """
    @pytest.mark.asyncio
    async def test_check_allows_first_request(self) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()

        request = RequestFactory.create()
        result = await limiter.check(
            request,
            "100/minute",
            raise_on_limit = False
        )

        assert result.allowed is True
        assert result.remaining == 99

        await limiter.close()

    @pytest.mark.asyncio
    async def test_check_multiple_rules(self) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()

        request = RequestFactory.create()
        result = await limiter.check(
            request,
            "100/minute",
            "1000/hour",
            raise_on_limit = False,
        )

        assert result.allowed is True

        await limiter.close()

    @pytest.mark.asyncio
    async def test_check_uses_default_rules_when_none_provided(
        self
    ) -> None:
        settings = RateLimiterSettings(
            DEFAULT_LIMITS = ["50/minute"],
        )
        storage = MemoryStorage()
        limiter = RateLimiter(settings = settings, storage = storage)
        await limiter.init()

        request = RequestFactory.create()
        result = await limiter.check(request, raise_on_limit = False)

        assert result.allowed is True
        assert result.limit == 50

        await limiter.close()

    @pytest.mark.asyncio
    async def test_check_raises_on_limit(self) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()

        request = RequestFactory.create()

        for _ in range(5):
            await limiter.check(
                request,
                "5/minute",
                raise_on_limit = False
            )

        with pytest.raises(EnhanceYourCalm) as exc_info:
            await limiter.check(request, "5/minute", raise_on_limit = True)

        assert exc_info.value.status_code == HTTP_420_ENHANCE_YOUR_CALM

        await limiter.close()

    @pytest.mark.asyncio
    async def test_check_returns_result_when_not_raising(self) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()

        request = RequestFactory.create()

        for _ in range(5):
            await limiter.check(
                request,
                "5/minute",
                raise_on_limit = False
            )

        result = await limiter.check(
            request,
            "5/minute",
            raise_on_limit = False
        )

        assert result.allowed is False
        assert result.remaining == 0

        await limiter.close()

    @pytest.mark.asyncio
    async def test_check_different_endpoints_independent(self) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()

        request1 = RequestFactory.create(path = "/api/endpoint1")
        request2 = RequestFactory.create(path = "/api/endpoint2")

        for _ in range(5):
            await limiter.check(
                request1,
                "5/minute",
                raise_on_limit = False
            )

        result1 = await limiter.check(
            request1,
            "5/minute",
            raise_on_limit = False
        )
        result2 = await limiter.check(
            request2,
            "5/minute",
            raise_on_limit = False
        )

        assert result1.allowed is False
        assert result2.allowed is True

        await limiter.close()

    @pytest.mark.asyncio
    async def test_check_different_users_independent(self) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()

        request1 = RequestFactory.create(client_ip = "192.168.1.1")
        request2 = RequestFactory.create(client_ip = "192.168.1.2")

        for _ in range(5):
            await limiter.check(
                request1,
                "5/minute",
                raise_on_limit = False
            )

        result1 = await limiter.check(
            request1,
            "5/minute",
            raise_on_limit = False
        )
        result2 = await limiter.check(
            request2,
            "5/minute",
            raise_on_limit = False
        )

        assert result1.allowed is False
        assert result2.allowed is True

        await limiter.close()

    @pytest.mark.asyncio
    async def test_check_with_custom_key_func(self) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()

        def custom_key(request):
            return "shared_key"

        request1 = RequestFactory.create(client_ip = "192.168.1.1")
        request2 = RequestFactory.create(client_ip = "192.168.1.2")

        for _ in range(5):
            await limiter.check(
                request1,
                "5/minute",
                key_func = custom_key,
                raise_on_limit = False,
            )

        result = await limiter.check(
            request2,
            "5/minute",
            key_func = custom_key,
            raise_on_limit = False,
        )

        assert result.allowed is False

        await limiter.close()

    @pytest.mark.asyncio
    async def test_check_auto_initializes(self) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)

        assert limiter.is_initialized is False

        request = RequestFactory.create()
        result = await limiter.check(
            request,
            "100/minute",
            raise_on_limit = False
        )

        assert limiter.is_initialized is True
        assert result.allowed is True

        await limiter.close()


class TestRateLimiterDecorator:
    """
    Tests for RateLimiter.limit() decorator
    """
    @pytest.mark.asyncio
    async def test_decorator_basic_usage(self) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()

        @limiter.limit("100/minute")
        async def endpoint(request):
            return {"success": True}

        request = RequestFactory.create()
        result = await endpoint(request)

        assert result == {"success": True}

        await limiter.close()

    @pytest.mark.asyncio
    async def test_decorator_enforces_limit(self) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()

        @limiter.limit("5/minute")
        async def endpoint(request):
            return {"success": True}

        request = RequestFactory.create()

        for _ in range(5):
            await endpoint(request)

        with pytest.raises(EnhanceYourCalm):
            await endpoint(request)

        await limiter.close()

    @pytest.mark.asyncio
    async def test_decorator_multiple_rules(self) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()

        @limiter.limit("100/minute", "1000/hour")
        async def endpoint(request):
            return {"success": True}

        request = RequestFactory.create()
        result = await endpoint(request)

        assert result == {"success": True}

        await limiter.close()

    @pytest.mark.asyncio
    async def test_decorator_without_request_skips(self) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()

        @limiter.limit("5/minute")
        async def endpoint():
            return {"success": True}

        result = await endpoint()
        assert result == {"success": True}

        await limiter.close()

    @pytest.mark.asyncio
    async def test_decorator_request_in_kwargs(self) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()

        @limiter.limit("100/minute")
        async def endpoint(data: str, request = None):
            return {"data": data}

        request = RequestFactory.create()
        result = await endpoint("test", request = request)

        assert result == {"data": "test"}

        await limiter.close()


class TestRateLimiterFailOpen:
    """
    Tests for fail-open behavior
    """
    @pytest.mark.asyncio
    async def test_fail_open_allows_requests_on_storage_failure(
        self
    ) -> None:
        settings = RateLimiterSettings(FAIL_OPEN = True)
        storage = MemoryStorage()
        await storage.close()

        limiter = RateLimiter(settings = settings, storage = storage)
        limiter._initialized = True
        limiter._storage = storage
        limiter._fallback_storage = None

        request = RequestFactory.create()
        result = await limiter.check(
            request,
            "100/minute",
            raise_on_limit = False
        )

        assert result.allowed is True


class TestRateLimiterSettings:
    """
    Tests for settings access
    """
    @pytest.mark.asyncio
    async def test_settings_property(self) -> None:
        settings = RateLimiterSettings(
            HTTP_420_MESSAGE = "Custom message",
            HTTP_420_DETAIL = "Custom detail",
        )
        limiter = RateLimiter(settings = settings)

        assert limiter.settings.HTTP_420_MESSAGE == "Custom message"
        assert limiter.settings.HTTP_420_DETAIL == "Custom detail"

    @pytest.mark.asyncio
    async def test_is_initialized_property(self) -> None:
        limiter = RateLimiter()
        assert limiter.is_initialized is False

        await limiter.init()
        assert limiter.is_initialized is True

        await limiter.close()
        assert limiter.is_initialized is False
