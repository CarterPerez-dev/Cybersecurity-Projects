"""
ⒸAngelaMos | 2025
test_integration.py
"""
from __future__ import annotations

import asyncio

import pytest
from fastapi import Depends, FastAPI, Request
from httpx import ASGITransport, AsyncClient

from fastapi_420.config import FingerprintSettings, RateLimiterSettings
from fastapi_420.dependencies import (
    RateLimitDep,
    ScopedRateLimiter,
    create_rate_limit_dep,
    set_global_limiter,
)
from fastapi_420.exceptions import HTTP_420_ENHANCE_YOUR_CALM
from fastapi_420.limiter import RateLimiter
from fastapi_420.middleware import RateLimitMiddleware, SlowDownMiddleware
from fastapi_420.storage import MemoryStorage
from fastapi_420.types import Algorithm

from tests.conftest import (
    assert_420_response,
    assert_rate_limit_headers,
)


def create_app_with_middleware(
    limiter: RateLimiter,
    default_limit: str = "100/minute",
    exclude_paths: list[str] | None = None,
) -> FastAPI:
    """
    Create a FastAPI app with rate limiting middleware
    """
    app = FastAPI(title = "Test App")

    @app.get("/")
    async def root():
        return {"message": "Hello World"}

    @app.get("/health")
    async def health():
        return {"status": "healthy"}

    @app.get("/api/test")
    async def test_endpoint():
        return {"endpoint": "test"}

    @app.post("/api/test")
    async def test_endpoint_post():
        return {"created": True}

    @app.get("/api/protected")
    async def protected():
        return {"protected": True}

    app.add_middleware(
        RateLimitMiddleware,
        limiter = limiter,
        default_limit = default_limit,
        exclude_paths = exclude_paths,
    )

    return app


def create_app_with_decorator(limiter: RateLimiter) -> FastAPI:
    """
    Create a FastAPI app using decorators for rate limiting
    """
    app = FastAPI(title = "Test App")

    @app.get("/")
    async def root():
        return {"message": "Hello World"}

    @app.get("/api/limited")
    @limiter.limit("5/minute")
    async def limited_endpoint(request: Request):
        return {"limited": True}

    @app.get("/api/multi-limited")
    @limiter.limit("10/minute", "100/hour")
    async def multi_limited_endpoint(request: Request):
        return {"multi": True}

    @app.get("/api/unlimited")
    async def unlimited_endpoint():
        return {"unlimited": True}

    return app


def create_app_with_dependency(limiter: RateLimiter) -> FastAPI:
    """
    Create a FastAPI app using dependency injection for rate limiting
    """
    app = FastAPI(title = "Test App")
    set_global_limiter(limiter)

    rate_limit = create_rate_limit_dep("5/minute")

    @app.get("/")
    async def root():
        return {"message": "Hello World"}

    @app.get("/api/limited", dependencies = [Depends(rate_limit)])
    async def limited_endpoint():
        return {"limited": True}

    @app.get("/api/with-result")
    async def with_result_endpoint(
        result = Depends(RateLimitDep("10/minute"))
    ):
        return {"remaining": result.remaining}

    return app


class TestMiddlewareIntegration:
    """
    Integration tests for RateLimitMiddleware
    """
    @pytest.mark.asyncio
    async def test_middleware_allows_requests_under_limit(self) -> None:
        storage = MemoryStorage()
        settings = RateLimiterSettings(INCLUDE_HEADERS = True)
        limiter = RateLimiter(settings = settings, storage = storage)
        await limiter.init()

        app = create_app_with_middleware(limiter, "100/minute")

        async with AsyncClient(transport = ASGITransport(app = app),
                               base_url = "http://test") as client:
            response = await client.get("/api/test")

            assert response.status_code == 200
            assert response.json() == {"endpoint": "test"}
            assert_rate_limit_headers(
                dict(response.headers),
                expected_limit = 100
            )

        await limiter.close()

    @pytest.mark.asyncio
    async def test_middleware_returns_420_when_exceeded(self) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()

        app = create_app_with_middleware(limiter, "5/minute")

        async with AsyncClient(transport = ASGITransport(app = app),
                               base_url = "http://test") as client:
            for _ in range(5):
                response = await client.get("/api/test")
                assert response.status_code == 200

            response = await client.get("/api/test")
            assert_420_response(response)

        await limiter.close()

    @pytest.mark.asyncio
    async def test_middleware_excludes_health_endpoint(self) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()

        app = create_app_with_middleware(limiter, "1/minute")

        async with AsyncClient(transport = ASGITransport(app = app),
                               base_url = "http://test") as client:
            for _ in range(10):
                response = await client.get("/health")
                assert response.status_code == 200

        await limiter.close()

    @pytest.mark.asyncio
    async def test_middleware_excludes_custom_paths(self) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()

        app = create_app_with_middleware(
            limiter,
            "1/minute",
            exclude_paths = ["/api/test"],
        )

        async with AsyncClient(transport = ASGITransport(app = app),
                               base_url = "http://test") as client:
            for _ in range(10):
                response = await client.get("/api/test")
                assert response.status_code == 200

        await limiter.close()

    @pytest.mark.asyncio
    async def test_middleware_different_endpoints_independent(
        self
    ) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()

        app = create_app_with_middleware(limiter, "3/minute")

        async with AsyncClient(transport = ASGITransport(app = app),
                               base_url = "http://test") as client:
            for _ in range(3):
                await client.get("/api/test")

            response1 = await client.get("/api/test")
            response2 = await client.get("/api/protected")

            assert response1.status_code == HTTP_420_ENHANCE_YOUR_CALM
            assert response2.status_code == 200

        await limiter.close()

    @pytest.mark.asyncio
    async def test_middleware_post_and_get_independent_limits(
        self
    ) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()

        app = create_app_with_middleware(limiter, "3/minute")

        async with AsyncClient(transport = ASGITransport(app = app),
                               base_url = "http://test") as client:
            for _ in range(3):
                await client.get("/api/test")

            get_response = await client.get("/api/test")
            assert get_response.status_code == HTTP_420_ENHANCE_YOUR_CALM

            post_response = await client.post("/api/test")
            assert post_response.status_code == 200

        await limiter.close()


class TestDecoratorIntegration:
    """
    Integration tests for @limiter.limit() decorator
    """
    @pytest.mark.asyncio
    async def test_decorator_allows_requests_under_limit(self) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()

        app = create_app_with_decorator(limiter)

        async with AsyncClient(transport = ASGITransport(app = app),
                               base_url = "http://test") as client:
            response = await client.get("/api/limited")
            assert response.status_code == 200
            assert response.json() == {"limited": True}

        await limiter.close()

    @pytest.mark.asyncio
    async def test_decorator_returns_420_when_exceeded(self) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()

        app = create_app_with_decorator(limiter)

        async with AsyncClient(transport = ASGITransport(app = app),
                               base_url = "http://test") as client:
            for _ in range(5):
                response = await client.get("/api/limited")
                assert response.status_code == 200

            response = await client.get("/api/limited")
            assert_420_response(response)

        await limiter.close()

    @pytest.mark.asyncio
    async def test_decorator_unlimited_endpoint_not_affected(self) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()

        app = create_app_with_decorator(limiter)

        async with AsyncClient(transport = ASGITransport(app = app),
                               base_url = "http://test") as client:
            for _ in range(100):
                response = await client.get("/api/unlimited")
                assert response.status_code == 200

        await limiter.close()

    @pytest.mark.asyncio
    async def test_decorator_different_endpoints_independent(self) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()

        app = create_app_with_decorator(limiter)

        async with AsyncClient(transport = ASGITransport(app = app),
                               base_url = "http://test") as client:
            for _ in range(5):
                await client.get("/api/limited")

            response1 = await client.get("/api/limited")
            response2 = await client.get("/api/multi-limited")

            assert response1.status_code == HTTP_420_ENHANCE_YOUR_CALM
            assert response2.status_code == 200

        await limiter.close()


class TestDependencyIntegration:
    """
    Integration tests for dependency injection
    """
    @pytest.mark.asyncio
    async def test_dependency_allows_requests_under_limit(self) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()

        app = create_app_with_dependency(limiter)

        async with AsyncClient(transport = ASGITransport(app = app),
                               base_url = "http://test") as client:
            response = await client.get("/api/limited")
            assert response.status_code == 200
            assert response.json() == {"limited": True}

        await limiter.close()

    @pytest.mark.asyncio
    async def test_dependency_returns_420_when_exceeded(self) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()

        app = create_app_with_dependency(limiter)

        async with AsyncClient(transport = ASGITransport(app = app),
                               base_url = "http://test") as client:
            for _ in range(5):
                response = await client.get("/api/limited")
                assert response.status_code == 200

            response = await client.get("/api/limited")
            assert_420_response(response)

        await limiter.close()

    @pytest.mark.asyncio
    async def test_dependency_with_result_access(self) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()

        app = create_app_with_dependency(limiter)

        async with AsyncClient(transport = ASGITransport(app = app),
                               base_url = "http://test") as client:
            response = await client.get("/api/with-result")
            assert response.status_code == 200
            data = response.json()
            assert "remaining" in data
            assert data["remaining"] == 9

        await limiter.close()


class TestScopedRateLimiterIntegration:
    """
    Integration tests for ScopedRateLimiter
    """
    @pytest.mark.asyncio
    async def test_scoped_limiter_applies_default_rules(self) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()
        set_global_limiter(limiter)

        app = FastAPI()
        scoped = ScopedRateLimiter(
            prefix = "/api",
            default_rules = ["5/minute"],
        )

        @app.get("/api/endpoint", dependencies = [Depends(scoped)])
        async def endpoint():
            return {"ok": True}

        async with AsyncClient(transport = ASGITransport(app = app),
                               base_url = "http://test") as client:
            for _ in range(5):
                response = await client.get("/api/endpoint")
                assert response.status_code == 200

            response = await client.get("/api/endpoint")
            assert_420_response(response)

        await limiter.close()

    @pytest.mark.asyncio
    async def test_scoped_limiter_endpoint_specific_rules(self) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()
        set_global_limiter(limiter)

        app = FastAPI()
        scoped = ScopedRateLimiter(
            prefix = "/api",
            default_rules = ["100/minute"],
            endpoint_rules = {
                "GET:/api/strict": ["2/minute"],
            },
        )

        @app.get("/api/normal", dependencies = [Depends(scoped)])
        async def normal():
            return {"type": "normal"}

        @app.get("/api/strict", dependencies = [Depends(scoped)])
        async def strict():
            return {"type": "strict"}

        async with AsyncClient(transport = ASGITransport(app = app),
                               base_url = "http://test") as client:
            for _ in range(2):
                response = await client.get("/api/strict")
                assert response.status_code == 200

            response = await client.get("/api/strict")
            assert_420_response(response)

            response = await client.get("/api/normal")
            assert response.status_code == 200

        await limiter.close()


class TestSlowDownMiddlewareIntegration:
    """
    Integration tests for SlowDownMiddleware
    """
    @pytest.mark.asyncio
    async def test_slowdown_middleware_allows_requests(self) -> None:
        storage = MemoryStorage()
        settings = RateLimiterSettings(INCLUDE_HEADERS = True)
        limiter = RateLimiter(settings = settings, storage = storage)
        await limiter.init()

        app = FastAPI()

        @app.get("/api/test")
        async def test_endpoint():
            return {"ok": True}

        app.add_middleware(
            SlowDownMiddleware,
            limiter = limiter,
            threshold_limit = "100/minute",
            max_delay_seconds = 1.0,
        )

        async with AsyncClient(transport = ASGITransport(app = app),
                               base_url = "http://test") as client:
            response = await client.get("/api/test")
            assert response.status_code == 200
            assert response.json() == {"ok": True}

        await limiter.close()


class TestConcurrentRequests:
    """
    Integration tests for concurrent request handling
    """
    @pytest.mark.asyncio
    async def test_concurrent_requests_all_counted(self) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()

        app = create_app_with_middleware(limiter, "100/minute")

        async with AsyncClient(transport = ASGITransport(app = app),
                               base_url = "http://test") as client:
            tasks = [client.get("/api/test") for _ in range(50)]
            responses = await asyncio.gather(*tasks)

            success_count = sum(
                1 for r in responses if r.status_code == 200
            )
            assert success_count == 50

        await limiter.close()

    @pytest.mark.asyncio
    async def test_concurrent_requests_enforce_limit(self) -> None:
        storage = MemoryStorage()
        limiter = RateLimiter(storage = storage)
        await limiter.init()

        app = create_app_with_middleware(limiter, "10/minute")

        async with AsyncClient(transport = ASGITransport(app = app),
                               base_url = "http://test") as client:
            tasks = [client.get("/api/test") for _ in range(20)]
            responses = await asyncio.gather(*tasks)

            success_count = sum(
                1 for r in responses if r.status_code == 200
            )
            blocked_count = sum(
                1 for r in responses
                if r.status_code == HTTP_420_ENHANCE_YOUR_CALM
            )

            assert success_count == 10
            assert blocked_count == 10

        await limiter.close()


class TestMultipleClients:
    """
    Integration tests for multiple clients (different IPs)
    """
    @pytest.mark.asyncio
    async def test_different_ips_independent_limits(self) -> None:
        storage = MemoryStorage()
        fingerprint_settings = FingerprintSettings(
            TRUST_X_FORWARDED_FOR = True
        )
        settings = RateLimiterSettings(fingerprint = fingerprint_settings)
        limiter = RateLimiter(settings = settings, storage = storage)
        await limiter.init()

        app = create_app_with_middleware(limiter, "5/minute")

        async with AsyncClient(transport = ASGITransport(app = app),
                               base_url = "http://test") as client:
            for _ in range(5):
                await client.get(
                    "/api/test",
                    headers = {"X-Forwarded-For": "192.168.1.1"}
                )

            response1 = await client.get(
                "/api/test",
                headers = {"X-Forwarded-For": "192.168.1.1"}
            )

            response2 = await client.get(
                "/api/test",
                headers = {"X-Forwarded-For": "192.168.1.2"}
            )

            assert response1.status_code == HTTP_420_ENHANCE_YOUR_CALM
            assert response2.status_code == 200

        await limiter.close()


class TestAlgorithmIntegration:
    """
    Integration tests for different algorithms
    """
    @pytest.mark.asyncio
    async def test_sliding_window_algorithm(self) -> None:
        settings = RateLimiterSettings(
            ALGORITHM = Algorithm.SLIDING_WINDOW
        )
        storage = MemoryStorage()
        limiter = RateLimiter(settings = settings, storage = storage)
        await limiter.init()

        app = create_app_with_middleware(limiter, "5/minute")

        async with AsyncClient(transport = ASGITransport(app = app),
                               base_url = "http://test") as client:
            for _ in range(5):
                response = await client.get("/api/test")
                assert response.status_code == 200

            response = await client.get("/api/test")
            assert_420_response(response)

        await limiter.close()

    @pytest.mark.asyncio
    async def test_token_bucket_algorithm(self) -> None:
        settings = RateLimiterSettings(ALGORITHM = Algorithm.TOKEN_BUCKET)
        storage = MemoryStorage()
        limiter = RateLimiter(settings = settings, storage = storage)
        await limiter.init()

        app = create_app_with_middleware(limiter, "5/minute")

        async with AsyncClient(transport = ASGITransport(app = app),
                               base_url = "http://test") as client:
            for _ in range(5):
                response = await client.get("/api/test")
                assert response.status_code == 200

            response = await client.get("/api/test")
            assert_420_response(response)

        await limiter.close()

    @pytest.mark.asyncio
    async def test_fixed_window_algorithm(self) -> None:
        settings = RateLimiterSettings(ALGORITHM = Algorithm.FIXED_WINDOW)
        storage = MemoryStorage()
        limiter = RateLimiter(settings = settings, storage = storage)
        await limiter.init()

        app = create_app_with_middleware(limiter, "5/minute")

        async with AsyncClient(transport = ASGITransport(app = app),
                               base_url = "http://test") as client:
            for _ in range(5):
                response = await client.get("/api/test")
                assert response.status_code == 200

            response = await client.get("/api/test")
            assert_420_response(response)

        await limiter.close()
