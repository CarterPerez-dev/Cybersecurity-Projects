"""
ⒸAngelaMos | 2025
middleware.py
"""

from __future__ import annotations

import re
import logging
import asyncio
from typing import (
    TYPE_CHECKING,
)
from collections.abc import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import (
    JSONResponse,
    Response,
)

from fastapi_420.exceptions import (
    HTTP_420_ENHANCE_YOUR_CALM,
    EnhanceYourCalm,
)
from fastapi_420.limiter import RateLimiter

if TYPE_CHECKING:
    from starlette.types import ASGIApp


logger = logging.getLogger("fastapi_420")


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    ASGI middleware for automatic rate limiting on all routes

    Usage:
        from fastapi import FastAPI
        from fastapi_420.middleware import RateLimitMiddleware
        from fastapi_420.limiter import RateLimiter

        app = FastAPI()
        limiter = RateLimiter()

        app.add_middleware(
            RateLimitMiddleware,
            limiter=limiter,
            default_limit="100/minute",
        )
    """
    def __init__(
        self,
        app: ASGIApp,
        limiter: RateLimiter,
        default_limit: str = "100/minute",
        exclude_paths: list[str] | None = None,
        exclude_patterns: list[str] | None = None,
        include_paths: list[str] | None = None,
        path_limits: dict[str,
                          str] | None = None,
        key_func: Callable[[Request],
                           str] | None = None,
    ) -> None:
        super().__init__(app)
        self.limiter = limiter
        self.default_limit = default_limit
        self.exclude_paths = set(exclude_paths or [])
        self.exclude_patterns = [
            re.compile(p) for p in (exclude_patterns or [])
        ]
        self.include_paths = set(include_paths) if include_paths else None
        self.path_limits = path_limits or {}
        self.key_func = key_func

        self.exclude_paths.add("/health")
        self.exclude_paths.add("/healthz")
        self.exclude_paths.add("/ready")
        self.exclude_paths.add("/metrics")

    async def dispatch(self, request: Request, call_next: Callable) -> Response:  # type: ignore[type-arg]
        """
        Process request and apply rate limiting
        """
        if not await self._should_limit(request):
            return await call_next(request)  # type: ignore[no-any-return]

        limit = self._get_limit_for_path(request.url.path)
        result = await self.limiter.check(
            request,
            limit,
            key_func = self.key_func,
            raise_on_limit = False,
        )

        if not result.allowed:
            exc = EnhanceYourCalm(
                result = result,
                message = self.limiter.settings.HTTP_420_MESSAGE,
                detail = self.limiter.settings.HTTP_420_DETAIL,
            )
            return self._create_420_response(exc)

        response = await call_next(request)

        if self.limiter.settings.INCLUDE_HEADERS:
            for header_name, header_value in result.headers.items():
                response.headers[header_name] = header_value

        return response  # type: ignore[no-any-return]

    async def _should_limit(self, request: Request) -> bool:
        """
        Determine if request should be rate limited
        """
        path = request.url.path

        if path in self.exclude_paths:
            return False

        for pattern in self.exclude_patterns:
            if pattern.match(path):
                return False

        if self.include_paths is not None:  # noqa: SIM102
            if path not in self.include_paths:
                for include_path in self.include_paths:
                    if path.startswith(include_path):
                        break
                else:
                    return False

        return True

    def _get_limit_for_path(self, path: str) -> str:
        """
        Get rate limit for specific path
        """
        if path in self.path_limits:
            return self.path_limits[path]

        for pattern_path, limit in self.path_limits.items():
            if path.startswith(pattern_path):
                return limit

        return self.default_limit

    def _create_420_response(self, exc: EnhanceYourCalm) -> JSONResponse:
        """
        Create HTTP 420 response
        """
        headers = {}
        if exc.result:
            headers.update(exc.result.headers)

        return JSONResponse(
            status_code = HTTP_420_ENHANCE_YOUR_CALM,
            content = exc.detail,
            headers = headers,
        )


class SlowDownMiddleware(BaseHTTPMiddleware):
    """
    Alternative middleware that adds delays instead of blocking

    Useful for gradual throttling rather than hard limits
    """
    def __init__(
        self,
        app: ASGIApp,
        limiter: RateLimiter,
        threshold_limit: str = "50/minute",
        max_delay_seconds: float = 5.0,
        delay_increment: float = 0.5,
    ) -> None:
        super().__init__(app)
        self.limiter = limiter
        self.threshold_limit = threshold_limit
        self.max_delay_seconds = max_delay_seconds
        self.delay_increment = delay_increment

    async def dispatch(self, request: Request, call_next: Callable) -> Response:  # type: ignore[type-arg]
        """
        Process request with potential delays
        """
        result = await self.limiter.check(
            request,
            self.threshold_limit,
            raise_on_limit = False,
        )

        if result.remaining <= 0:
            delay = min(
                self.max_delay_seconds,
                result.retry_after or self.delay_increment,
            )
            await asyncio.sleep(delay)

        response = await call_next(request)

        if self.limiter.settings.INCLUDE_HEADERS:
            for header_name, header_value in result.headers.items():
                response.headers[header_name] = header_value

        return response  # type: ignore[no-any-return]
