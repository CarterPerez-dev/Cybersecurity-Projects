"""
ⒸAngelaMos | 2025
limiter.py
"""

from __future__ import annotations

import asyncio
import logging
import functools
from typing import (
    Any,
    ParamSpec,
    TypeVar,
    TYPE_CHECKING,
)
from collections.abc import Callable

from starlette.requests import Request

from fastapi_420.algorithms import (
    create_algorithm,
)
from fastapi_420.config import (
    RateLimiterSettings,
    get_settings,
)
from fastapi_420.exceptions import (
    EnhanceYourCalm,
    StorageConnectionError,
    StorageError,
)
from fastapi_420.fingerprinting import (
    CompositeFingerprinter,
)
from fastapi_420.storage import (
    MemoryStorage,
    RedisStorage,
    create_storage,
)
from fastapi_420.types import (
    Layer,
    RateLimitKey,
    RateLimitResult,
    RateLimitRule,
)

if TYPE_CHECKING:
    from fastapi_420.algorithms.base import BaseAlgorithm
    from fastapi_420.storage import Storage


logger = logging.getLogger("fastapi_420")

P = ParamSpec("P")
R = TypeVar("R")


class RateLimiter:
    """
    Main rate limiter class for FastAPI applications.

    Usage:
        limiter = RateLimiter()

        @app.get("/api/data")
        @limiter.limit("100/minute", "1000/hour")
        async def get_data(request: Request):
            return {"data": "value"}
    """
    def __init__(
        self,
        settings: RateLimiterSettings | None = None,
        storage: Storage | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._storage = storage
        self._fallback_storage: MemoryStorage | None = None
        self._algorithm: BaseAlgorithm | None = None
        self._fingerprinter: CompositeFingerprinter | None = None
        self._initialized = False
        self._lock = asyncio.Lock()

    async def init(self) -> None:
        """
        Initialize storage, algorithm, and fingerprinter
        """
        async with self._lock:
            if self._initialized:
                return

            if self._storage is None:
                self._storage = create_storage(self._settings.storage)

            if self._settings.storage.FALLBACK_TO_MEMORY:
                self._fallback_storage = MemoryStorage.from_settings(
                    self._settings.storage
                )
                await self._fallback_storage.start_cleanup_task()

            if isinstance(self._storage, RedisStorage):
                try:
                    await self._storage.connect()
                except StorageConnectionError:
                    if self._settings.FAIL_OPEN and self._fallback_storage:
                        logger.warning(
                            "Redis unavailable, using memory fallback",
                            extra = {
                                "redis_url":
                                self._settings.storage.REDIS_URL
                            },
                        )
                        self._storage = self._fallback_storage
                        self._fallback_storage = None
                    else:
                        raise

            if isinstance(self._storage,
                          MemoryStorage
                          ) and self._storage != self._fallback_storage:
                await self._storage.start_cleanup_task()

            self._algorithm = create_algorithm(self._settings.ALGORITHM)
            self._fingerprinter = CompositeFingerprinter.from_settings(
                self._settings.fingerprint
            )

            self._initialized = True
            logger.info(
                "Rate limiter initialized",
                extra = {
                    "algorithm":
                    self._settings.ALGORITHM.value,
                    "storage":
                    self._storage.storage_type.value,
                    "fingerprint_level":
                    self._settings.fingerprint.LEVEL.value,
                },
            )

    async def close(self) -> None:
        """
        Close storage connections
        """
        if self._storage:
            await self._storage.close()

        if self._fallback_storage:
            await self._fallback_storage.close()

        self._initialized = False

    def limit(
        self,
        *rules: str,
        key_func: Callable[[Request],
                           str] | None = None,
    ) -> Callable[[Callable[P,
                            R]],
                  Callable[P,
                           R]]:
        """
        Decorator to apply rate limits to an endpoint

        Args:
            rules: Rate limit strings like "100/minute", "1000/hour"
            key_func: Optional custom function to generate rate limit key
        """
        parsed_rules = [RateLimitRule.parse(rule) for rule in rules]

        def decorator(func: Callable[P, R]) -> Callable[P, R]:
            @functools.wraps(func)
            async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
                request = self._extract_request(args, kwargs)

                if request is None:
                    return await func(*args, **kwargs)  # type: ignore[misc, no-any-return]

                await self._check_rate_limits(
                    request = request,
                    rules = parsed_rules,
                    key_func = key_func,
                )

                return await func(*args, **kwargs)  # type: ignore[misc, no-any-return]

            return wrapper  # type: ignore[return-value]

        return decorator

    async def check(
        self,
        request: Request,
        *rules: str,
        key_func: Callable[[Request],
                           str] | None = None,
        raise_on_limit: bool = True,
    ) -> RateLimitResult:
        """
        Manually check rate limit without decorator

        Returns the result of the strictest (most restrictive) rule
        """
        parsed_rules = [RateLimitRule.parse(rule) for rule in rules]

        if not parsed_rules:
            parsed_rules = self._settings.get_default_rules()

        return await self._check_rate_limits(
            request = request,
            rules = parsed_rules,
            key_func = key_func,
            raise_on_limit = raise_on_limit,
        )

    async def _check_rate_limits(
        self,
        request: Request,
        rules: list[RateLimitRule],
        key_func: Callable[[Request],
                           str] | None = None,
        raise_on_limit: bool = True,
    ) -> RateLimitResult:
        """
        Check all rules and return/raise for the most restrictive failure
        """
        if not self._initialized:
            await self.init()

        storage = await self._get_active_storage()
        if storage is None:
            if self._settings.FAIL_OPEN:
                return RateLimitResult(
                    allowed = True,
                    limit = 0,
                    remaining = 0,
                    reset_after = 0,
                )
            raise StorageError(operation = "check", backend = None)

        fingerprint = await self._fingerprinter.extract(request)  # type: ignore[union-attr]
        endpoint = self._get_endpoint(request)

        if key_func:
            identifier = key_func(request)
        else:
            identifier = fingerprint.to_composite_key(
                self._settings.fingerprint.LEVEL
            )

        worst_result: RateLimitResult | None = None

        for rule in rules:
            key = RateLimitKey(
                prefix = self._settings.KEY_PREFIX,
                version = self._settings.KEY_VERSION,
                layer = Layer.USER,
                endpoint = endpoint,
                identifier = identifier,
                window = rule.window_seconds,
            ).build()

            result = await self._algorithm.check(  # type: ignore[union-attr]
                storage = storage,
                key = key,
                rule = rule,
            )

            if not result.allowed:  # noqa: SIM102
                if worst_result is None or result.retry_after > (worst_result.retry_after or 0):  # type: ignore[operator]
                    worst_result = result

        if worst_result is not None:
            if self._settings.LOG_VIOLATIONS:
                logger.warning(
                    "Rate limit exceeded",
                    extra = {
                        "endpoint": endpoint,
                        "identifier": identifier[: 16],
                        "remaining": worst_result.remaining,
                        "reset_after": worst_result.reset_after,
                    },
                )

            if raise_on_limit:
                raise EnhanceYourCalm(
                    result = worst_result,
                    message = self._settings.HTTP_420_MESSAGE,
                    detail = self._settings.HTTP_420_DETAIL,
                )

            return worst_result

        best_result = result
        return best_result

    async def _get_active_storage(self) -> Storage | None:
        """
        Get active storage, falling back to memory if primary fails
        """
        if self._storage is None:
            return self._fallback_storage

        try:
            is_healthy = await self._storage.health_check()
            if is_healthy:
                return self._storage
        except Exception:  # noqa: S110
            pass

        if self._fallback_storage:
            logger.warning(
                "Primary storage unavailable, using memory fallback",
                extra = {
                    "primary_storage": self._storage.storage_type.value
                },
            )
            return self._fallback_storage

        return None

    def _extract_request(
        self,
        args: tuple[Any,
                    ...],
        kwargs: dict[str,
                     Any],
    ) -> Request | None:
        """
        Extract Request object from function arguments
        """
        for arg in args:
            if isinstance(arg, Request):
                return arg

        for value in kwargs.values():
            if isinstance(value, Request):
                return value

        return None

    def _get_endpoint(self, request: Request) -> str:
        """
        Get endpoint identifier from request
        """
        route = request.scope.get("route")
        if route:
            return f"{request.method}:{route.path}"

        return f"{request.method}:{request.url.path}"

    @property
    def settings(self) -> RateLimiterSettings:
        """
        Get current settings
        """
        return self._settings

    @property
    def is_initialized(self) -> bool:
        """
        Check if limiter is initialized
        """
        return self._initialized
