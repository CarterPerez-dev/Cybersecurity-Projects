"""
ⒸAngelaMos | 2025
dependencies.py
"""
from __future__ import annotations

from typing import Annotated
from collections.abc import Callable

from fastapi import Depends, Request

from fastapi_420.limiter import RateLimiter
from fastapi_420.types import RateLimitResult, RateLimitRule


_global_limiter: RateLimiter | None = None


def set_global_limiter(limiter: RateLimiter) -> None:
    """
    Set the global rate limiter instance for dependency injection
    """
    global _global_limiter  # pylint: disable=global-statement
    _global_limiter = limiter


def get_limiter() -> RateLimiter:
    """
    Get the global rate limiter instance
    """
    if _global_limiter is None:
        raise RuntimeError(
            "Rate limiter not initialized. "
            "Call set_global_limiter() or use RateLimiterDep with explicit limiter."
        )
    return _global_limiter


class RateLimitDep:
    """
    FastAPI dependency for rate limiting

    Usage:
        @app.get("/api/data", dependencies=[Depends(RateLimitDep("100/minute"))])
        async def get_data():
            return {"data": "value"}

        # Or with result access:
        @app.get("/api/data")
        async def get_data(limit_result: Annotated[RateLimitResult, Depends(RateLimitDep("100/minute"))]):
            return {"remaining": limit_result.remaining}
    """
    def __init__(
        self,
        *rules: str,
        limiter: RateLimiter | None = None,
        key_func: Callable[[Request],
                           str] | None = None,
    ) -> None:
        self.rules = [RateLimitRule.parse(rule) for rule in rules]
        self._limiter = limiter
        self.key_func = key_func

    @property
    def limiter(self) -> RateLimiter:
        """
        Get limiter instance
        """
        if self._limiter is not None:
            return self._limiter
        return get_limiter()

    async def __call__(self, request: Request) -> RateLimitResult:
        """
        Check rate limit and return result
        """
        rule_strings = [str(rule) for rule in self.rules]
        return await self.limiter.check(
            request,
            *rule_strings,
            key_func = self.key_func,
            raise_on_limit = True,
        )


def create_rate_limit_dep(
    *rules: str,
    limiter: RateLimiter | None = None,
    key_func: Callable[[Request],
                       str] | None = None,
) -> RateLimitDep:
    """
    Factory function to create rate limit dependency

    Usage:
        rate_limit = create_rate_limit_dep("100/minute", "1000/hour")

        @app.get("/api/data", dependencies=[Depends(rate_limit)])
        async def get_data():
            return {"data": "value"}
    """
    return RateLimitDep(*rules, limiter = limiter, key_func = key_func)


LimiterDep = Annotated[RateLimiter, Depends(get_limiter)]


async def require_rate_limit(
    request: Request,
    limiter: LimiterDep,
) -> RateLimitResult:
    """
    Dependency that applies default rate limits

    Usage:
        @app.get("/api/data")
        async def get_data(
            limit_result: Annotated[RateLimitResult, Depends(require_rate_limit)]
        ):
            return {"remaining": limit_result.remaining}
    """
    return await limiter.check(request, raise_on_limit = True)


class ScopedRateLimiter:
    """
    Rate limiter scoped to specific endpoints or route groups

    Usage:
        api_limiter = ScopedRateLimiter(
            prefix="/api/v1",
            default_rules=["100/minute"],
            endpoint_rules={
                "POST:/api/v1/upload": ["10/minute"],
                "POST:/api/v1/login": ["5/minute"],
            }
        )

        @app.post("/api/v1/upload", dependencies=[Depends(api_limiter)])
        async def upload():
            return {"status": "ok"}
    """
    def __init__(
        self,
        prefix: str = "",
        default_rules: list[str] | None = None,
        endpoint_rules: dict[str,
                             list[str]] | None = None,
        limiter: RateLimiter | None = None,
    ) -> None:
        self.prefix = prefix
        self.default_rules = default_rules or ["100/minute"]
        self.endpoint_rules = endpoint_rules or {}
        self._limiter = limiter

    @property
    def limiter(self) -> RateLimiter:
        """
        Get limiter instance
        """
        if self._limiter is not None:
            return self._limiter
        return get_limiter()

    async def __call__(self, request: Request) -> RateLimitResult:
        """
        Apply appropriate rate limit based on endpoint
        """
        endpoint = f"{request.method}:{request.url.path}"

        rules = self.endpoint_rules.get(endpoint, self.default_rules)

        return await self.limiter.check(
            request,
            *rules,
            raise_on_limit = True,
        )
