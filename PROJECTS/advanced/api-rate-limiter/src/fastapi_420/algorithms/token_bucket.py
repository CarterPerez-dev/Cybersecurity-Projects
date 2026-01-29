"""
ⒸAngelaMos | 2025
token_bucket.py
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi_420.algorithms.base import BaseAlgorithm
from fastapi_420.types import Algorithm

if TYPE_CHECKING:
    from fastapi_420.storage import Storage
    from fastapi_420.types import RateLimitResult, RateLimitRule


class TokenBucketAlgorithm(BaseAlgorithm):
    """
    Token bucket algorithm

    Allows controlled bursting up to bucket capacity while
    enforcing average rate limits. Tokens refill at a constant
    rate and are consumed per request.

    Best for APIs that need burst tolerance with eventual rate enforcement.
    """
    @property
    def name(self) -> str:
        return Algorithm.TOKEN_BUCKET.value

    async def check(
        self,
        storage: Storage,
        key: str,
        rule: RateLimitRule,
        timestamp: float | None = None,  # noqa: ARG002
    ) -> RateLimitResult:
        """
        Check and consume token using token bucket algorithm
        """
        capacity = rule.requests
        refill_rate = rule.requests / rule.window_seconds

        return await storage.consume_token(
            key = key,
            capacity = capacity,
            refill_rate = refill_rate,
            tokens_to_consume = 1,
        )

    async def get_current_usage(
        self,
        storage: Storage,
        key: str,
        rule: RateLimitRule,
    ) -> int:
        """
        Get current token count (inverted as usage)
        """
        state = await storage.get_token_bucket_state(key = key)

        if state is None:
            return 0

        return rule.requests - int(state.tokens)
