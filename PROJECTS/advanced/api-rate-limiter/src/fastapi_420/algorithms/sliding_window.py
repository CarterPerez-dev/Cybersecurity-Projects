"""
ⒸAngelaMos | 2025
sliding_window.py
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from fastapi_420.algorithms.base import BaseAlgorithm
from fastapi_420.types import Algorithm

if TYPE_CHECKING:
    from fastapi_420.storage import Storage
    from fastapi_420.types import RateLimitResult, RateLimitRule


class SlidingWindowAlgorithm(BaseAlgorithm):
    """
    Sliding window counter algorithm

    The recommended default for production rate limiting.
    Achieves ~99.997% accuracy with O(1) memory per client.
    Uses weighted interpolation between two fixed windows to
    approximate a true sliding window.
    """
    @property
    def name(self) -> str:
        return Algorithm.SLIDING_WINDOW.value

    async def check(
        self,
        storage: Storage,
        key: str,
        rule: RateLimitRule,
        timestamp: float | None = None,
    ) -> RateLimitResult:
        """
        Check and increment counter using sliding window algorithm
        """
        return await storage.increment(
            key = key,
            window_seconds = rule.window_seconds,
            limit = rule.requests,
            timestamp = timestamp,
        )

    async def get_current_usage(
        self,
        storage: Storage,
        key: str,
        rule: RateLimitRule,
    ) -> int:
        """
        Get current weighted usage count without incrementing
        """
        now = time.time()
        elapsed_ratio = (now % rule.window_seconds) / rule.window_seconds

        state = await storage.get_window_state(
            key = key,
            window_seconds = rule.window_seconds,
        )

        return int(state.weighted_count(elapsed_ratio))
