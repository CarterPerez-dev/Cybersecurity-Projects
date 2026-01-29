"""
ⒸAngelaMos | 2025
base.py
"""
# pylint: disable=unnecessary-ellipsis

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi_420.storage import Storage
    from fastapi_420.types import RateLimitResult, RateLimitRule


class BaseAlgorithm(ABC):
    """
    Abstract base class for rate limiting algorithms
    """
    @property
    @abstractmethod
    def name(self) -> str:
        """
        Algorithm name for logging and debugging
        """
        ...

    @abstractmethod
    async def check(
        self,
        storage: Storage,
        key: str,
        rule: RateLimitRule,
        timestamp: float | None = None,
    ) -> RateLimitResult:
        """
        Check if request is allowed under rate limit
        """
        ...

    @abstractmethod
    async def get_current_usage(
        self,
        storage: Storage,
        key: str,
        rule: RateLimitRule,
    ) -> int:
        """
        Get current usage count without incrementing
        """
        ...
