"""
ⒸAngelaMos | 2025
memory.py
"""
from __future__ import annotations

import asyncio
import contextlib
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from fastapi_420.types import (
    RateLimitResult,
    StorageType,
    TokenBucketState,
    WindowState,
)

if TYPE_CHECKING:
    from fastapi_420.config import StorageSettings


@dataclass
class WindowEntry:
    """
    Storage entry for sliding window counter.
    """
    count: int = 0
    window_start: int = 0
    expires_at: float = 0.0


@dataclass
class MemoryStorage:
    """
    In memory storage backend for rate limiting.

    Thread safe through asyncio locks. Suitable for single instance
    deployments, development, and as a fallback when Redis is unavailable
    """
    max_keys: int = 100_000
    cleanup_interval: int = 60
    _windows: OrderedDict[str,
                          WindowEntry] = field(
                              default_factory = OrderedDict
                          )
    _buckets: dict[str, TokenBucketState] = field(default_factory = dict)
    _lock: asyncio.Lock = field(default_factory = asyncio.Lock)
    _cleanup_task: asyncio.Task[None] | None = field(
        default = None,
        repr = False
    )
    _closed: bool = field(default = False)

    @classmethod
    def from_settings(cls, settings: StorageSettings) -> MemoryStorage:
        """
        Create storage instance from settings
        """
        return cls(
            max_keys = settings.MEMORY_MAX_KEYS,
            cleanup_interval = settings.MEMORY_CLEANUP_INTERVAL,
        )

    async def start_cleanup_task(self) -> None:
        """
        Start background cleanup task for expired entries
        """
        if self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def _cleanup_loop(self) -> None:
        """
        Background loop to clean up expired entries
        """
        while not self._closed:
            await asyncio.sleep(self.cleanup_interval)
            await self._cleanup_expired()

    async def _cleanup_expired(self) -> None:
        """
        Remove expired entries from storage
        """
        now = time.time()
        async with self._lock:
            expired_keys = [
                key for key, entry in self._windows.items()
                if entry.expires_at < now
            ]
            for key in expired_keys:
                del self._windows[key]

            expired_buckets = [
                key for key, state in self._buckets.items()
                if state.last_refill + 3600 < now
            ]
            for key in expired_buckets:
                del self._buckets[key]

    async def _enforce_max_keys(self) -> None:
        """
        Evict oldest entries when max_keys is exceeded
        """
        while len(self._windows) > self.max_keys:
            self._windows.popitem(last = False)

    async def get_window_state(
        self,
        key: str,
        window_seconds: int,
    ) -> WindowState:
        """
        Get current sliding window state
        """
        now = time.time()
        current_window = int(now // window_seconds)
        previous_window = current_window - 1

        current_key = f"{key}:{current_window}"
        previous_key = f"{key}:{previous_window}"

        async with self._lock:
            current_entry = self._windows.get(current_key)
            previous_entry = self._windows.get(previous_key)

            return WindowState(
                current_count = current_entry.count
                if current_entry else 0,
                previous_count = previous_entry.count
                if previous_entry else 0,
                current_window = current_window,
                window_seconds = window_seconds,
            )

    async def increment(
        self,
        key: str,
        window_seconds: int,
        limit: int,
        timestamp: float | None = None,
    ) -> RateLimitResult:
        """
        Atomically check and increment counter using sliding window algorithm
        """
        now = timestamp if timestamp is not None else time.time()
        current_window = int(now // window_seconds)
        previous_window = current_window - 1
        elapsed_ratio = (now % window_seconds) / window_seconds

        current_key = f"{key}:{current_window}"
        previous_key = f"{key}:{previous_window}"

        async with self._lock:
            current_entry = self._windows.get(current_key)
            previous_entry = self._windows.get(previous_key)

            current_count = current_entry.count if current_entry else 0
            previous_count = previous_entry.count if previous_entry else 0

            weighted_count = int(
                previous_count * (1 - elapsed_ratio) + current_count
            )

            if weighted_count >= limit:
                reset_after = window_seconds - (now % window_seconds)
                return RateLimitResult(
                    allowed = False,
                    limit = limit,
                    remaining = 0,
                    reset_after = reset_after,
                    retry_after = reset_after,
                )

            if current_entry:
                current_entry.count += 1
            else:
                self._windows[current_key] = WindowEntry(
                    count = 1,
                    window_start = current_window,
                    expires_at = now + (window_seconds * 2),
                )
                self._windows.move_to_end(current_key)
                await self._enforce_max_keys()

            new_weighted = int(
                previous_count * (1 - elapsed_ratio) + current_count + 1
            )
            remaining = max(0, limit - new_weighted)
            reset_after = window_seconds - (now % window_seconds)

            return RateLimitResult(
                allowed = True,
                limit = limit,
                remaining = remaining,
                reset_after = reset_after,
            )

    async def get_token_bucket_state(
        self,
        key: str,
    ) -> TokenBucketState | None:
        """
        Get token bucket state if it exists
        """
        async with self._lock:
            return self._buckets.get(key)

    async def consume_token(
        self,
        key: str,
        capacity: int,
        refill_rate: float,
        tokens_to_consume: int = 1,
    ) -> RateLimitResult:
        """
        Attempt to consume tokens from bucket
        """
        now = time.time()

        async with self._lock:
            state = self._buckets.get(key)

            if state is None:
                state = TokenBucketState(
                    tokens = float(capacity),
                    last_refill = now,
                    capacity = capacity,
                    refill_rate = refill_rate,
                )
                self._buckets[key] = state

            elapsed = now - state.last_refill
            tokens_to_add = elapsed * refill_rate
            state.tokens = min(
                float(capacity),
                state.tokens + tokens_to_add
            )
            state.last_refill = now

            if state.tokens >= tokens_to_consume:
                state.tokens -= tokens_to_consume
                time_to_full = (
                    capacity - state.tokens
                ) / refill_rate if refill_rate > 0 else 0

                return RateLimitResult(
                    allowed = True,
                    limit = capacity,
                    remaining = int(state.tokens),
                    reset_after = time_to_full,
                )

            tokens_needed = tokens_to_consume - state.tokens
            wait_time = tokens_needed / refill_rate if refill_rate > 0 else float(
                "inf"
            )

            return RateLimitResult(
                allowed = False,
                limit = capacity,
                remaining = 0,
                reset_after = wait_time,
                retry_after = wait_time,
            )

    async def close(self) -> None:
        """
        Close storage and cleanup resources
        """
        self._closed = True
        if self._cleanup_task:
            self._cleanup_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._cleanup_task
            self._cleanup_task = None

        async with self._lock:
            self._windows.clear()
            self._buckets.clear()

    async def health_check(self) -> bool:
        """
        Check if storage is healthy
        """
        return not self._closed

    @property
    def storage_type(self) -> StorageType:
        """
        Return storage type identifier
        """
        return StorageType.MEMORY
