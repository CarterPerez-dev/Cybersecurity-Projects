"""
ⒸAngelaMos | 2025
circuit_breaker.py
"""

from __future__ import annotations

import time
import asyncio
import logging
from dataclasses import (
    field,
    dataclass,
)
from typing import TYPE_CHECKING

from fastapi_420.types import CircuitState, DefenseMode

if TYPE_CHECKING:
    from fastapi_420.storage import Storage


logger = logging.getLogger("fastapi_420")


@dataclass
class CircuitBreaker:
    """
    Global circuit breaker for API-wide protection

    When request volume exceeds threshold, the circuit opens
    and applies configured defense strategy.
    """
    threshold: int = 10000
    window_seconds: int = 60
    recovery_time: int = 30
    defense_mode: DefenseMode = DefenseMode.ADAPTIVE

    _state: CircuitState = field(default_factory = CircuitState)
    _lock: asyncio.Lock = field(default_factory = asyncio.Lock)
    _counter_key: str = "circuit:global:requests"

    async def check(self, storage: Storage) -> bool:
        """
        Check if circuit is allowing requests

        Returns True if requests should be allowed
        """
        async with self._lock:
            now = time.time()

            if self._state.is_open:
                if now - self._state.last_failure_time >= self.recovery_time:
                    await self._enter_half_open()
                    return True
                return False

            request_count = await self._get_request_count(storage)
            self._state.total_requests_in_window = request_count

            if request_count >= self.threshold:
                await self._trip(now)
                return False

            return True

    async def record_request(self, storage: Storage) -> None:
        """
        Record a request in the circuit breaker counter
        """
        now = time.time()
        window = int(now // self.window_seconds)
        key = f"{self._counter_key}:{window}"

        await storage.increment(
            key = key,
            window_seconds = self.window_seconds,
            limit = self.threshold * 10,
            timestamp = now,
        )

    async def _get_request_count(self, storage: Storage) -> int:
        """
        Get current request count in window
        """
        now = time.time()
        window = int(now // self.window_seconds)
        key = f"{self._counter_key}:{window}"

        state = await storage.get_window_state(
            key = key,
            window_seconds = self.window_seconds,
        )

        return state.current_count

    async def _trip(self, now: float) -> None:
        """
        Trip the circuit breaker
        """
        self._state.is_open = True
        self._state.last_failure_time = now
        self._state.failure_count += 1
        self._state.half_open_requests = 0

        logger.warning(
            "Circuit breaker tripped",
            extra = {
                "threshold": self.threshold,
                "total_requests": self._state.total_requests_in_window,
                "defense_mode": self.defense_mode.value,
            },
        )

    async def _enter_half_open(self) -> None:
        """
        Enter half-open state for recovery testing
        """
        self._state.half_open_requests = 0
        logger.info("Circuit breaker entering half-open state")

    async def reset(self) -> None:
        """
        Reset circuit breaker to closed state
        """
        async with self._lock:
            self._state = CircuitState()
            logger.info("Circuit breaker reset to closed state")

    @property
    def is_open(self) -> bool:
        """
        Check if circuit is open
        """
        return self._state.is_open

    @property
    def current_state(self) -> CircuitState:
        """
        Get current circuit state
        """
        return self._state
