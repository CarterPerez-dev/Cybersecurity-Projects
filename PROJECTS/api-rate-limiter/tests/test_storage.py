"""
ⒸAngelaMos | 2025
test_storage.py
"""
from __future__ import annotations

import asyncio
import time

import pytest

from fastapi_420.storage import MemoryStorage, create_storage
from fastapi_420.config import StorageSettings
from fastapi_420.types import StorageType

from tests.conftest import (
    WINDOW_MINUTE,
    WINDOW_SECOND,
    DEFAULT_LIMIT_REQUESTS,
)


class TestMemoryStorageBasic:
    """
    Basic MemoryStorage creation and lifecycle tests
    """
    @pytest.mark.asyncio
    async def test_create_storage(self) -> None:
        storage = MemoryStorage()
        assert storage.storage_type == StorageType.MEMORY
        assert storage.max_keys == 100_000

    @pytest.mark.asyncio
    async def test_create_storage_custom_settings(self) -> None:
        storage = MemoryStorage(max_keys = 5000, cleanup_interval = 30)
        assert storage.max_keys == 5000
        assert storage.cleanup_interval == 30

    @pytest.mark.asyncio
    async def test_from_settings(self) -> None:
        settings = StorageSettings(
            MEMORY_MAX_KEYS = 2000,
            MEMORY_CLEANUP_INTERVAL = 120,
        )
        storage = MemoryStorage.from_settings(settings)
        assert storage.max_keys == 2000
        assert storage.cleanup_interval == 120

    @pytest.mark.asyncio
    async def test_health_check_healthy(self) -> None:
        storage = MemoryStorage()
        assert await storage.health_check() is True

    @pytest.mark.asyncio
    async def test_health_check_after_close(self) -> None:
        storage = MemoryStorage()
        await storage.close()
        assert await storage.health_check() is False

    @pytest.mark.asyncio
    async def test_close_clears_data(self) -> None:
        storage = MemoryStorage()
        await storage.increment("test_key", WINDOW_MINUTE, 100)
        await storage.close()
        assert len(storage._windows) == 0
        assert len(storage._buckets) == 0


class TestMemoryStorageSlidingWindow:
    """
    Tests for sliding window counter in MemoryStorage
    """
    @pytest.mark.asyncio
    async def test_increment_first_request(self) -> None:
        storage = MemoryStorage()
        result = await storage.increment(
            key = "test",
            window_seconds = WINDOW_MINUTE,
            limit = 100,
        )
        assert result.allowed is True
        assert result.limit == 100
        assert result.remaining == 99
        await storage.close()

    @pytest.mark.asyncio
    async def test_increment_multiple_requests(self) -> None:
        storage = MemoryStorage()
        key = "multi_test"

        for i in range(10):
            result = await storage.increment(key, WINDOW_MINUTE, 100)
            assert result.allowed is True
            assert result.remaining == 100 - (i + 1)

        await storage.close()

    @pytest.mark.asyncio
    async def test_increment_reaches_limit(self) -> None:
        storage = MemoryStorage()
        key = "limit_test"
        limit = 5

        for _ in range(limit):
            result = await storage.increment(key, WINDOW_MINUTE, limit)
            assert result.allowed is True

        result = await storage.increment(key, WINDOW_MINUTE, limit)
        assert result.allowed is False
        assert result.remaining == 0
        assert result.retry_after is not None
        assert result.retry_after > 0

        await storage.close()

    @pytest.mark.asyncio
    async def test_increment_with_explicit_timestamp(self) -> None:
        storage = MemoryStorage()
        fixed_time = 1000000.0

        result = await storage.increment(
            key = "timestamp_test",
            window_seconds = WINDOW_MINUTE,
            limit = 100,
            timestamp = fixed_time,
        )
        assert result.allowed is True

        await storage.close()

    @pytest.mark.asyncio
    async def test_get_window_state_empty(self) -> None:
        storage = MemoryStorage()
        state = await storage.get_window_state(
            "nonexistent",
            WINDOW_MINUTE
        )
        assert state.current_count == 0
        assert state.previous_count == 0
        await storage.close()

    @pytest.mark.asyncio
    async def test_get_window_state_with_data(self) -> None:
        storage = MemoryStorage()
        key = "state_test"

        for _ in range(5):
            await storage.increment(key, WINDOW_MINUTE, 100)

        state = await storage.get_window_state(key, WINDOW_MINUTE)
        assert state.current_count == 5
        await storage.close()

    @pytest.mark.asyncio
    async def test_sliding_window_weighted_count(self) -> None:
        storage = MemoryStorage()
        key = "weighted_test"
        window = 2
        limit = 100

        base_time = 1000.0
        current_window = int(base_time // window)
        previous_window = current_window - 1

        prev_key = f"{key}:{previous_window}"
        curr_key = f"{key}:{current_window}"

        storage._windows[prev_key] = storage._windows.__class__().__class__
        from fastapi_420.storage.memory import WindowEntry
        storage._windows[prev_key] = WindowEntry(
            count = 50,
            window_start = previous_window,
            expires_at = base_time + window * 2,
        )

        result = await storage.increment(
            key = key,
            window_seconds = window,
            limit = limit,
            timestamp = base_time + 1.0,
        )

        assert result.allowed is True
        await storage.close()


class TestMemoryStorageTokenBucket:
    """
    Tests for token bucket algorithm in MemoryStorage
    """
    @pytest.mark.asyncio
    async def test_consume_token_first_request(self) -> None:
        storage = MemoryStorage()
        result = await storage.consume_token(
            key = "bucket_test",
            capacity = 100,
            refill_rate = 1.67,
            tokens_to_consume = 1,
        )
        assert result.allowed is True
        assert result.remaining == 99
        await storage.close()

    @pytest.mark.asyncio
    async def test_consume_token_multiple(self) -> None:
        storage = MemoryStorage()
        key = "multi_bucket"

        for i in range(10):
            result = await storage.consume_token(
                key = key,
                capacity = 100,
                refill_rate = 1.67,
            )
            assert result.allowed is True
            assert result.remaining == 100 - (i + 1)

        await storage.close()

    @pytest.mark.asyncio
    async def test_consume_token_exhausted(self) -> None:
        storage = MemoryStorage()
        key = "exhaust_bucket"
        capacity = 5

        for _ in range(capacity):
            result = await storage.consume_token(
                key = key,
                capacity = capacity,
                refill_rate = 1.0,
            )
            assert result.allowed is True

        result = await storage.consume_token(
            key = key,
            capacity = capacity,
            refill_rate = 1.0,
        )
        assert result.allowed is False
        assert result.retry_after is not None

        await storage.close()

    @pytest.mark.asyncio
    async def test_consume_token_refill(self) -> None:
        storage = MemoryStorage()
        key = "refill_test"
        capacity = 10
        refill_rate = 10.0

        for _ in range(capacity):
            await storage.consume_token(key, capacity, refill_rate)

        result = await storage.consume_token(key, capacity, refill_rate)
        assert result.allowed is False

        await asyncio.sleep(0.15)

        result = await storage.consume_token(key, capacity, refill_rate)
        assert result.allowed is True

        await storage.close()

    @pytest.mark.asyncio
    async def test_get_token_bucket_state_empty(self) -> None:
        storage = MemoryStorage()
        state = await storage.get_token_bucket_state("nonexistent")
        assert state is None
        await storage.close()

    @pytest.mark.asyncio
    async def test_get_token_bucket_state_exists(self) -> None:
        storage = MemoryStorage()
        key = "bucket_state_test"

        await storage.consume_token(
            key,
            capacity = 100,
            refill_rate = 1.67
        )

        state = await storage.get_token_bucket_state(key)
        assert state is not None
        assert state.tokens == 99.0
        assert state.capacity == 100

        await storage.close()


class TestMemoryStorageMaxKeys:
    """
    Tests for key eviction when max_keys is exceeded
    """
    @pytest.mark.asyncio
    async def test_max_keys_eviction(self) -> None:
        storage = MemoryStorage(max_keys = 5)

        for i in range(10):
            await storage.increment(f"key_{i}", WINDOW_MINUTE, 100)

        assert len(storage._windows) <= 6

        await storage.close()

    @pytest.mark.asyncio
    async def test_lru_eviction_order(self) -> None:
        storage = MemoryStorage(max_keys = 3)

        await storage.increment("key_a", WINDOW_MINUTE, 100)
        await storage.increment("key_b", WINDOW_MINUTE, 100)
        await storage.increment("key_c", WINDOW_MINUTE, 100)

        await storage.increment("key_d", WINDOW_MINUTE, 100)

        keys = list(storage._windows.keys())
        assert not any("key_a" in k for k in keys)

        await storage.close()


class TestMemoryStorageCleanup:
    """
    Tests for automatic cleanup of expired entries
    """
    @pytest.mark.asyncio
    async def test_cleanup_expired_entries(self) -> None:
        storage = MemoryStorage(cleanup_interval = 60)

        from fastapi_420.storage.memory import WindowEntry
        storage._windows["expired_key"] = WindowEntry(
            count = 10,
            window_start = 1,
            expires_at = time.time() - 100,
        )
        storage._windows["valid_key"] = WindowEntry(
            count = 10,
            window_start = 1,
            expires_at = time.time() + 100,
        )

        await storage._cleanup_expired()

        assert "expired_key" not in storage._windows
        assert "valid_key" in storage._windows

        await storage.close()

    @pytest.mark.asyncio
    async def test_cleanup_task_starts(self) -> None:
        storage = MemoryStorage(cleanup_interval = 1)
        await storage.start_cleanup_task()

        assert storage._cleanup_task is not None
        assert not storage._cleanup_task.done()

        await storage.close()

    @pytest.mark.asyncio
    async def test_cleanup_task_stops_on_close(self) -> None:
        storage = MemoryStorage(cleanup_interval = 1)
        await storage.start_cleanup_task()

        task = storage._cleanup_task
        await storage.close()

        assert storage._cleanup_task is None


class TestStorageFactory:
    """
    Tests for create_storage factory function
    """
    def test_create_memory_storage_no_redis(self) -> None:
        settings = StorageSettings(REDIS_URL = None)
        storage = create_storage(settings)
        assert isinstance(storage, MemoryStorage)

    def test_create_memory_storage_explicit(self) -> None:
        settings = StorageSettings(
            REDIS_URL = None,
            MEMORY_MAX_KEYS = 5000,
        )
        storage = create_storage(settings)
        assert isinstance(storage, MemoryStorage)
        assert storage.max_keys == 5000


class TestMemoryStorageConcurrency:
    """
    Tests for concurrent access to MemoryStorage
    """
    @pytest.mark.asyncio
    async def test_concurrent_increments(self) -> None:
        storage = MemoryStorage()
        key = "concurrent_test"
        limit = 1000

        async def increment() -> bool:
            result = await storage.increment(key, WINDOW_MINUTE, limit)
            return result.allowed

        tasks = [increment() for _ in range(100)]
        results = await asyncio.gather(*tasks)

        assert all(results)

        state = await storage.get_window_state(key, WINDOW_MINUTE)
        assert state.current_count == 100

        await storage.close()

    @pytest.mark.asyncio
    async def test_concurrent_different_keys(self) -> None:
        storage = MemoryStorage()
        limit = 100

        async def increment(key: str) -> int:
            for _ in range(10):
                await storage.increment(key, WINDOW_MINUTE, limit)
            state = await storage.get_window_state(key, WINDOW_MINUTE)
            return state.current_count

        tasks = [increment(f"key_{i}") for i in range(10)]
        results = await asyncio.gather(*tasks)

        assert all(r == 10 for r in results)

        await storage.close()
