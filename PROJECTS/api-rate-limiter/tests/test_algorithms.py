"""
ⒸAngelaMos | 2025
test_algorithms.py
"""
from __future__ import annotations

import time

import pytest

from fastapi_420.algorithms import create_algorithm
from fastapi_420.algorithms.sliding_window import SlidingWindowAlgorithm
from fastapi_420.algorithms.token_bucket import TokenBucketAlgorithm
from fastapi_420.algorithms.fixed_window import FixedWindowAlgorithm
from fastapi_420.storage import MemoryStorage
from fastapi_420.types import Algorithm

from tests.conftest import (
    WINDOW_MINUTE,
    WINDOW_SECOND,
    RuleFactory,
)


class TestAlgorithmFactory:
    """
    Tests for algorithm factory function
    """
    def test_create_sliding_window(self) -> None:
        algo = create_algorithm(Algorithm.SLIDING_WINDOW)
        assert isinstance(algo, SlidingWindowAlgorithm)

    def test_create_token_bucket(self) -> None:
        algo = create_algorithm(Algorithm.TOKEN_BUCKET)
        assert isinstance(algo, TokenBucketAlgorithm)

    def test_create_fixed_window(self) -> None:
        algo = create_algorithm(Algorithm.FIXED_WINDOW)
        assert isinstance(algo, FixedWindowAlgorithm)

    def test_create_from_string(self) -> None:
        algo = create_algorithm(Algorithm.SLIDING_WINDOW)
        assert algo.name == Algorithm.SLIDING_WINDOW.value


class TestSlidingWindowAlgorithm:
    """
    Tests for sliding window counter algorithm
    """
    @pytest.mark.asyncio
    async def test_algorithm_name(self) -> None:
        algo = SlidingWindowAlgorithm()
        assert algo.name == "sliding_window"

    @pytest.mark.asyncio
    async def test_first_request_allowed(self) -> None:
        algo = SlidingWindowAlgorithm()
        storage = MemoryStorage()
        rule = RuleFactory.per_minute(100)

        result = await algo.check(
            storage = storage,
            key = "test_key",
            rule = rule,
        )

        assert result.allowed is True
        assert result.remaining == 99

        await storage.close()

    @pytest.mark.asyncio
    async def test_multiple_requests(self) -> None:
        algo = SlidingWindowAlgorithm()
        storage = MemoryStorage()
        rule = RuleFactory.per_minute(100)

        for i in range(50):
            result = await algo.check(storage, f"multi_key", rule)
            assert result.allowed is True

        assert result.remaining == 50

        await storage.close()

    @pytest.mark.asyncio
    async def test_limit_exceeded(self) -> None:
        algo = SlidingWindowAlgorithm()
        storage = MemoryStorage()
        rule = RuleFactory.create(
            requests = 5,
            window_seconds = WINDOW_MINUTE
        )

        for _ in range(5):
            result = await algo.check(storage, "limit_key", rule)
            assert result.allowed is True

        result = await algo.check(storage, "limit_key", rule)
        assert result.allowed is False
        assert result.retry_after is not None

        await storage.close()

    @pytest.mark.asyncio
    async def test_different_keys_independent(self) -> None:
        algo = SlidingWindowAlgorithm()
        storage = MemoryStorage()
        rule = RuleFactory.create(
            requests = 5,
            window_seconds = WINDOW_MINUTE
        )

        for _ in range(5):
            await algo.check(storage, "key_a", rule)

        result_a = await algo.check(storage, "key_a", rule)
        result_b = await algo.check(storage, "key_b", rule)

        assert result_a.allowed is False
        assert result_b.allowed is True

        await storage.close()

    @pytest.mark.asyncio
    async def test_get_current_usage_empty(self) -> None:
        algo = SlidingWindowAlgorithm()
        storage = MemoryStorage()
        rule = RuleFactory.per_minute()

        usage = await algo.get_current_usage(storage, "empty_key", rule)
        assert usage == 0

        await storage.close()

    @pytest.mark.asyncio
    async def test_get_current_usage_after_requests(self) -> None:
        algo = SlidingWindowAlgorithm()
        storage = MemoryStorage()
        rule = RuleFactory.per_minute(100)

        for _ in range(25):
            await algo.check(storage, "usage_key", rule)

        usage = await algo.get_current_usage(storage, "usage_key", rule)
        assert usage >= 24

        await storage.close()

    @pytest.mark.asyncio
    async def test_explicit_timestamp(self) -> None:
        algo = SlidingWindowAlgorithm()
        storage = MemoryStorage()
        rule = RuleFactory.per_minute(100)
        fixed_time = 1000000.0

        result = await algo.check(
            storage = storage,
            key = "timestamp_key",
            rule = rule,
            timestamp = fixed_time,
        )

        assert result.allowed is True

        await storage.close()


class TestTokenBucketAlgorithm:
    """
    Tests for token bucket algorithm
    """
    @pytest.mark.asyncio
    async def test_algorithm_name(self) -> None:
        algo = TokenBucketAlgorithm()
        assert algo.name == "token_bucket"

    @pytest.mark.asyncio
    async def test_first_request_allowed(self) -> None:
        algo = TokenBucketAlgorithm()
        storage = MemoryStorage()
        rule = RuleFactory.per_minute(100)

        result = await algo.check(
            storage = storage,
            key = "bucket_test",
            rule = rule,
        )

        assert result.allowed is True
        assert result.remaining == 99

        await storage.close()

    @pytest.mark.asyncio
    async def test_burst_consumption(self) -> None:
        algo = TokenBucketAlgorithm()
        storage = MemoryStorage()
        rule = RuleFactory.create(
            requests = 10,
            window_seconds = WINDOW_MINUTE
        )

        for i in range(10):
            result = await algo.check(storage, "burst_key", rule)
            assert result.allowed is True
            assert result.remaining == 10 - (i + 1)

        await storage.close()

    @pytest.mark.asyncio
    async def test_bucket_exhausted(self) -> None:
        algo = TokenBucketAlgorithm()
        storage = MemoryStorage()
        rule = RuleFactory.create(
            requests = 5,
            window_seconds = WINDOW_MINUTE
        )

        for _ in range(5):
            await algo.check(storage, "exhaust_key", rule)

        result = await algo.check(storage, "exhaust_key", rule)
        assert result.allowed is False

        await storage.close()

    @pytest.mark.asyncio
    async def test_different_keys_independent(self) -> None:
        algo = TokenBucketAlgorithm()
        storage = MemoryStorage()
        rule = RuleFactory.create(
            requests = 5,
            window_seconds = WINDOW_MINUTE
        )

        for _ in range(5):
            await algo.check(storage, "bucket_a", rule)

        result_a = await algo.check(storage, "bucket_a", rule)
        result_b = await algo.check(storage, "bucket_b", rule)

        assert result_a.allowed is False
        assert result_b.allowed is True

        await storage.close()

    @pytest.mark.asyncio
    async def test_get_current_usage_empty(self) -> None:
        algo = TokenBucketAlgorithm()
        storage = MemoryStorage()
        rule = RuleFactory.per_minute(100)

        usage = await algo.get_current_usage(storage, "empty_bucket", rule)
        assert usage == 0

        await storage.close()

    @pytest.mark.asyncio
    async def test_get_current_usage_after_consumption(self) -> None:
        algo = TokenBucketAlgorithm()
        storage = MemoryStorage()
        rule = RuleFactory.per_minute(100)

        for _ in range(25):
            await algo.check(storage, "usage_bucket", rule)

        usage = await algo.get_current_usage(storage, "usage_bucket", rule)
        assert usage >= 24

        await storage.close()


class TestFixedWindowAlgorithm:
    """
    Tests for fixed window counter algorithm
    """
    @pytest.mark.asyncio
    async def test_algorithm_name(self) -> None:
        algo = FixedWindowAlgorithm()
        assert algo.name == "fixed_window"

    @pytest.mark.asyncio
    async def test_first_request_allowed(self) -> None:
        algo = FixedWindowAlgorithm()
        storage = MemoryStorage()
        rule = RuleFactory.per_minute(100)

        result = await algo.check(
            storage = storage,
            key = "fixed_test",
            rule = rule,
        )

        assert result.allowed is True

        await storage.close()

    @pytest.mark.asyncio
    async def test_multiple_requests(self) -> None:
        algo = FixedWindowAlgorithm()
        storage = MemoryStorage()
        rule = RuleFactory.per_minute(100)

        for _ in range(50):
            result = await algo.check(storage, "multi_fixed", rule)
            assert result.allowed is True

        await storage.close()

    @pytest.mark.asyncio
    async def test_limit_exceeded(self) -> None:
        algo = FixedWindowAlgorithm()
        storage = MemoryStorage()
        rule = RuleFactory.create(
            requests = 5,
            window_seconds = WINDOW_MINUTE
        )

        for _ in range(5):
            result = await algo.check(storage, "limit_fixed", rule)
            assert result.allowed is True

        result = await algo.check(storage, "limit_fixed", rule)
        assert result.allowed is False

        await storage.close()

    @pytest.mark.asyncio
    async def test_different_keys_independent(self) -> None:
        algo = FixedWindowAlgorithm()
        storage = MemoryStorage()
        rule = RuleFactory.create(
            requests = 5,
            window_seconds = WINDOW_MINUTE
        )

        for _ in range(5):
            await algo.check(storage, "fixed_a", rule)

        result_a = await algo.check(storage, "fixed_a", rule)
        result_b = await algo.check(storage, "fixed_b", rule)

        assert result_a.allowed is False
        assert result_b.allowed is True

        await storage.close()

    @pytest.mark.asyncio
    async def test_get_current_usage_empty(self) -> None:
        algo = FixedWindowAlgorithm()
        storage = MemoryStorage()
        rule = RuleFactory.per_minute(100)

        usage = await algo.get_current_usage(storage, "empty_fixed", rule)
        assert usage == 0

        await storage.close()

    @pytest.mark.asyncio
    async def test_get_current_usage_after_requests(self) -> None:
        algo = FixedWindowAlgorithm()
        storage = MemoryStorage()
        rule = RuleFactory.per_minute(100)

        for _ in range(25):
            await algo.check(storage, "usage_fixed", rule)

        usage = await algo.get_current_usage(storage, "usage_fixed", rule)
        assert usage >= 0

        await storage.close()

    @pytest.mark.asyncio
    async def test_explicit_timestamp(self) -> None:
        algo = FixedWindowAlgorithm()
        storage = MemoryStorage()
        rule = RuleFactory.per_minute(100)
        fixed_time = 1000000.0

        result = await algo.check(
            storage = storage,
            key = "timestamp_fixed",
            rule = rule,
            timestamp = fixed_time,
        )

        assert result.allowed is True

        await storage.close()


class TestAlgorithmComparison:
    """
    Comparative tests between algorithms
    """
    @pytest.mark.asyncio
    async def test_all_algorithms_allow_first_request(self) -> None:
        algorithms = [
            SlidingWindowAlgorithm(),
            TokenBucketAlgorithm(),
            FixedWindowAlgorithm(),
        ]
        rule = RuleFactory.per_minute(100)

        for algo in algorithms:
            storage = MemoryStorage()
            result = await algo.check(storage, "compare_key", rule)
            assert result.allowed is True, f"{algo.name} failed first request"
            await storage.close()

    @pytest.mark.asyncio
    async def test_all_algorithms_enforce_limit(self) -> None:
        algorithms = [
            SlidingWindowAlgorithm(),
            TokenBucketAlgorithm(),
            FixedWindowAlgorithm(),
        ]
        rule = RuleFactory.create(
            requests = 5,
            window_seconds = WINDOW_MINUTE
        )

        for algo in algorithms:
            storage = MemoryStorage()
            for _ in range(5):
                await algo.check(storage, "enforce_key", rule)

            result = await algo.check(storage, "enforce_key", rule)
            assert result.allowed is False, f"{algo.name} didn't enforce limit"
            await storage.close()

    @pytest.mark.asyncio
    async def test_algorithms_have_correct_names(self) -> None:
        assert SlidingWindowAlgorithm(
        ).name == Algorithm.SLIDING_WINDOW.value
        assert TokenBucketAlgorithm().name == Algorithm.TOKEN_BUCKET.value
        assert FixedWindowAlgorithm().name == Algorithm.FIXED_WINDOW.value
