"""
©AngelaMos | 2026
test_pipeline.py
"""

import fakeredis.aioredis
import pytest

from app.core.detection.rules import RuleEngine
from app.core.ingestion.pipeline import Pipeline, ScoredRequest

VALID_LINE = (
    "93.184.216.34 - - [11/Feb/2026:14:30:00 +0000] "
    '"GET /api/v1/users HTTP/1.1" 200 1234 '
    '"https://example.com" '
    '"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
)

SQLI_LINE = (
    "93.184.216.34 - - [11/Feb/2026:14:30:01 +0000] "
    '"GET /users?id=1%27OR%201=1-- HTTP/1.1" 200 512 '
    '"-" "Mozilla/5.0"'
)


async def _make_pipeline(
    results: list[ScoredRequest],
    raw_queue_size: int = 100,
    parsed_queue_size: int = 100,
    feature_queue_size: int = 100,
    alert_queue_size: int = 100,
) -> Pipeline:
    """
    Build a Pipeline wired to an in-memory Redis and a results collector.
    """
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)

    async def collect(sr: ScoredRequest) -> None:
        results.append(sr)

    pipeline = Pipeline(
        redis_client=redis,
        rule_engine=RuleEngine(),
        on_result=collect,
        raw_queue_size=raw_queue_size,
        parsed_queue_size=parsed_queue_size,
        feature_queue_size=feature_queue_size,
        alert_queue_size=alert_queue_size,
    )
    await pipeline.start()
    return pipeline


@pytest.mark.asyncio
async def test_end_to_end_valid_line() -> None:
    """
    A valid log line flows through all 4 stages and produces a scored result.
    """
    results: list[ScoredRequest] = []
    pipeline = await _make_pipeline(results)

    await pipeline.raw_queue.put(VALID_LINE)
    await pipeline.stop()

    assert len(results) == 1
    assert results[0].entry.ip == "93.184.216.34"
    assert results[0].entry.method == "GET"
    assert len(results[0].feature_vector) == 35
    assert results[0].rule_result.severity == "LOW"


@pytest.mark.asyncio
async def test_malformed_line_dropped() -> None:
    """
    Malformed lines are dropped at the parse stage without crashing.
    """
    results: list[ScoredRequest] = []
    pipeline = await _make_pipeline(results)

    await pipeline.raw_queue.put("this is not a valid log line")
    await pipeline.raw_queue.put(VALID_LINE)
    await pipeline.stop()

    assert len(results) == 1


@pytest.mark.asyncio
async def test_backpressure_with_tiny_queues() -> None:
    """
    Items flow through correctly even when all queues have maxsize=1.
    """
    results: list[ScoredRequest] = []
    pipeline = await _make_pipeline(
        results,
        raw_queue_size=1,
        parsed_queue_size=1,
        feature_queue_size=1,
        alert_queue_size=1,
    )

    for _ in range(5):
        await pipeline.raw_queue.put(VALID_LINE)

    await pipeline.stop()
    assert len(results) == 5


@pytest.mark.asyncio
async def test_shutdown_drains_and_exits() -> None:
    """
    Calling stop() drains remaining items and all tasks exit cleanly.
    """
    results: list[ScoredRequest] = []
    pipeline = await _make_pipeline(results)

    await pipeline.raw_queue.put(VALID_LINE)
    await pipeline.raw_queue.put(VALID_LINE)
    await pipeline.stop()

    assert len(results) == 2
    assert all(t.done() for t in pipeline._tasks)


@pytest.mark.asyncio
async def test_attack_line_scored_high() -> None:
    """
    A SQLi payload in the log line is scored as HIGH by the rule engine.
    """
    results: list[ScoredRequest] = []
    pipeline = await _make_pipeline(results)

    await pipeline.raw_queue.put(SQLI_LINE)
    await pipeline.stop()

    assert len(results) == 1
    assert results[0].rule_result.severity == "HIGH"
    assert "SQL_INJECTION" in results[0].rule_result.matched_rules
