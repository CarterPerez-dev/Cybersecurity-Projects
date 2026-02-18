"""
©AngelaMos | 2026
pipeline.py
"""

import asyncio
import logging
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import redis.asyncio as aioredis

from app.core.detection.rules import RuleEngine, RuleResult
from app.core.enrichment.geoip import GeoIPService, GeoResult
from app.core.features.aggregator import WindowAggregator
from app.core.features.encoder import encode_for_inference
from app.core.features.extractor import extract_request_features
from app.core.ingestion.parsers import ParsedLogEntry, parse_combined

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class EnrichedRequest:
    """
    A parsed log entry enriched with extracted features and GeoIP data.
    """

    entry: ParsedLogEntry
    features: dict[str, int | float | bool | str]
    feature_vector: list[float]
    geo: GeoResult | None


@dataclass(slots=True)
class ScoredRequest:
    """
    A fully scored request ready for dispatch.
    """

    entry: ParsedLogEntry
    features: dict[str, int | float | bool | str]
    feature_vector: list[float]
    geo: GeoResult | None
    rule_result: RuleResult


class Pipeline:
    """
    Four-stage async pipeline that transforms raw log lines
    into scored threat candidates.

    Stages:
        raw_queue → [parse] → parsed_queue → [enrich+features]
        → feature_queue → [detect] → alert_queue → [dispatch]
    """

    def __init__(
        self,
        redis_client: aioredis.Redis[bytes],
        rule_engine: RuleEngine,
        geoip: GeoIPService | None = None,
        on_result: Callable[[ScoredRequest], Awaitable[None]] | None = None,
        raw_queue_size: int = 1000,
        parsed_queue_size: int = 500,
        feature_queue_size: int = 200,
        alert_queue_size: int = 100,
    ) -> None:
        self.raw_queue: asyncio.Queue[str | None] = asyncio.Queue(
            maxsize=raw_queue_size,
        )
        self._parsed_queue: asyncio.Queue[ParsedLogEntry | None] = asyncio.Queue(
            maxsize=parsed_queue_size,
        )
        self._feature_queue: asyncio.Queue[EnrichedRequest | None] = asyncio.Queue(
            maxsize=feature_queue_size,
        )
        self._alert_queue: asyncio.Queue[ScoredRequest | None] = asyncio.Queue(
            maxsize=alert_queue_size,
        )

        self._aggregator = WindowAggregator(redis_client)
        self._rule_engine = rule_engine
        self._geoip = geoip
        self._on_result = on_result
        self._tasks: list[asyncio.Task[None]] = []

    async def start(self) -> None:
        """
        Spawn worker tasks for each pipeline stage.
        """
        self._tasks = [
            asyncio.create_task(self._parse_worker(), name="parse"),
            asyncio.create_task(self._feature_worker(), name="feature"),
            asyncio.create_task(self._detection_worker(), name="detection"),
            asyncio.create_task(self._dispatch_worker(), name="dispatch"),
        ]
        logger.info("Pipeline started — 4 stage workers running")

    async def stop(self) -> None:
        """
        Send a poison pill through the chain and wait for all workers to exit.
        """
        await self.raw_queue.put(None)
        await asyncio.gather(*self._tasks)
        logger.info("Pipeline stopped — all workers exited")

    async def _parse_worker(self) -> None:
        """
        Stage 1: Parse raw log lines into structured entries.
        """
        while True:
            line = await self.raw_queue.get()
            if line is None:
                self.raw_queue.task_done()
                await self._parsed_queue.put(None)
                break
            try:
                entry = parse_combined(line)
                if entry is not None:
                    await self._parsed_queue.put(entry)
            except Exception:
                logger.exception("Parse error")
            self.raw_queue.task_done()

    async def _feature_worker(self) -> None:
        """
        Stage 2: Enrich with GeoIP, extract per-request features,
        aggregate per-IP windowed features, and encode the 35-dim vector.
        """
        while True:
            entry = await self._parsed_queue.get()
            if entry is None:
                self._parsed_queue.task_done()
                await self._feature_queue.put(None)
                break
            try:
                country_code = ""
                geo = None
                if self._geoip is not None:
                    geo = await self._geoip.lookup(entry.ip)
                    if geo and geo.country:
                        country_code = geo.country

                per_request = extract_request_features(entry, country_code)

                windowed = await self._aggregator.record_and_aggregate(
                    ip=entry.ip,
                    request_id=uuid.uuid4().hex,
                    path=entry.path,
                    path_depth=int(per_request["path_depth"]),
                    method=entry.method,
                    status_code=entry.status_code,
                    user_agent=entry.user_agent,
                    response_size=entry.response_size,
                    timestamp=entry.timestamp.timestamp(),
                )

                merged = {**per_request, **windowed}
                vector = encode_for_inference(merged)

                await self._feature_queue.put(
                    EnrichedRequest(
                        entry=entry,
                        features=merged,
                        feature_vector=vector,
                        geo=geo,
                    )
                )
            except Exception:
                logger.exception("Feature extraction failed for %s", entry.ip)
            self._parsed_queue.task_done()

    async def _detection_worker(self) -> None:
        """
        Stage 3: Score enriched requests using the rule engine.
        """
        while True:
            enriched = await self._feature_queue.get()
            if enriched is None:
                self._feature_queue.task_done()
                await self._alert_queue.put(None)
                break
            try:
                rule_result = self._rule_engine.score_request(
                    enriched.features,
                    enriched.entry,
                )
                await self._alert_queue.put(
                    ScoredRequest(
                        entry=enriched.entry,
                        features=enriched.features,
                        feature_vector=enriched.feature_vector,
                        geo=enriched.geo,
                        rule_result=rule_result,
                    )
                )
            except Exception:
                logger.exception("Detection failed")
            self._feature_queue.task_done()

    async def _dispatch_worker(self) -> None:
        """
        Stage 4: Dispatch scored results via the on_result callback.
        """
        while True:
            scored = await self._alert_queue.get()
            if scored is None:
                self._alert_queue.task_done()
                break
            try:
                if self._on_result is not None:
                    await self._on_result(scored)
            except Exception:
                logger.exception("Dispatch failed for %s", scored.entry.ip)
            self._alert_queue.task_done()
