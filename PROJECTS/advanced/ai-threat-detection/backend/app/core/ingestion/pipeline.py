"""
©AngelaMos | 2026
pipeline.py

Four-stage async pipeline transforming raw nginx log lines
into scored threat candidates

Stage 1 (_parse_worker): parses raw lines via parse_
combined into ParsedLogEntry. Stage 2 (_feature_worker):
enriches with GeoIP lookup, extracts 23 per-request
features, aggregates 12 windowed features via Redis-backed
WindowAggregator, and encodes the merged 35-dim float
vector. Stage 3 (_detection_worker): scores via RuleEngine,
optionally runs ML ensemble inference (normalize AE/IF
scores, fuse with configurable weights, blend with rule
score at 0.7 ML weight). Stage 4 (_dispatch_worker):
forwards ScoredRequests via the on_result callback. Stages
are connected by sized asyncio.Queues with poison-pill
shutdown propagation. EnrichedRequest and ScoredRequest
dataclasses carry data between stages

Connects to:
  core/ingestion/parsers    - parse_combined
  core/enrichment/geoip     - GeoIPService.lookup
  core/features/extractor   - extract_request_features
  core/features/aggregator  - WindowAggregator
  core/features/encoder     - encode_for_inference
  core/detection/rules      - RuleEngine.score_request
  core/detection/inference  - InferenceEngine.predict
  core/detection/ensemble   - normalize/fuse/blend scores
  core/alerts/dispatcher    - on_result callback
"""

import asyncio
import logging
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

import redis.asyncio as aioredis

from app.core.detection.ensemble import (
    blend_scores,
    fuse_scores,
    normalize_ae_score,
    normalize_if_score,
)
from app.core.detection.rules import RuleEngine, RuleResult
from app.core.enrichment.geoip import GeoIPService, GeoResult
from app.core.features.aggregator import WindowAggregator
from app.core.features.encoder import encode_for_inference
from app.core.features.extractor import extract_request_features
from app.core.ingestion.parsers import ParsedLogEntry, parse_combined

try:
    import numpy as np
except ImportError:
    np = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from app.core.detection.inference import InferenceEngine

logger = logging.getLogger(__name__)

DEFAULT_ENSEMBLE_WEIGHTS: dict[str, float] = {
    "ae": 0.40,
    "rf": 0.40,
    "if": 0.20,
}


@dataclass(slots=True)
class EnrichedRequest:
    """
    A parsed log entry enriched with extracted features and GeoIP data
    """

    entry: ParsedLogEntry
    features: dict[str, int | float | bool | str]
    feature_vector: list[float]
    geo: GeoResult | None


@dataclass(slots=True)
class ScoredRequest:
    """
    A fully scored request ready for dispatch
    """

    entry: ParsedLogEntry
    features: dict[str, int | float | bool | str]
    feature_vector: list[float]
    geo: GeoResult | None
    rule_result: RuleResult
    final_score: float = 0.0
    detection_mode: str = "rules"


class Pipeline:
    """
    Four-stage async pipeline that transforms raw log lines
    into scored threat candidates

    Stages:
        raw_queue -> [parse] -> parsed_queue -> [enrich+features]
        -> feature_queue -> [detect] -> alert_queue -> [dispatch]
    """

    def __init__(
        self,
        redis_client: aioredis.Redis[str],
        rule_engine: RuleEngine,
        geoip: GeoIPService | None = None,
        on_result: (Callable[[ScoredRequest], Awaitable[None]] | None) = None,
        inference_engine: InferenceEngine | None = None,
        ensemble_weights: dict[str, float] | None = None,
        raw_queue_size: int = 1000,
        parsed_queue_size: int = 500,
        feature_queue_size: int = 200,
        alert_queue_size: int = 100,
    ) -> None:
        self.raw_queue: asyncio.Queue[str | None] = asyncio.Queue(
            maxsize=raw_queue_size)
        self._parsed_queue: asyncio.Queue[ParsedLogEntry
                                          | None] = asyncio.Queue(
                                              maxsize=parsed_queue_size)
        self._feature_queue: asyncio.Queue[EnrichedRequest
                                           | None] = asyncio.Queue(
                                               maxsize=feature_queue_size)
        self._alert_queue: asyncio.Queue[ScoredRequest | None] = asyncio.Queue(
            maxsize=alert_queue_size)

        self._aggregator = WindowAggregator(redis_client)
        self._rule_engine = rule_engine
        self._geoip = geoip
        self._on_result = on_result
        self._inference_engine = inference_engine
        self._ensemble_weights = ensemble_weights or DEFAULT_ENSEMBLE_WEIGHTS
        self._tasks: list[asyncio.Task[None]] = []

    async def start(self) -> None:
        """
        Spawn worker tasks for each pipeline stage
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
        Send a poison pill through the chain and wait
        for all workers to exit
        """
        await self.raw_queue.put(None)
        await asyncio.gather(*self._tasks)
        logger.info("Pipeline stopped — all workers exited")

    async def _parse_worker(self) -> None:
        """
        Stage 1: Parse raw log lines into structured entries
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
        Stage 2: Enrich with GeoIP, extract per-request
        features, aggregate per-IP windowed features,
        and encode the 35-dim vector
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
                    ))
            except Exception:
                logger.exception(
                    "Feature extraction failed for %s",
                    entry.ip,
                )
            self._parsed_queue.task_done()

    async def _detection_worker(self) -> None:
        """
        Stage 3: Score enriched requests using the rule
        engine, optionally enhanced with ML ensemble
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

                final_score = rule_result.threat_score
                detection_mode = "rules"

                if (self._inference_engine is not None
                        and self._inference_engine.is_loaded
                        and np is not None):
                    ml_scores = self._score_with_ml(enriched.feature_vector)
                    if ml_scores is not None:
                        ml_fused = fuse_scores(
                            ml_scores,
                            self._ensemble_weights,
                        )
                        final_score = blend_scores(
                            ml_fused,
                            rule_result.threat_score,
                        )
                        detection_mode = "hybrid"

                await self._alert_queue.put(
                    ScoredRequest(
                        entry=enriched.entry,
                        features=enriched.features,
                        feature_vector=enriched.feature_vector,
                        geo=enriched.geo,
                        rule_result=rule_result,
                        final_score=final_score,
                        detection_mode=detection_mode,
                    ))
            except Exception:
                logger.exception("Detection failed")
            self._feature_queue.task_done()

    def _score_with_ml(self,
                       feature_vector: list[float]) -> dict[str, float] | None:
        """
        Run ML ensemble inference on a single feature vector
        and return normalized per-model scores
        """
        batch = np.array([feature_vector], dtype=np.float32)
        raw = self._inference_engine.predict(batch)  # type: ignore[union-attr]
        if raw is None:
            return None

        return {
            "ae":
            normalize_ae_score(
                raw["ae"][0],
                self._inference_engine.threshold,  # type: ignore[union-attr]
            ),
            "rf":
            raw["rf"][0],
            "if":
            normalize_if_score(raw["if"][0]),
        }

    async def _dispatch_worker(self) -> None:
        """
        Stage 4: Dispatch scored results via the
        on_result callback
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
                logger.exception(
                    "Dispatch failed for %s",
                    scored.entry.ip,
                )
            self._alert_queue.task_done()
