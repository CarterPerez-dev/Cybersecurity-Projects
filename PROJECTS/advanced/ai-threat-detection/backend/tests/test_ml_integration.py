"""
©AngelaMos | 2026
test_ml_integration.py

Tests the ML inference engine wired into the ingestion
pipeline in hybrid detection mode

Uses a trained_model_dir fixture with ONNX models to build
a pipeline with InferenceEngine. Validates hybrid detection
mode is set when ML models are present, final_score is in
[0, 1], rules-only mode falls back to rule score as final
score, attack lines score higher than benign in hybrid
mode, and rule_result is preserved alongside ML scores

Connects to:
  core/detection/inference - InferenceEngine
  core/detection/rules     - RuleEngine
  core/ingestion/pipeline  - Pipeline, ScoredRequest
  ml/export_onnx           - model export for fixture
"""

import json
from pathlib import Path

import fakeredis.aioredis
import numpy as np
import pytest
from sklearn.ensemble import (
    IsolationForest,
    RandomForestClassifier,
)

from app.core.detection.inference import InferenceEngine
from app.core.detection.rules import RuleEngine
from app.core.ingestion.pipeline import (
    Pipeline,
    ScoredRequest,
)
from ml.autoencoder import ThreatAutoencoder
from ml.export_onnx import (
    export_autoencoder,
    export_isolation_forest,
    export_random_forest,
)
from ml.scaler import FeatureScaler

VALID_LINE = ("93.184.216.34 - - [11/Feb/2026:14:30:00 +0000] "
              '"GET /api/v1/users HTTP/1.1" 200 1234 '
              '"https://example.com" '
              '"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"')

SQLI_LINE = ("93.184.216.34 - - [11/Feb/2026:14:30:01 +0000] "
             '"GET /users?id=1%27OR%201=1-- HTTP/1.1" 200 512 '
             '"-" "Mozilla/5.0"')


@pytest.fixture
def trained_model_dir(tmp_path: Path) -> Path:
    """
    Create a temp directory with trained ONNX models,
    scaler, and threshold
    """
    rng = np.random.default_rng(42)
    X = rng.standard_normal((200, 35)).astype(np.float32)
    y = np.concatenate([np.zeros(140, dtype=int), np.ones(60, dtype=int)])

    ae = ThreatAutoencoder(input_dim=35)
    export_autoencoder(ae, tmp_path / "ae.onnx")

    rf = RandomForestClassifier(n_estimators=10, random_state=42)
    rf.fit(X, y)
    export_random_forest(rf, 35, tmp_path / "rf.onnx")

    iso = IsolationForest(n_estimators=10, random_state=42)
    iso.fit(X[:140])
    export_isolation_forest(iso, 35, tmp_path / "if.onnx")

    scaler = FeatureScaler()
    scaler.fit(X[:140])
    scaler.save_json(tmp_path / "scaler.json")

    threshold_data = {"threshold": 0.05}
    (tmp_path / "threshold.json").write_text(json.dumps(threshold_data))

    return tmp_path


async def _make_pipeline_with_ml(
    results: list[ScoredRequest],
    model_dir: Path,
) -> Pipeline:
    """
    Build a Pipeline with ML inference engine wired in
    """
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    engine = InferenceEngine(model_dir=str(model_dir))

    async def collect(sr: ScoredRequest) -> None:
        results.append(sr)

    pipeline = Pipeline(
        redis_client=redis,
        rule_engine=RuleEngine(),
        on_result=collect,
        inference_engine=engine,
    )
    await pipeline.start()
    return pipeline


async def _make_pipeline_rules_only(
    results: list[ScoredRequest], ) -> Pipeline:
    """
    Build a Pipeline without ML inference engine
    """
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)

    async def collect(sr: ScoredRequest) -> None:
        results.append(sr)

    pipeline = Pipeline(
        redis_client=redis,
        rule_engine=RuleEngine(),
        on_result=collect,
    )
    await pipeline.start()
    return pipeline


class TestMLIntegration:

    @pytest.mark.asyncio
    async def test_pipeline_with_ml_sets_hybrid_mode(
            self, trained_model_dir: Path) -> None:
        results: list[ScoredRequest] = []
        pipeline = await _make_pipeline_with_ml(results, trained_model_dir)

        await pipeline.raw_queue.put(VALID_LINE)
        await pipeline.stop()

        assert len(results) == 1
        assert results[0].detection_mode == "hybrid"

    @pytest.mark.asyncio
    async def test_pipeline_with_ml_produces_final_score(
            self, trained_model_dir: Path) -> None:
        results: list[ScoredRequest] = []
        pipeline = await _make_pipeline_with_ml(results, trained_model_dir)

        await pipeline.raw_queue.put(VALID_LINE)
        await pipeline.stop()

        assert len(results) == 1
        assert results[0].final_score >= 0.0
        assert results[0].final_score <= 1.0

    @pytest.mark.asyncio
    async def test_rules_only_uses_rule_score(self, ) -> None:
        results: list[ScoredRequest] = []
        pipeline = await _make_pipeline_rules_only(results)

        await pipeline.raw_queue.put(VALID_LINE)
        await pipeline.stop()

        assert len(results) == 1
        assert results[0].detection_mode == "rules"
        assert results[0].final_score == results[0].rule_result.threat_score

    @pytest.mark.asyncio
    async def test_attack_scores_higher_than_benign(
            self, trained_model_dir: Path) -> None:
        results: list[ScoredRequest] = []
        pipeline = await _make_pipeline_with_ml(results, trained_model_dir)

        await pipeline.raw_queue.put(VALID_LINE)
        await pipeline.raw_queue.put(SQLI_LINE)
        await pipeline.stop()

        assert len(results) == 2
        benign_score = results[0].final_score
        attack_score = results[1].final_score
        assert attack_score > benign_score

    @pytest.mark.asyncio
    async def test_rule_result_preserved_in_hybrid_mode(
            self, trained_model_dir: Path) -> None:
        results: list[ScoredRequest] = []
        pipeline = await _make_pipeline_with_ml(results, trained_model_dir)

        await pipeline.raw_queue.put(SQLI_LINE)
        await pipeline.stop()

        assert len(results) == 1
        assert "SQL_INJECTION" in results[0].rule_result.matched_rules
        assert results[0].rule_result.threat_score > 0
