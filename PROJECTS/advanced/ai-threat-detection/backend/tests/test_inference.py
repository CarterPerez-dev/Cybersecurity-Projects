"""
©AngelaMos | 2026
test_inference.py

Tests the ONNX InferenceEngine for model loading, batch
prediction, score ranges, and error handling

Uses a model_dir fixture with all 3 exported ONNX models,
scaler.json, and threshold.json. Validates is_loaded=True
with all models, is_loaded=False for nonexistent and
partial directories, predict returns None when not loaded,
predict returns ae/rf/if score dicts, AE scores are non-
negative, RF probabilities are in [0, 1], single-sample
prediction works, threshold loads from JSON, and partial
model sets (AE only) report not loaded

Connects to:
  core/detection/inference - InferenceEngine
  ml/export_onnx           - model export for fixture
  ml/scaler                - FeatureScaler for fixture
  ml/autoencoder           - ThreatAutoencoder for fixture
"""

import json
from pathlib import Path

import numpy as np
import pytest

from ml.autoencoder import ThreatAutoencoder
from ml.export_onnx import (
    export_autoencoder,
    export_isolation_forest,
    export_random_forest,
)
from ml.scaler import FeatureScaler
from sklearn.ensemble import IsolationForest, RandomForestClassifier

from app.core.detection.inference import InferenceEngine


@pytest.fixture
def model_dir(tmp_path: Path) -> Path:
    """
    Create a temp directory with all 3 ONNX models + scaler + threshold
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


class TestInferenceEngine:

    def test_loads_all_models(self, model_dir: Path) -> None:
        """
        Engine reports is_loaded=True when all three ONNX models are present.
        """
        engine = InferenceEngine(model_dir=str(model_dir))
        assert engine.is_loaded

    def test_returns_none_when_no_models(self) -> None:
        """
        Engine reports is_loaded=False when the model directory does not exist.
        """
        engine = InferenceEngine(model_dir="/nonexistent/path")
        assert not engine.is_loaded

    def test_predict_returns_none_when_not_loaded(self) -> None:
        """
        predict returns None when the engine has no models loaded.
        """
        engine = InferenceEngine(model_dir="/nonexistent/path")
        result = engine.predict(np.zeros((1, 35), dtype=np.float32))
        assert result is None

    def test_predict_returns_scores(self, model_dir: Path) -> None:
        """
        predict returns a dict with ae, rf, and if score arrays.
        """
        engine = InferenceEngine(model_dir=str(model_dir))
        rng = np.random.default_rng(99)
        x = rng.standard_normal((4, 35)).astype(np.float32)
        result = engine.predict(x)
        assert result is not None
        assert "ae" in result
        assert "rf" in result
        assert "if" in result

    def test_predict_ae_scores_are_positive(self, model_dir: Path) -> None:
        """
        AE reconstruction error scores are non-negative for all samples.
        """
        engine = InferenceEngine(model_dir=str(model_dir))
        rng = np.random.default_rng(99)
        x = rng.standard_normal((4, 35)).astype(np.float32)
        result = engine.predict(x)
        assert result is not None
        assert all(s >= 0.0 for s in result["ae"])

    def test_predict_rf_probabilities_in_range(self, model_dir: Path) -> None:
        """
        RF malicious-class probabilities are within [0, 1].
        """
        engine = InferenceEngine(model_dir=str(model_dir))
        rng = np.random.default_rng(99)
        x = rng.standard_normal((4, 35)).astype(np.float32)
        result = engine.predict(x)
        assert result is not None
        assert all(0.0 <= p <= 1.0 for p in result["rf"])

    def test_predict_single_sample(self, model_dir: Path) -> None:
        """
        predict works on a single sample and returns one score per model.
        """
        engine = InferenceEngine(model_dir=str(model_dir))
        rng = np.random.default_rng(99)
        x = rng.standard_normal((1, 35)).astype(np.float32)
        result = engine.predict(x)
        assert result is not None
        assert len(result["ae"]) == 1
        assert len(result["rf"]) == 1
        assert len(result["if"]) == 1

    def test_threshold_loaded(self, model_dir: Path) -> None:
        """
        Autoencoder threshold is read from threshold.json on initialization.
        """
        engine = InferenceEngine(model_dir=str(model_dir))
        assert engine.threshold == 0.05

    def test_partial_models_not_loaded(self, tmp_path: Path) -> None:
        """
        Engine with only the AE model present reports is_loaded=False.
        """
        ae = ThreatAutoencoder(input_dim=35)
        export_autoencoder(ae, tmp_path / "ae.onnx")
        engine = InferenceEngine(model_dir=str(tmp_path))
        assert not engine.is_loaded
