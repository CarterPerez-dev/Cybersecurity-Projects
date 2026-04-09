"""
©AngelaMos | 2026
test_orchestrator.py

Tests the TrainingOrchestrator pipeline from data splitting
through model export, validation, and MLflow logging

Verifies all 5 output files are produced (ae.onnx, rf.onnx,
if.onnx, scaler.json, threshold.json), TrainingResult
dataclass structure, scaler.json keys (center, scale,
n_features), threshold.json float value, per-model metrics
presence (ae_threshold, rf f1, if n_samples), ensemble
validation metrics, MLflow run ID capture (32-char hex),
and passed_gates boolean type

Connects to:
  ml/orchestrator - TrainingOrchestrator, TrainingResult
"""

import json
from pathlib import Path

import numpy as np

from ml.orchestrator import TrainingOrchestrator, TrainingResult

N_FEATURES = 35
EXPECTED_FILES = [
    "ae.onnx",
    "rf.onnx",
    "if.onnx",
    "scaler.json",
    "threshold.json",
]


def _make_dataset() -> tuple[np.ndarray, np.ndarray]:
    """
    Generate a small synthetic dataset for testing
    """
    rng = np.random.default_rng(42)
    X_normal = rng.standard_normal((200, N_FEATURES)).astype(np.float32)
    X_attack = (rng.standard_normal((80, N_FEATURES)).astype(np.float32) + 2.0)
    X = np.vstack([X_normal, X_attack])
    y = np.array([0] * 200 + [1] * 80, dtype=np.int32)
    return X, y


class TestTrainingOrchestrator:
    """
    Test the end-to-end training orchestrator
    """

    def test_produces_all_output_files(self, tmp_path: Path) -> None:
        """
        Orchestrator produces all 5 expected output files
        """
        X, y = _make_dataset()
        orch = TrainingOrchestrator(output_dir=tmp_path, epochs=3)
        orch.run(X, y)

        for filename in EXPECTED_FILES:
            assert (tmp_path / filename).exists(), f"Missing {filename}"

    def test_returns_training_result(self, tmp_path: Path) -> None:
        """
        Returns a TrainingResult dataclass
        """
        X, y = _make_dataset()
        orch = TrainingOrchestrator(output_dir=tmp_path, epochs=3)
        result = orch.run(X, y)

        assert isinstance(result, TrainingResult)

    def test_scaler_json_has_required_keys(self, tmp_path: Path) -> None:
        """
        scaler.json contains center, scale, and n_features
        """
        X, y = _make_dataset()
        orch = TrainingOrchestrator(output_dir=tmp_path, epochs=3)
        orch.run(X, y)

        scaler_data = json.loads((tmp_path / "scaler.json").read_text())
        assert "center" in scaler_data
        assert "scale" in scaler_data
        assert "n_features" in scaler_data

    def test_threshold_json_has_float(self, tmp_path: Path) -> None:
        """
        threshold.json contains a float threshold value
        """
        X, y = _make_dataset()
        orch = TrainingOrchestrator(output_dir=tmp_path, epochs=3)
        orch.run(X, y)

        threshold_data = json.loads((tmp_path / "threshold.json").read_text())
        assert "threshold" in threshold_data
        assert isinstance(threshold_data["threshold"], float)

    def test_result_has_per_model_metrics(self, tmp_path: Path) -> None:
        """
        TrainingResult includes metrics for each model
        """
        X, y = _make_dataset()
        orch = TrainingOrchestrator(output_dir=tmp_path, epochs=3)
        result = orch.run(X, y)

        assert "ae_threshold" in result.ae_metrics
        assert "f1" in result.rf_metrics
        assert "n_samples" in result.if_metrics

    def test_ensemble_metrics_present(self, tmp_path: Path) -> None:
        """
        Ensemble validation metrics are populated
        """
        X, y = _make_dataset()
        orch = TrainingOrchestrator(output_dir=tmp_path, epochs=3)
        result = orch.run(X, y)

        assert result.ensemble_metrics is not None
        assert 0.0 <= result.ensemble_metrics.f1 <= 1.0

    def test_mlflow_run_id_set(self, tmp_path: Path) -> None:
        """
        MLflow run ID is captured in the result
        """
        X, y = _make_dataset()
        mlflow_dir = tmp_path / "mlruns"
        mlflow_dir.mkdir()
        orch = TrainingOrchestrator(
            output_dir=tmp_path / "models",
            epochs=3,
        )
        result = orch.run(X, y)

        assert result.mlflow_run_id is not None
        assert len(result.mlflow_run_id) == 32

    def test_passed_gates_is_bool(self, tmp_path: Path) -> None:
        """
        passed_gates is a boolean value
        """
        X, y = _make_dataset()
        orch = TrainingOrchestrator(output_dir=tmp_path, epochs=3)
        result = orch.run(X, y)

        assert isinstance(result.passed_gates, bool)
