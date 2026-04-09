"""
©AngelaMos | 2026
test_training_e2e.py

End-to-end training integration test from synthetic data
generation through ONNX inference and score fusion

test_full_training_produces_loadable_models generates a
500-normal/200-attack synthetic dataset, runs the full
TrainingOrchestrator pipeline with 3 epochs, verifies all
5 output files (ae.onnx, rf.onnx, if.onnx, scaler.json,
threshold.json), loads models via InferenceEngine, runs
batch prediction, normalizes and fuses per-model scores,
blends with rule scores, and asserts all values are in
[0, 1]. Validates passed_gates is a boolean

Connects to:
  ml/orchestrator          - TrainingOrchestrator
  ml/synthetic             - generate_mixed_dataset
  core/detection/ensemble  - normalize, fuse, blend
  core/detection/inference - InferenceEngine
"""

from pathlib import Path

from app.core.detection.ensemble import (
    blend_scores,
    fuse_scores,
    normalize_ae_score,
    normalize_if_score,
)
from app.core.detection.inference import InferenceEngine
from ml.orchestrator import TrainingOrchestrator
from ml.synthetic import generate_mixed_dataset

N_NORMAL = 500
N_ATTACK = 200
N_FEATURES = 35
ENSEMBLE_WEIGHTS = {"ae": 0.4, "rf": 0.4, "if": 0.2}


class TestTrainingE2E:
    """
    End-to-end training integration test
    """

    def test_full_training_produces_loadable_models(self,
                                                    tmp_path: Path) -> None:
        """
        Full pipeline produces models that load and predict
        """
        X, y = generate_mixed_dataset(N_NORMAL, N_ATTACK)
        assert X.shape == (
            N_NORMAL + N_ATTACK,
            N_FEATURES,
        )

        model_dir = tmp_path / "models"
        orch = TrainingOrchestrator(output_dir=model_dir, epochs=3)
        result = orch.run(X, y)

        expected_files = [
            "ae.onnx",
            "rf.onnx",
            "if.onnx",
            "scaler.json",
            "threshold.json",
        ]
        for filename in expected_files:
            assert (model_dir / filename).exists(), f"Missing {filename}"

        engine = InferenceEngine(str(model_dir))
        assert engine.is_loaded

        sample = X[:5]
        predictions = engine.predict(sample)
        assert predictions is not None
        assert "ae" in predictions
        assert "rf" in predictions
        assert "if" in predictions
        assert len(predictions["ae"]) == 5

        threshold = engine.threshold
        for i in range(5):
            ae_score = normalize_ae_score(predictions["ae"][i], threshold)
            if_score = normalize_if_score(predictions["if"][i])
            rf_score = predictions["rf"][i]

            scores = {
                "ae": ae_score,
                "rf": rf_score,
                "if": if_score,
            }
            fused = fuse_scores(scores, ENSEMBLE_WEIGHTS)
            assert 0.0 <= fused <= 1.0

            blended = blend_scores(fused, 0.0)
            assert 0.0 <= blended <= 1.0

        assert result.passed_gates is not None
        assert isinstance(result.passed_gates, bool)
