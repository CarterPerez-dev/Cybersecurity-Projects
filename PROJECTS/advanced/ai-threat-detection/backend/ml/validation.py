"""
©AngelaMos | 2026
validation.py

Post-training ensemble validation with quality gates for
deployment readiness

validate_ensemble loads all 3 ONNX models via
InferenceEngine, runs batch prediction on held-out test
data, normalizes per-model raw scores (AE reconstruction
error against threshold, IF anomaly scores), fuses them
via weighted average (default weights: AE 0.4, RF 0.4,
IF 0.2), applies a 0.5 binary threshold, and computes
precision, recall, F1, PR-AUC, and ROC-AUC. Quality
gates require PR-AUC >= 0.85 and F1 >= 0.80 for
passed_gates to be True. Returns a ValidationResult
dataclass with all metrics, confusion matrix, and
per-gate pass/fail details

Connects to:
  core/detection/ensemble  - normalize_ae_score,
                             normalize_if_score, fuse_scores
  core/detection/inference - InferenceEngine ONNX runtime
  ml/orchestrator          - called after training to gate
                             deployment
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from app.core.detection.ensemble import (
    fuse_scores,
    normalize_ae_score,
    normalize_if_score,
)
from app.core.detection.inference import InferenceEngine

logger = logging.getLogger(__name__)

DEFAULT_ENSEMBLE_WEIGHTS: dict[str, float] = {
    "ae": 0.4,
    "rf": 0.4,
    "if": 0.2,
}

BINARY_THRESHOLD = 0.5


@dataclass
class ValidationResult:
    """
    Ensemble validation metrics and gate results
    """

    precision: float
    recall: float
    f1: float
    pr_auc: float
    roc_auc: float
    confusion_matrix: list[list[int]]
    passed_gates: bool
    gate_details: dict[str, bool] = field(default_factory=dict)


def validate_ensemble(
    model_dir: Path,
    X_test: np.ndarray,
    y_test: np.ndarray,
    ensemble_weights: dict[str, float] | None = None,
    pr_auc_gate: float = 0.85,
    f1_gate: float = 0.80,
) -> ValidationResult:
    """
    Run all 3 models on test data and compute classification metrics
    """
    weights = ensemble_weights or DEFAULT_ENSEMBLE_WEIGHTS

    engine = InferenceEngine(model_dir=str(model_dir))
    if not engine.is_loaded:
        raise RuntimeError(f"Failed to load models from {model_dir}")

    raw_scores = engine.predict(X_test.astype(np.float32), )
    if raw_scores is None:
        raise RuntimeError("Inference returned None")

    fused = _compute_fused_scores(raw_scores, engine.threshold, weights)

    y_pred = (fused >= BINARY_THRESHOLD).astype(np.int32)

    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1_val = float(f1_score(y_test, y_pred, zero_division=0))
    pr_auc_val = float(average_precision_score(y_test, fused))
    roc_auc_val = float(roc_auc_score(y_test, fused))

    cm = confusion_matrix(y_test, y_pred).tolist()

    pr_auc_passed = pr_auc_val >= pr_auc_gate
    f1_passed = f1_val >= f1_gate
    gate_details = {
        "pr_auc": pr_auc_passed,
        "f1": f1_passed,
    }

    logger.info(
        "Validation: precision=%.3f recall=%.3f "
        "f1=%.3f pr_auc=%.3f roc_auc=%.3f",
        prec,
        rec,
        f1_val,
        pr_auc_val,
        roc_auc_val,
    )

    return ValidationResult(
        precision=prec,
        recall=rec,
        f1=f1_val,
        pr_auc=pr_auc_val,
        roc_auc=roc_auc_val,
        confusion_matrix=cm,
        passed_gates=pr_auc_passed and f1_passed,
        gate_details=gate_details,
    )


def _compute_fused_scores(
    raw_scores: dict[str, list[float]],
    threshold: float,
    weights: dict[str, float],
) -> np.ndarray:
    """
    Normalize and fuse per-model raw scores into a single score array
    """
    n_samples = len(raw_scores["ae"])
    fused = np.zeros(n_samples, dtype=np.float64)

    for i in range(n_samples):
        per_model: dict[str, float] = {}

        per_model["ae"] = normalize_ae_score(raw_scores["ae"][i], threshold)
        per_model["rf"] = raw_scores["rf"][i]
        per_model["if"] = normalize_if_score(raw_scores["if"][i])

        fused[i] = fuse_scores(per_model, weights)

    return fused
