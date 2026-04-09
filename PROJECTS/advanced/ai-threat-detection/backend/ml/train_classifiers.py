"""
©AngelaMos | 2026
train_classifiers.py

Sklearn classifier training for the random forest and
isolation forest ensemble members

train_random_forest builds a 200-tree balanced-weight
RandomForestClassifier with max_depth 20, wraps it in
CalibratedClassifierCV with isotonic calibration (3-fold
CV) for well-calibrated probability outputs, evaluates on
a held-out 20% calibration split, and returns the
calibrated model with accuracy, precision, recall, F1, and
PR-AUC metrics. train_isolation_forest fits a 200-tree
IsolationForest on normal-only traffic with automatic
contamination estimation, returning the model and sample
count

Connects to:
  ml/orchestrator - called during pipeline execution
  ml/export_onnx  - models exported to ONNX after training
"""

from typing import Any

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split


def train_random_forest(
    X: np.ndarray,
    y: np.ndarray,
    n_estimators: int = 200,
    max_depth: int = 20,
    calibration_split: float = 0.2,
) -> dict[str, Any]:
    """
    Train a random forest with isotonic probability calibration
    """
    X_train, X_eval, y_train, y_eval = train_test_split(
        X, y, test_size=calibration_split, stratify=y, random_state=42)

    base_rf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    calibrated = CalibratedClassifierCV(base_rf, method="isotonic", cv=3)
    calibrated.fit(X_train, y_train)

    y_pred = calibrated.predict(X_eval)
    y_proba = calibrated.predict_proba(X_eval)[:, 1]

    metrics = {
        "accuracy": float(accuracy_score(y_eval, y_pred)),
        "precision": float(precision_score(y_eval, y_pred, zero_division=0)),
        "recall": float(recall_score(y_eval, y_pred, zero_division=0)),
        "f1": float(f1_score(y_eval, y_pred, zero_division=0)),
        "pr_auc": float(average_precision_score(y_eval, y_proba)),
    }

    return {"model": calibrated, "metrics": metrics}


def train_isolation_forest(
    X_normal: np.ndarray,
    n_estimators: int = 200,
) -> dict[str, Any]:
    """
    Train an isolation forest on normal-only traffic
    """
    iso = IsolationForest(
        n_estimators=n_estimators,
        contamination="auto",
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(X_normal)

    return {
        "model": iso,
        "metrics": {
            "n_samples": len(X_normal)
        },
    }
