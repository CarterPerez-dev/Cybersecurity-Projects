"""
©AngelaMos | 2026
test_training.py

Tests training functions for the autoencoder, random forest,
and isolation forest models

TestAutoencoderTraining validates train_autoencoder returns
model/threshold/scaler/history, threshold is positive,
history has correct epoch count, higher percentile yields
higher threshold, and returned model is in eval mode.
TestRandomForestTraining validates model/metrics return,
predict_proba availability, required metric keys (f1,
pr_auc, accuracy, precision, recall), probability range,
and metric value range. TestIsolationForestTraining
validates model return, score_samples availability,
n_samples metric, and normal/outlier score separation

Connects to:
  ml/train_autoencoder  - train_autoencoder
  ml/train_classifiers  - train_random_forest,
                          train_isolation_forest
"""

import numpy as np
import pytest

from ml.train_autoencoder import train_autoencoder
from ml.train_classifiers import train_isolation_forest, train_random_forest


class TestAutoencoderTraining:

    @pytest.fixture
    def normal_data(self) -> np.ndarray:
        """
        Three-hundred samples of clipped 35-dimensional float32 data representing normal traffic.
        """
        rng = np.random.default_rng(42)
        return (rng.standard_normal(
            (300, 35)) * 0.3 + 0.5).astype(np.float32).clip(0, 1)

    def test_returns_model_and_threshold(self,
                                         normal_data: np.ndarray) -> None:
        """
        Training returns model, threshold, scaler, and history keys.
        """
        result = train_autoencoder(normal_data, epochs=5, batch_size=32)
        assert "model" in result
        assert "threshold" in result
        assert "scaler" in result
        assert "history" in result

    def test_threshold_is_positive(self, normal_data: np.ndarray) -> None:
        """
        Computed reconstruction error threshold is a positive value.
        """
        result = train_autoencoder(normal_data, epochs=5, batch_size=32)
        assert result["threshold"] > 0.0

    def test_history_has_train_loss(self, normal_data: np.ndarray) -> None:
        """
        Training history includes one train_loss entry per epoch.
        """
        result = train_autoencoder(normal_data, epochs=5, batch_size=32)
        assert "train_loss" in result["history"]
        assert len(result["history"]["train_loss"]) == 5

    def test_custom_percentile(self, normal_data: np.ndarray) -> None:
        """
        Higher percentile produces a higher or equal reconstruction threshold.
        """
        result_95 = train_autoencoder(normal_data,
                                      epochs=3,
                                      batch_size=32,
                                      percentile=95.0)
        result_99 = train_autoencoder(normal_data,
                                      epochs=3,
                                      batch_size=32,
                                      percentile=99.0)
        assert result_99["threshold"] >= result_95["threshold"]

    def test_model_is_in_eval_mode(self, normal_data: np.ndarray) -> None:
        """
        Returned model is in eval mode after training completes.
        """
        result = train_autoencoder(normal_data, epochs=3, batch_size=32)
        assert not result["model"].training


class TestRandomForestTraining:

    @pytest.fixture
    def labeled_data(self) -> tuple[np.ndarray, np.ndarray]:
        """
        Four-hundred samples with 300 benign and 100 attack labels.
        """
        rng = np.random.default_rng(42)
        X = rng.standard_normal((400, 35)).astype(np.float32)
        y = np.concatenate(
            [np.zeros(300, dtype=np.int64),
             np.ones(100, dtype=np.int64)])
        return X, y

    def test_returns_model_and_metrics(
            self, labeled_data: tuple[np.ndarray, np.ndarray]) -> None:
        """
        Training returns model and metrics dict.
        """
        X, y = labeled_data
        result = train_random_forest(X, y)
        assert "model" in result
        assert "metrics" in result

    def test_model_has_predict_proba(
            self, labeled_data: tuple[np.ndarray, np.ndarray]) -> None:
        """
        Trained model exposes predict_proba for probability scoring.
        """
        X, y = labeled_data
        result = train_random_forest(X, y)
        assert hasattr(result["model"], "predict_proba")

    def test_metrics_contain_required_keys(
            self, labeled_data: tuple[np.ndarray, np.ndarray]) -> None:
        """
        Metrics dict contains f1, pr_auc, accuracy, precision, and recall.
        """
        X, y = labeled_data
        result = train_random_forest(X, y)
        for key in ("f1", "pr_auc", "accuracy", "precision", "recall"):
            assert key in result["metrics"]

    def test_probabilities_in_valid_range(
            self, labeled_data: tuple[np.ndarray, np.ndarray]) -> None:
        """
        Predicted probabilities are within the [0, 1] range.
        """
        X, y = labeled_data
        result = train_random_forest(X, y)
        proba = result["model"].predict_proba(X[:10])
        assert proba.min() >= 0.0
        assert proba.max() <= 1.0

    def test_metrics_values_in_valid_range(
            self, labeled_data: tuple[np.ndarray, np.ndarray]) -> None:
        """
        All metric values fall within [0, 1].
        """
        X, y = labeled_data
        result = train_random_forest(X, y)
        for value in result["metrics"].values():
            assert 0.0 <= value <= 1.0


class TestIsolationForestTraining:

    @pytest.fixture
    def normal_data(self) -> np.ndarray:
        """
        Two-hundred samples of 35-dimensional standard normal float32 data.
        """
        rng = np.random.default_rng(42)
        return rng.standard_normal((200, 35)).astype(np.float32)

    def test_returns_model(self, normal_data: np.ndarray) -> None:
        """
        Training returns a model key in the result dict.
        """
        result = train_isolation_forest(normal_data)
        assert "model" in result

    def test_model_has_score_samples(self, normal_data: np.ndarray) -> None:
        """
        Trained model exposes score_samples for anomaly scoring.
        """
        result = train_isolation_forest(normal_data)
        assert hasattr(result["model"], "score_samples")

    def test_returns_metrics_with_n_samples(self,
                                            normal_data: np.ndarray) -> None:
        """
        Metrics include n_samples matching the training set size.
        """
        result = train_isolation_forest(normal_data)
        assert result["metrics"]["n_samples"] == 200

    def test_anomaly_scores_distinguish_normal_and_outlier(
            self, normal_data: np.ndarray) -> None:
        """
        Normal training data scores higher than extreme outliers.
        """
        result = train_isolation_forest(normal_data)
        model = result["model"]
        normal_scores = model.score_samples(normal_data[:50])
        outlier_data = np.full((50, 35), 10.0, dtype=np.float32)
        outlier_scores = model.score_samples(outlier_data)
        assert normal_scores.mean() > outlier_scores.mean()
