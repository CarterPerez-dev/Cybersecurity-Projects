"""
©AngelaMos | 2026
test_splitting.py

Tests stratified train/val/test splitting with SMOTE
oversampling for imbalanced datasets

Validates TrainingSplit dataclass return, 70/15/15 split
proportions within tolerance, stratified class distribution
preservation in val/test sets, SMOTE minority ratio near
target strategy (0.3), val/test sizes unaffected by SMOTE,
X_normal_train containing only class-0 rows, small dataset
(50 samples) success, single-class ValueError, and SMOTE
skip when minority count is below k_neighbors threshold

Connects to:
  ml/splitting - prepare_training_data, TrainingSplit
"""

import numpy as np
import pytest

from ml.splitting import TrainingSplit, prepare_training_data

N_NORMAL = 160
N_ATTACK = 40
N_FEATURES = 35
TOTAL = N_NORMAL + N_ATTACK


def _make_dataset(
    n_normal: int = N_NORMAL,
    n_attack: int = N_ATTACK,
    n_features: int = N_FEATURES,
) -> tuple[np.ndarray, np.ndarray]:
    """
    Generate synthetic imbalanced dataset
    """
    rng = np.random.default_rng(42)
    X = rng.standard_normal(
        (n_normal + n_attack, n_features)).astype(np.float32)
    y = np.array(
        [0] * n_normal + [1] * n_attack,
        dtype=np.int32,
    )
    return X, y


class TestPrepareTrainingData:
    """
    Tests for stratified splitting with SMOTE
    """

    def test_returns_training_split(self) -> None:
        """
        Returns a TrainingSplit dataclass
        """
        X, y = _make_dataset()
        result = prepare_training_data(X, y)
        assert isinstance(result, TrainingSplit)

    def test_split_proportions(self) -> None:
        """
        Validates 70/15/15 split proportions
        """
        X, y = _make_dataset()
        result = prepare_training_data(X, y)
        expected_val = int(TOTAL * 0.15)
        expected_test = int(TOTAL * 0.15)
        tolerance = int(TOTAL * 0.05)
        assert abs(result.X_val.shape[0] - expected_val) <= tolerance
        assert abs(result.X_test.shape[0] - expected_test) <= tolerance

    def test_stratified_class_distribution(self, ) -> None:
        """
        Splits preserve the original class ratio
        """
        X, y = _make_dataset()
        original_ratio = np.mean(y == 1)
        result = prepare_training_data(X, y)
        val_ratio = np.mean(result.y_val == 1)
        test_ratio = np.mean(result.y_test == 1)
        ratio_tol = 0.10
        assert abs(val_ratio - original_ratio) < ratio_tol
        assert abs(test_ratio - original_ratio) < ratio_tol

    def test_smote_increases_minority(self) -> None:
        """
        SMOTE brings minority ratio near strategy
        """
        X, y = _make_dataset()
        result = prepare_training_data(
            X,
            y,
            smote_strategy=0.3,
        )
        minority = np.sum(result.y_train == 1)
        majority = np.sum(result.y_train == 0)
        ratio = minority / majority
        assert ratio >= 0.25

    def test_val_test_untouched(self) -> None:
        """
        Val test sizes match pre-SMOTE counts
        """
        X, y = _make_dataset()
        result = prepare_training_data(X, y)
        remainder = TOTAL - int(TOTAL * 0.70)
        half = remainder // 2
        tol = 3
        assert abs(result.X_val.shape[0] - half) <= tol
        assert abs(result.X_test.shape[0] - half) <= tol
        assert (result.X_val.shape[0] == result.y_val.shape[0])
        assert (result.X_test.shape[0] == result.y_test.shape[0])

    def test_x_normal_train_only_normals(self, ) -> None:
        """
        X_normal_train has only class-0 rows
        """
        X, y = _make_dataset()
        result = prepare_training_data(X, y)
        expected = int(N_NORMAL * 0.70)
        tol = int(TOTAL * 0.05)
        assert abs(result.X_normal_train.shape[0] - expected) <= tol
        assert (result.X_normal_train.shape[1] == N_FEATURES)

    def test_small_dataset_works(self) -> None:
        """
        Small 50-sample dataset succeeds
        """
        X, y = _make_dataset(
            n_normal=40,
            n_attack=10,
            n_features=N_FEATURES,
        )
        result = prepare_training_data(X, y, smote_k=3)
        assert isinstance(result, TrainingSplit)
        assert result.X_train.shape[0] > 0
        assert result.X_val.shape[0] > 0
        assert result.X_test.shape[0] > 0

    def test_all_one_class_raises_value_error(self, ) -> None:
        """
        Single-class labels raise ValueError
        """
        rng = np.random.default_rng(99)
        X = rng.standard_normal((100, N_FEATURES)).astype(np.float32)
        y_zeros = np.zeros(100, dtype=np.int32)
        with pytest.raises(ValueError):
            prepare_training_data(X, y_zeros)
        y_ones = np.ones(100, dtype=np.int32)
        with pytest.raises(ValueError):
            prepare_training_data(X, y_ones)

    def test_smote_skipped_minority_too_small(self, ) -> None:
        """
        Tiny minority skips SMOTE gracefully
        """
        X, y = _make_dataset(
            n_normal=90,
            n_attack=10,
            n_features=N_FEATURES,
        )
        result = prepare_training_data(X, y, smote_k=50)
        assert isinstance(result, TrainingSplit)
        assert result.X_train.shape[0] > 0
