"""
©AngelaMos | 2026
splitting.py

Stratified train/val/test splitting with SMOTE
oversampling for imbalanced attack data

prepare_training_data performs a 70/15/15 stratified split
preserving class ratios, extracts the normal-only subset
from training data for the autoencoder and isolation
forest, and conditionally applies SMOTE oversampling to
the training set when the minority class ratio falls below
the target strategy (default 0.3). SMOTE is skipped if the
minority class has fewer than k_neighbors+1 samples.
Returns a TrainingSplit dataclass with X_train, y_train,
X_val, y_val, X_test, y_test, and X_normal_train arrays

Connects to:
  ml/orchestrator - called at the start of the training
                    pipeline
"""

from dataclasses import dataclass

import numpy as np
from imblearn.over_sampling import SMOTE
from sklearn.model_selection import train_test_split


@dataclass
class TrainingSplit:
    """
    Result of stratified splitting with SMOTE oversampling
    """

    X_train: np.ndarray
    y_train: np.ndarray
    X_val: np.ndarray
    y_val: np.ndarray
    X_test: np.ndarray
    y_test: np.ndarray
    X_normal_train: np.ndarray


def prepare_training_data(
    X: np.ndarray,
    y: np.ndarray,
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    smote_strategy: float = 0.3,
    smote_k: int = 5,
    random_state: int = 42,
) -> TrainingSplit:
    """
    Split data into train/val/test with SMOTE on training set only
    """
    n_classes = len(np.unique(y))
    if n_classes < 2:
        raise ValueError("y must contain at least 2 classes")

    test_size = 1.0 - train_ratio
    X_train, X_rem, y_train, y_rem = train_test_split(
        X,
        y,
        test_size=test_size,
        stratify=y,
        random_state=random_state,
    )

    X_val, X_test, y_val, y_test = train_test_split(
        X_rem,
        y_rem,
        test_size=0.5,
        stratify=y_rem,
        random_state=random_state,
    )

    X_normal_train = X_train[y_train == 0]

    class_counts = np.bincount(y_train)
    minority_count = class_counts.min()
    majority_count = class_counts.max()
    current_ratio = minority_count / majority_count

    if (minority_count >= smote_k + 1 and current_ratio < smote_strategy):
        sampler = SMOTE(
            sampling_strategy=smote_strategy,
            k_neighbors=smote_k,
            random_state=random_state,
        )
        X_train, y_train = sampler.fit_resample(X_train, y_train)

    return TrainingSplit(
        X_train=X_train,
        y_train=y_train,
        X_val=X_val,
        y_val=y_val,
        X_test=X_test,
        y_test=y_test,
        X_normal_train=X_normal_train,
    )
