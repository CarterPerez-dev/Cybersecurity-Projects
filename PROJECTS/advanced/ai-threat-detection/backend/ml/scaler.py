"""
©AngelaMos | 2026
scaler.py

IQR-based feature scaler with JSON persistence for the
autoencoder preprocessing stage

FeatureScaler wraps sklearn RobustScaler (median/IQR
normalization) to handle outlier-heavy HTTP traffic data.
Provides fit, transform, fit_transform, and
inverse_transform mirroring the sklearn API. save_json
serializes center, scale arrays, and optional feature_names
to a human-readable JSON file (avoiding pickle for security
and portability), and load_json reconstructs a fitted
scaler from that file with optional feature ordering
validation against expected_feature_names.
Only the autoencoder uses this scaler since tree-based
models (random forest, isolation forest) are
scale-invariant

Connects to:
  ml/train_autoencoder - fitted during AE training
  ml/orchestrator      - scaler.json saved alongside models
  core/detection/
    inference          - loaded at inference time for AE
                         input normalization
"""

import json
from pathlib import Path

import numpy as np
from sklearn.preprocessing import RobustScaler


class FeatureScaler:
    """
    IQR-based feature scaler persisted as JSON (not pickle).

    Wraps sklearn RobustScaler for outlier-robust normalization.
    Used only for autoencoder input — tree models are scale-invariant.
    """

    def __init__(self) -> None:
        self._scaler: RobustScaler | None = None
        self._fitted = False

    @property
    def n_features(self) -> int:
        """
        Number of features the scaler was fitted on.
        """
        if not self._fitted or self._scaler is None:
            raise RuntimeError("Scaler has not been fitted")
        return int(self._scaler.n_features_in_)

    def fit(self, X: np.ndarray) -> FeatureScaler:
        """
        Fit the scaler on training data.
        """
        self._scaler = RobustScaler()
        self._scaler.fit(X)
        self._fitted = True
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        """
        Transform features using the fitted scaler parameters.
        """
        if not self._fitted or self._scaler is None:
            raise RuntimeError("Scaler has not been fitted")
        return self._scaler.transform(X).astype(np.float32)  # type: ignore[no-any-return]

    def inverse_transform(self, X: np.ndarray) -> np.ndarray:
        """
        Reverse the scaling transformation.
        """
        if not self._fitted or self._scaler is None:
            raise RuntimeError("Scaler has not been fitted")
        return self._scaler.inverse_transform(X).astype(np.float32)  # type: ignore[no-any-return]

    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        """
        Fit and transform in one step.
        """
        self.fit(X)
        return self.transform(X)

    def save_json(
        self,
        path: Path | str,
        feature_names: list[str] | None = None,
    ) -> None:
        """
        Serialize scaler parameters to a human-readable JSON file.
        """
        if not self._fitted or self._scaler is None:
            raise RuntimeError("Scaler has not been fitted")
        data: dict[str, object] = {
            "center": self._scaler.center_.tolist(),
            "scale": self._scaler.scale_.tolist(),
            "n_features": int(self._scaler.n_features_in_),
        }
        if feature_names is not None:
            data["feature_names"] = feature_names
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")

    @classmethod
    def load_json(
        cls,
        path: Path | str,
        expected_feature_names: list[str] | None = None,
    ) -> FeatureScaler:
        """
        Reconstruct a fitted scaler from a JSON file.
        """
        data = json.loads(Path(path).read_text(encoding="utf-8"))

        stored_names = data.get("feature_names")
        if (
            expected_feature_names is not None
            and stored_names is not None
            and stored_names != expected_feature_names
        ):
            raise ValueError(
                "Feature ordering mismatch between trained "
                "scaler and current FEATURE_ORDER"
            )

        scaler = cls()
        scaler._scaler = RobustScaler()
        scaler._scaler.center_ = np.array(data["center"], dtype=np.float64)
        scaler._scaler.scale_ = np.array(data["scale"], dtype=np.float64)
        scaler._scaler.n_features_in_ = data["n_features"]
        scaler._fitted = True
        return scaler
