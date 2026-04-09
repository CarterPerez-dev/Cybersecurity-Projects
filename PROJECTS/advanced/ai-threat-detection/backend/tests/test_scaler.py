"""
©AngelaMos | 2026
test_scaler.py

Tests the FeatureScaler IQR-based normalization for
fitting, transform correctness, JSON round-trip, and error
handling

Validates n_features is stored after fit, transform
preserves shape and float32 dtype, median of scaled
features is near zero, inverse_transform recovers original
values within 1e-5, save_json creates a valid JSON file
with center/scale/n_features keys, load_json round-trip
produces identical transform output within 1e-6, transform
before fit raises RuntimeError, and fit_transform
convenience method works

Connects to:
  ml/scaler - FeatureScaler
"""

import json
from pathlib import Path

import numpy as np
import pytest

from ml.scaler import FeatureScaler


@pytest.fixture
def sample_data() -> np.ndarray:
    """
    Two-hundred samples of 35-dimensional random float32 data.
    """
    rng = np.random.default_rng(42)
    return rng.standard_normal((200, 35)).astype(np.float32)


class TestFeatureScaler:

    def test_fit_sets_n_features(self, sample_data: np.ndarray) -> None:
        """
        Fitting stores the number of input features.
        """
        scaler = FeatureScaler()
        scaler.fit(sample_data)
        assert scaler.n_features == 35

    def test_transform_preserves_shape(self, sample_data: np.ndarray) -> None:
        """
        Transform output has the same shape as the input array.
        """
        scaler = FeatureScaler()
        scaler.fit(sample_data)
        transformed = scaler.transform(sample_data)
        assert transformed.shape == sample_data.shape

    def test_transform_dtype_float32(self, sample_data: np.ndarray) -> None:
        """
        Transformed array dtype remains float32.
        """
        scaler = FeatureScaler()
        scaler.fit(sample_data)
        transformed = scaler.transform(sample_data)
        assert transformed.dtype == np.float32

    def test_transformed_median_near_zero(self,
                                          sample_data: np.ndarray) -> None:
        """
        Median of each feature column is approximately zero after scaling.
        """
        scaler = FeatureScaler()
        scaler.fit(sample_data)
        transformed = scaler.transform(sample_data)
        medians = np.median(transformed, axis=0)
        assert np.allclose(medians, 0.0, atol=0.15)

    def test_inverse_transform_recovers_original(
            self, sample_data: np.ndarray) -> None:
        """
        Inverse transform recovers the original values within floating-point tolerance.
        """
        scaler = FeatureScaler()
        scaler.fit(sample_data)
        transformed = scaler.transform(sample_data)
        recovered = scaler.inverse_transform(transformed)
        np.testing.assert_allclose(recovered, sample_data, atol=1e-5)

    def test_save_json_creates_file(self, sample_data: np.ndarray,
                                    tmp_path: Path) -> None:
        """
        save_json writes a non-empty file to the given path.
        """
        scaler = FeatureScaler()
        scaler.fit(sample_data)
        path = tmp_path / "scaler.json"
        scaler.save_json(path)
        assert path.exists()
        assert path.stat().st_size > 0

    def test_save_json_is_valid_json(self, sample_data: np.ndarray,
                                     tmp_path: Path) -> None:
        """
        Saved JSON contains center, scale, and n_features keys.
        """
        scaler = FeatureScaler()
        scaler.fit(sample_data)
        path = tmp_path / "scaler.json"
        scaler.save_json(path)
        data = json.loads(path.read_text())
        assert "center" in data
        assert "scale" in data
        assert "n_features" in data

    def test_load_json_round_trip(self, sample_data: np.ndarray,
                                  tmp_path: Path) -> None:
        """
        Loading from JSON produces a scaler with identical transform output.
        """
        scaler = FeatureScaler()
        scaler.fit(sample_data)
        path = tmp_path / "scaler.json"
        scaler.save_json(path)

        loaded = FeatureScaler.load_json(path)
        assert loaded.n_features == scaler.n_features

        original_out = scaler.transform(sample_data)
        loaded_out = loaded.transform(sample_data)
        np.testing.assert_allclose(original_out, loaded_out, atol=1e-6)

    def test_transform_before_fit_raises(self) -> None:
        """
        Calling transform before fit raises RuntimeError.
        """
        scaler = FeatureScaler()
        with pytest.raises(RuntimeError):
            scaler.transform(np.zeros((5, 35), dtype=np.float32))

    def test_fit_transform_convenience(self, sample_data: np.ndarray) -> None:
        """
        fit_transform fits and transforms in one call.
        """
        scaler = FeatureScaler()
        result = scaler.fit_transform(sample_data)
        assert result.shape == sample_data.shape
        assert scaler.n_features == 35
