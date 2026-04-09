"""
©AngelaMos | 2026
test_config_ml.py

Tests ML-related settings defaults for detection mode,
ensemble weights, model paths, and MLflow tracking URI

Validates that the default detection_mode is 'rules',
ensemble weights (AE + RF + IF) sum to exactly 1.0,
model_dir defaults to 'data/models', ae_threshold_
percentile defaults to 99.5, and mlflow_tracking_uri
defaults to 'file:./mlruns'

Connects to:
  app/config - Settings pydantic-settings model
"""

from app.config import settings


def test_default_detection_mode_is_rules() -> None:
    """
    Default detection_mode is 'rules' before any ML models are loaded.
    """
    assert settings.detection_mode == "rules"


def test_default_ensemble_weights_sum_to_one() -> None:
    """
    AE + RF + IF ensemble weights sum to exactly 1.0.
    """
    total = (settings.ensemble_weight_ae + settings.ensemble_weight_rf +
             settings.ensemble_weight_if)
    assert abs(total - 1.0) < 1e-6


def test_default_model_dir() -> None:
    """
    Default model artifact directory is data/models.
    """
    assert settings.model_dir == "data/models"


def test_default_ae_threshold_percentile() -> None:
    """
    Default autoencoder threshold percentile is 99.5.
    """
    assert settings.ae_threshold_percentile == 99.5


def test_default_mlflow_tracking_uri() -> None:
    """
    Default MLflow tracking URI uses local file storage.
    """
    assert settings.mlflow_tracking_uri == "file:./mlruns"
