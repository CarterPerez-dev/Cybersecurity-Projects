"""
©AngelaMos | 2026
inference.py

ONNX-based inference engine for the 3-model ML ensemble

InferenceEngine loads autoencoder (ae.onnx), random
forest (rf.onnx), and isolation forest (if.onnx) sessions
plus RobustScaler parameters (scaler.json) and anomaly
threshold (threshold.json) from a model directory. predict
runs all 3 models on a batch of feature vectors: applies
_scale_for_ae to normalize autoencoder input, computes
reconstruction MSE for ae scores, extracts attack
probability from skl2onnx RF output format via _extract_
rf_proba, and returns raw IF decision scores. Returns
None when models are unavailable. Each ONNX session uses
single-threaded execution (inter/intra_op_num_threads=1)

Connects to:
  config.py          - settings.model_dir
  factory.py         - _load_inference_engine at startup
  core/ingestion/
    pipeline         - batch inference in scoring stage
  ml/export_onnx     - produces the ONNX model files
"""

import json
import logging
from pathlib import Path
from typing import Any

import numpy as np

try:
    import onnxruntime as ort
except ImportError:
    ort = None

logger = logging.getLogger(__name__)

AE_FILENAME = "ae.onnx"
RF_FILENAME = "rf.onnx"
IF_FILENAME = "if.onnx"
SCALER_FILENAME = "scaler.json"
THRESHOLD_FILENAME = "threshold.json"


class InferenceEngine:
    """
    ONNX-based inference engine for the 3-model ML ensemble.

    Loads autoencoder, random forest, and isolation forest ONNX sessions
    from a model directory. Returns None for predictions when models
    are not available.
    """

    def __init__(self, model_dir: str) -> None:
        self._ae_session: ort.InferenceSession | None = None
        self._rf_session: ort.InferenceSession | None = None
        self._if_session: ort.InferenceSession | None = None
        self._scaler_center: np.ndarray | None = None
        self._scaler_scale: np.ndarray | None = None
        self._threshold: float = 0.0
        self._loaded = False

        if ort is None:
            logger.warning("onnxruntime not installed")
            return

        model_path = Path(model_dir)
        ae_path = model_path / AE_FILENAME
        rf_path = model_path / RF_FILENAME
        if_path = model_path / IF_FILENAME
        scaler_path = model_path / SCALER_FILENAME
        threshold_path = model_path / THRESHOLD_FILENAME

        required = [ae_path, rf_path, if_path, scaler_path, threshold_path]
        if not all(p.exists() for p in required):
            return

        try:
            opts = ort.SessionOptions()
            opts.inter_op_num_threads = 1
            opts.intra_op_num_threads = 1

            self._ae_session = ort.InferenceSession(str(ae_path), opts)
            self._rf_session = ort.InferenceSession(str(rf_path), opts)
            self._if_session = ort.InferenceSession(str(if_path), opts)

            scaler_data = json.loads(scaler_path.read_text())
            self._scaler_center = np.array(scaler_data["center"],
                                           dtype=np.float32)
            self._scaler_scale = np.array(scaler_data["scale"],
                                          dtype=np.float32)

            threshold_data = json.loads(threshold_path.read_text())
            self._threshold = float(threshold_data["threshold"])

            self._loaded = True
            logger.info("Loaded 3 ONNX models from %s", model_dir)
        except Exception:
            logger.exception("Failed to load ONNX models from %s", model_dir)

    @property
    def is_loaded(self) -> bool:
        """
        Whether all 3 models are loaded and ready for inference
        """
        return self._loaded

    @property
    def threshold(self) -> float:
        """
        Autoencoder anomaly detection threshold
        """
        return self._threshold

    def predict(self, batch: np.ndarray) -> dict[str, list[float]] | None:
        """
        Run all 3 models on a batch of feature vectors.

        Returns per-model raw scores for ensemble fusion, or None
        if models are not loaded.
        """
        if not self._loaded:
            return None

        ae_input = self._scale_for_ae(batch)
        ae_reconstructed = self._ae_session.run(  # type: ignore[union-attr]
            None, {"features": ae_input})[0]
        ae_errors = np.mean((ae_input - ae_reconstructed)**2, axis=1)

        rf_result = self._rf_session.run(  # type: ignore[union-attr]
            None, {"features": batch})
        rf_proba = self._extract_rf_proba(rf_result[1])

        if_scores_raw = self._if_session.run(  # type: ignore[union-attr]
            None, {"features": batch})[1].flatten()

        return {
            "ae": ae_errors.tolist(),
            "rf": rf_proba.tolist(),
            "if": if_scores_raw.tolist(),
        }

    def _scale_for_ae(self, batch: np.ndarray) -> np.ndarray:
        """
        Apply RobustScaler transform for autoencoder input
        """
        if self._scaler_center is None or self._scaler_scale is None:
            return batch
        return (batch - self._scaler_center) / self._scaler_scale  # type: ignore[no-any-return]

    @staticmethod
    def _extract_rf_proba(
            ort_output: list[Any] | np.ndarray
    ) -> np.ndarray:
        """
        Extract attack probability from skl2onnx RF output format.

        skl2onnx outputs a list of dicts [{0: p0, 1: p1}, ...] for
        probability output.
        """
        if isinstance(ort_output, np.ndarray):
            if ort_output.ndim == 2 and ort_output.shape[1] >= 2:
                return ort_output[:, 1].astype(np.float32)
            return ort_output.flatten().astype(np.float32)

        proba = []
        for row in ort_output:
            if isinstance(row, dict):
                proba.append(float(row.get(1, 0.0)))
            else:
                proba.append(float(row))
        return np.array(proba, dtype=np.float32)
