"""
©AngelaMos | 2026
test_export_onnx.py

Tests ONNX export and inference parity for the autoencoder,
random forest, and isolation forest models

TestAutoencoderExport validates file creation, PyTorch-to-
ONNX output match within 1e-5 tolerance, and dynamic batch
dimension (1, 16, 64). TestRandomForestExport validates
file creation and ONNX inference returning class predictions
and probabilities. TestIsolationForestExport validates file
creation and ONNX anomaly scores matching sklearn
decision_function within 1e-4 tolerance

Connects to:
  ml/export_onnx  - export_autoencoder,
                    export_random_forest,
                    export_isolation_forest
  ml/autoencoder  - ThreatAutoencoder for AE export
"""

from pathlib import Path

import numpy as np
import onnxruntime as ort
import torch
from sklearn.ensemble import IsolationForest, RandomForestClassifier

from ml.autoencoder import ThreatAutoencoder
from ml.export_onnx import (
    export_autoencoder,
    export_isolation_forest,
    export_random_forest,
)


class TestAutoencoderExport:

    def test_creates_onnx_file(self, tmp_path: Path) -> None:
        """
        Exporting creates a non-empty .onnx file at the given path.
        """
        model = ThreatAutoencoder(input_dim=35)
        path = export_autoencoder(model, tmp_path / "ae.onnx")
        assert path.exists()
        assert path.stat().st_size > 0

    def test_onnx_output_matches_pytorch(self, tmp_path: Path) -> None:
        """
        ONNX inference output matches PyTorch forward pass within 1e-5 tolerance.
        """
        torch.manual_seed(42)
        model = ThreatAutoencoder(input_dim=35)
        model.eval()
        onnx_path = export_autoencoder(model, tmp_path / "ae.onnx")

        rng = np.random.default_rng(42)
        x = rng.standard_normal((8, 35)).astype(np.float32)

        with torch.no_grad():
            pt_out = model(torch.from_numpy(x)).numpy()

        session = ort.InferenceSession(str(onnx_path))
        ort_out = session.run(None, {"features": x})[0]

        np.testing.assert_allclose(pt_out, ort_out, atol=1e-5)

    def test_dynamic_batch_dimension(self, tmp_path: Path) -> None:
        """
        Exported model accepts variable batch sizes (1, 16, 64).
        """
        model = ThreatAutoencoder(input_dim=35)
        model.eval()
        onnx_path = export_autoencoder(model, tmp_path / "ae.onnx")
        session = ort.InferenceSession(str(onnx_path))

        for batch_size in (1, 16, 64):
            rng = np.random.default_rng(batch_size)
            x = rng.standard_normal((batch_size, 35)).astype(np.float32)
            out = session.run(None, {"features": x})[0]
            assert out.shape == (batch_size, 35)


class TestRandomForestExport:

    def test_creates_onnx_file(self, tmp_path: Path) -> None:
        """
        Exporting a fitted RandomForest creates a non-empty .onnx file.
        """
        rng = np.random.default_rng(42)
        rf = RandomForestClassifier(n_estimators=10, random_state=42)
        X = rng.standard_normal((100, 35)).astype(np.float32)
        y = np.concatenate([np.zeros(70, dtype=int), np.ones(30, dtype=int)])
        rf.fit(X, y)
        path = export_random_forest(rf, 35, tmp_path / "rf.onnx")
        assert path.exists()
        assert path.stat().st_size > 0

    def test_onnx_produces_valid_output(self, tmp_path: Path) -> None:
        """
        ONNX inference returns class predictions and probabilities for each sample.
        """
        rng = np.random.default_rng(42)
        rf = RandomForestClassifier(n_estimators=10, random_state=42)
        X = rng.standard_normal((100, 35)).astype(np.float32)
        y = np.concatenate([np.zeros(70, dtype=int), np.ones(30, dtype=int)])
        rf.fit(X, y)
        onnx_path = export_random_forest(rf, 35, tmp_path / "rf.onnx")
        session = ort.InferenceSession(str(onnx_path))

        x_test = rng.standard_normal((5, 35)).astype(np.float32)
        result = session.run(None, {"features": x_test})
        assert len(result) == 2
        assert len(result[0]) == 5


class TestIsolationForestExport:

    def test_creates_onnx_file(self, tmp_path: Path) -> None:
        """
        Exporting a fitted IsolationForest creates a non-empty .onnx file.
        """
        rng = np.random.default_rng(42)
        iso = IsolationForest(n_estimators=10, random_state=42)
        iso.fit(rng.standard_normal((100, 35)).astype(np.float32))
        path = export_isolation_forest(iso, 35, tmp_path / "if.onnx")
        assert path.exists()
        assert path.stat().st_size > 0

    def test_onnx_scores_match_decision_function(self, tmp_path: Path) -> None:
        """
        ONNX anomaly scores match sklearn decision_function within 1e-4 tolerance.
        """
        rng = np.random.default_rng(42)
        iso = IsolationForest(n_estimators=10, random_state=42)
        X = rng.standard_normal((100, 35)).astype(np.float32)
        iso.fit(X)
        onnx_path = export_isolation_forest(iso, 35, tmp_path / "if.onnx")
        session = ort.InferenceSession(str(onnx_path))

        x_test = rng.standard_normal((10, 35)).astype(np.float32)
        sk_decision = iso.decision_function(x_test)
        ort_scores = session.run(None, {"features": x_test})[1].flatten()

        np.testing.assert_allclose(sk_decision, ort_scores, atol=1e-4)
