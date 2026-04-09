"""
©AngelaMos | 2026
test_autoencoder.py

Tests the ThreatAutoencoder PyTorch architecture for shape
correctness, output range, reconstruction error, and
training behavior

Validates output shape matches input (batch, 35), encoder
bottleneck compresses to 6 dimensions, single-sample
forward pass succeeds in eval mode, decoder output is
unbounded (matching RobustScaler range), reconstruction
error returns one positive scalar per sample, trained model
reconstructs normal data better than anomalies after 50
epochs, eval mode produces deterministic output (dropout
off), and variable batch sizes (1, 8, 32, 128) are handled

Connects to:
  ml/autoencoder - ThreatAutoencoder
"""

import pytest
import torch

from ml.autoencoder import ThreatAutoencoder


class TestAutoencoderArchitecture:

    def test_output_shape_matches_input(self) -> None:
        """
        Forward pass on a batch of 16 produces output matching input shape.
        """
        model = ThreatAutoencoder(input_dim=35)
        x = torch.randn(16, 35)
        out = model(x)
        assert out.shape == (16, 35)

    def test_bottleneck_dim_is_six(self) -> None:
        """
        Encoder bottleneck compresses 35 features to a 6-dimensional latent vector.
        """
        model = ThreatAutoencoder(input_dim=35)
        x = torch.randn(4, 35)
        encoded = model.encode(x)
        assert encoded.shape == (4, 6)

    def test_single_sample_forward(self) -> None:
        """
        Single-sample forward pass completes without error in eval mode.
        """
        model = ThreatAutoencoder(input_dim=35)
        model.eval()
        x = torch.randn(1, 35)
        with torch.no_grad():
            out = model(x)
        assert out.shape == (1, 35)

    def test_output_is_unbounded(self) -> None:
        """
        Decoder output is unbounded to match RobustScaler-transformed input range.
        """
        model = ThreatAutoencoder(input_dim=35)
        model.eval()
        x = torch.randn(64, 35) * 3.0
        with torch.no_grad():
            out = model(x)
        assert out.shape == (64, 35)
        assert out.min().item() < 0.0 or out.max().item() > 1.0

    def test_reconstruction_error_shape(self) -> None:
        """
        compute_reconstruction_error returns one scalar per sample in the batch.
        """
        model = ThreatAutoencoder(input_dim=35)
        model.eval()
        x = torch.randn(8, 35)
        with torch.no_grad():
            errors = model.compute_reconstruction_error(x)
        assert errors.shape == (8, )

    def test_reconstruction_error_positive(self) -> None:
        """
        Reconstruction error is non-negative for all samples.
        """
        model = ThreatAutoencoder(input_dim=35)
        model.eval()
        x = torch.randn(8, 35)
        with torch.no_grad():
            errors = model.compute_reconstruction_error(x)
        assert (errors >= 0.0).all()

    def test_trained_model_reconstructs_normal_better_than_anomaly(
            self) -> None:
        """
        After training on normal data, reconstruction error is lower for normals than anomalies.
        """
        torch.manual_seed(42)
        model = ThreatAutoencoder(input_dim=35)
        optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)

        normal_data = torch.randn(500, 35) * 0.5 + 0.5
        normal_data = normal_data.clamp(0, 1)

        model.train()
        for _ in range(50):
            out = model(normal_data)
            loss = torch.nn.functional.mse_loss(out, normal_data)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

        model.eval()
        with torch.no_grad():
            normal_errors = model.compute_reconstruction_error(
                normal_data[:50])
            anomaly_data = torch.rand(50, 35) * 3.0 - 1.0
            anomaly_errors = model.compute_reconstruction_error(anomaly_data)

        assert anomaly_errors.mean() > normal_errors.mean()

    def test_eval_mode_disables_dropout(self) -> None:
        """
        Identical inputs produce identical outputs in eval mode (dropout is off).
        """
        model = ThreatAutoencoder(input_dim=35)
        model.eval()
        x = torch.randn(4, 35)
        with torch.no_grad():
            out1 = model(x)
            out2 = model(x)
        assert torch.allclose(out1, out2)

    @pytest.mark.parametrize("batch_size", [1, 8, 32, 128])
    def test_variable_batch_sizes(self, batch_size: int) -> None:
        """
        Output shape matches input for batch sizes 1, 8, 32, and 128.
        """
        model = ThreatAutoencoder(input_dim=35)
        model.eval()
        x = torch.randn(batch_size, 35)
        with torch.no_grad():
            out = model(x)
        assert out.shape == (batch_size, 35)
