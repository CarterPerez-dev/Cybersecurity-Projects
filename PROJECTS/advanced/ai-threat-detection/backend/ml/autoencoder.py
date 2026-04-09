"""
©AngelaMos | 2026
autoencoder.py

PyTorch symmetric autoencoder for HTTP request anomaly
detection

ThreatAutoencoder has a 35->24->12->6 encoder and 6->12
->24->35 decoder with BatchNorm1d, LeakyReLU(0.2), and
Dropout(0.2) between each linear layer. Trained on normal
traffic only so that high reconstruction error (compute_
reconstruction_error via per-sample MSE) indicates
anomalous requests. encode/decode expose bottleneck access
for analysis

Connects to:
  ml/export_onnx     - exported to ae.onnx
  ml/orchestrator    - trained in _train_autoencoder
  ml/scaler          - input normalized before training
"""

import torch
from torch import Tensor, nn


class ThreatAutoencoder(nn.Module):
    """
    Symmetric autoencoder for HTTP request anomaly detection.

    Architecture (35-dim input):
        Encoder: 35 → 24 → 12 → 6 (bottleneck)
        Decoder: 6 → 12 → 24 → 35

    Trained on normal traffic only. High reconstruction error
    indicates an anomalous (potentially malicious) request.
    """

    def __init__(self, input_dim: int = 35) -> None:
        super().__init__()
        self.input_dim = input_dim

        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 24),
            nn.BatchNorm1d(24),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.2),
            nn.Linear(24, 12),
            nn.BatchNorm1d(12),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.2),
            nn.Linear(12, 6),
        )

        self.decoder = nn.Sequential(
            nn.Linear(6, 12),
            nn.BatchNorm1d(12),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.2),
            nn.Linear(12, 24),
            nn.BatchNorm1d(24),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.2),
            nn.Linear(24, input_dim),
        )

    def encode(self, x: Tensor) -> Tensor:
        """
        Compress input through the encoder to the 6-dim bottleneck.
        """
        return self.encoder(x)  # type: ignore[no-any-return]

    def decode(self, z: Tensor) -> Tensor:
        """
        Reconstruct input from the bottleneck representation.
        """
        return self.decoder(z)  # type: ignore[no-any-return]

    def forward(self, x: Tensor) -> Tensor:
        """
        Full forward pass: encode then decode.
        """
        return self.decode(self.encode(x))

    def compute_reconstruction_error(self, x: Tensor) -> Tensor:
        """
        Per-sample mean squared error between input and reconstruction.
        """
        reconstructed = self.forward(x)
        return torch.mean((x - reconstructed)**2, dim=1)
