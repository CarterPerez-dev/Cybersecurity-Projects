"""
©AngelaMos | 2026
train_autoencoder.py

PyTorch autoencoder training loop with early stopping and
anomaly threshold calibration

train_autoencoder takes normal-only traffic vectors, splits
off a 15% validation set, fits a FeatureScaler (IQR-based)
on training data, builds DataLoaders, and trains a
ThreatAutoencoder (35->24->12->6->12->24->35) using MSE
loss with AdamW optimizer (weight decay 1e-5),
ReduceLROnPlateau scheduler (factor 0.5, patience 5),
gradient clipping at max_norm 1.0, and early stopping
(default patience 10). After training, computes per-sample
reconstruction error on the validation set and sets the
anomaly threshold at the 99.5th percentile. Returns the
trained model, fitted scaler, calibrated threshold, and
train/val loss history

Connects to:
  ml/autoencoder   - ThreatAutoencoder model class
  ml/scaler        - FeatureScaler for input normalization
  ml/orchestrator  - called during pipeline execution
"""

from typing import Any

import numpy as np
import torch
from torch.utils.data import DataLoader, TensorDataset

from ml.autoencoder import ThreatAutoencoder
from ml.scaler import FeatureScaler


def train_autoencoder(
    X_normal: np.ndarray,
    epochs: int = 100,
    batch_size: int = 256,
    lr: float = 1e-3,
    percentile: float = 99.5,
    val_split: float = 0.15,
    patience: int = 10,
) -> dict[str, Any]:
    """
    Train the autoencoder on normal-only traffic and calibrate the
    anomaly detection threshold.
    """
    input_dim = X_normal.shape[1]

    split_idx = int(len(X_normal) * (1 - val_split))
    X_train_raw = X_normal[:split_idx]
    X_val_raw = X_normal[split_idx:]

    scaler = FeatureScaler()
    X_train_scaled = scaler.fit_transform(X_train_raw)
    X_val_scaled = scaler.transform(X_val_raw)

    train_tensor = torch.from_numpy(X_train_scaled)
    val_tensor = torch.from_numpy(X_val_scaled)

    train_loader = DataLoader(
        TensorDataset(train_tensor),
        batch_size=batch_size,
        shuffle=True,
        drop_last=len(train_tensor) > batch_size,
    )

    model = ThreatAutoencoder(input_dim=input_dim)
    optimizer = torch.optim.AdamW(model.parameters(),
                                  lr=lr,
                                  weight_decay=1e-5,
                                  betas=(0.9, 0.999))
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer,
                                                           mode="min",
                                                           factor=0.5,
                                                           patience=5,
                                                           min_lr=1e-6)

    history: dict[str, list[float]] = {"train_loss": [], "val_loss": []}
    best_val_loss = float("inf")
    best_state = None
    epochs_without_improvement = 0

    for _epoch in range(epochs):
        model.train()
        epoch_loss = 0.0
        n_batches = 0

        for (batch, ) in train_loader:
            reconstructed = model(batch)
            loss = torch.nn.functional.mse_loss(reconstructed, batch)
            optimizer.zero_grad()
            loss.backward()  # type: ignore[no-untyped-call]
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            epoch_loss += loss.item()
            n_batches += 1

        avg_train_loss = epoch_loss / max(n_batches, 1)
        history["train_loss"].append(avg_train_loss)

        model.eval()
        with torch.no_grad():
            val_reconstructed = model(val_tensor)
            val_loss = torch.nn.functional.mse_loss(val_reconstructed,
                                                    val_tensor).item()
        history["val_loss"].append(val_loss)

        scheduler.step(val_loss)

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
            epochs_without_improvement = 0
        else:
            epochs_without_improvement += 1

        if epochs_without_improvement >= patience:
            break

    if best_state is not None:
        model.load_state_dict(best_state)

    model.eval()
    with torch.no_grad():
        val_errors = model.compute_reconstruction_error(val_tensor)
    threshold = float(np.percentile(val_errors.numpy(), percentile))

    return {
        "model": model,
        "scaler": scaler,
        "threshold": threshold,
        "history": history,
    }
