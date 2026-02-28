"""
©AngelaMos | 2026
orchestrator.py
"""

import json
import logging
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from ml.experiment import VigilExperiment
from ml.export_onnx import (
    export_autoencoder,
    export_isolation_forest,
    export_random_forest,
)
from ml.splitting import prepare_training_data
from ml.train_autoencoder import train_autoencoder
from ml.train_classifiers import (
    train_isolation_forest,
    train_random_forest,
)
from ml.validation import ValidationResult, validate_ensemble

logger = logging.getLogger(__name__)

N_FEATURES = 35

AE_FILENAME = "ae.onnx"
RF_FILENAME = "rf.onnx"
IF_FILENAME = "if.onnx"
SCALER_FILENAME = "scaler.json"
THRESHOLD_FILENAME = "threshold.json"


@dataclass
class TrainingResult:
    """
    Aggregated results from a full training pipeline run
    """

    ae_metrics: dict[str, float]
    rf_metrics: dict[str, float]
    if_metrics: dict[str, float]
    ensemble_metrics: ValidationResult | None
    passed_gates: bool
    output_dir: Path
    mlflow_run_id: str | None


class TrainingOrchestrator:
    """
    End-to-end training pipeline that splits data, trains all 3 models,
    exports to ONNX, validates the ensemble, and logs to MLflow
    """

    def __init__(
        self,
        output_dir: Path,
        experiment_name: str = "angelusvigil-training",
        epochs: int = 100,
        batch_size: int = 256,
    ) -> None:
        self._output_dir = output_dir
        self._experiment_name = experiment_name
        self._epochs = epochs
        self._batch_size = batch_size

    def run(
        self,
        X: np.ndarray,
        y: np.ndarray,
    ) -> TrainingResult:
        """
        Execute the full training pipeline
        """
        self._output_dir.mkdir(parents=True, exist_ok=True)

        split = prepare_training_data(X, y)

        logger.info(
            "Split: train=%d val=%d test=%d normal_train=%d",
            len(split.X_train),
            len(split.X_val),
            len(split.X_test),
            len(split.X_normal_train),
        )

        with VigilExperiment(
            self._experiment_name
        ) as experiment:
            experiment.log_params({
                "epochs": self._epochs,
                "batch_size": self._batch_size,
                "n_samples": len(X),
                "n_attack": int(np.sum(y == 1)),
                "n_normal": int(np.sum(y == 0)),
                "n_features": X.shape[1],
            })

            ae_result = self._train_ae(
                split.X_normal_train
            )
            ae_metrics = {
                "ae_threshold": ae_result["threshold"],
                "ae_final_train_loss": ae_result[
                    "history"
                ]["train_loss"][-1],
                "ae_final_val_loss": ae_result[
                    "history"
                ]["val_loss"][-1],
            }

            rf_result = self._train_rf(
                split.X_train, split.y_train
            )
            rf_metrics = rf_result["metrics"]

            if_result = self._train_if(
                split.X_normal_train
            )
            if_metrics = if_result["metrics"]

            self._export_models(
                ae_result, rf_result, if_result
            )

            experiment.log_metrics(ae_metrics)
            experiment.log_metrics(
                {f"rf_{k}": v for k, v in rf_metrics.items()}
            )

            try:
                ensemble = validate_ensemble(
                    self._output_dir,
                    split.X_test,
                    split.y_test,
                )
                experiment.log_metrics({
                    "ensemble_precision": ensemble.precision,
                    "ensemble_recall": ensemble.recall,
                    "ensemble_f1": ensemble.f1,
                    "ensemble_pr_auc": ensemble.pr_auc,
                    "ensemble_roc_auc": ensemble.roc_auc,
                })
                passed = ensemble.passed_gates
            except Exception:
                logger.exception("Ensemble validation failed")
                ensemble = None
                passed = False

            for artifact in self._output_dir.iterdir():
                experiment.log_artifact(artifact)

            run_id = experiment.run_id

        logger.info(
            "Training complete: passed_gates=%s run_id=%s",
            passed,
            run_id,
        )

        return TrainingResult(
            ae_metrics=ae_metrics,
            rf_metrics=rf_metrics,
            if_metrics=if_metrics,
            ensemble_metrics=ensemble,
            passed_gates=passed,
            output_dir=self._output_dir,
            mlflow_run_id=run_id,
        )

    def _train_ae(
        self, X_normal: np.ndarray
    ) -> dict:
        """
        Train the autoencoder on normal-only data
        """
        logger.info(
            "Training autoencoder (%d epochs, %d samples)",
            self._epochs,
            len(X_normal),
        )
        return train_autoencoder(
            X_normal,
            epochs=self._epochs,
            batch_size=self._batch_size,
        )

    def _train_rf(
        self, X: np.ndarray, y: np.ndarray
    ) -> dict:
        """
        Train the random forest classifier
        """
        logger.info(
            "Training random forest (%d samples)",
            len(X),
        )
        return train_random_forest(X, y)

    def _train_if(
        self, X_normal: np.ndarray
    ) -> dict:
        """
        Train the isolation forest on normal-only data
        """
        logger.info(
            "Training isolation forest (%d samples)",
            len(X_normal),
        )
        return train_isolation_forest(X_normal)

    def _export_models(
        self,
        ae_result: dict,
        rf_result: dict,
        if_result: dict,
    ) -> None:
        """
        Export all 3 models to ONNX and save scaler/threshold
        """
        export_autoencoder(
            ae_result["model"],
            self._output_dir / AE_FILENAME,
        )
        ae_result["scaler"].save_json(
            self._output_dir / SCALER_FILENAME
        )
        threshold_data = {
            "threshold": ae_result["threshold"]
        }
        (self._output_dir / THRESHOLD_FILENAME).write_text(
            json.dumps(threshold_data, indent=2)
        )

        export_random_forest(
            rf_result["model"],
            N_FEATURES,
            self._output_dir / RF_FILENAME,
        )

        export_isolation_forest(
            if_result["model"],
            N_FEATURES,
            self._output_dir / IF_FILENAME,
        )

        logger.info(
            "Exported models to %s", self._output_dir
        )
