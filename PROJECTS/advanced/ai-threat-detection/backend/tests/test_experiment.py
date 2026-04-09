"""
©AngelaMos | 2026
test_experiment.py

Tests the VigilExperiment MLflow context manager for run
lifecycle, parameter/metric logging, and status tagging

Uses a tmp_path MLflow tracking URI for isolation.
Validates run ID is set on context entry and None before,
log_params writes string values, log_metrics stores floats,
log_artifact uploads files to the artifact list,
python_version and platform system metadata tags are auto-
logged, successful exit tags status='completed', and
exception exit tags status='failed' with the error message

Connects to:
  ml/experiment - VigilExperiment
"""

from pathlib import Path

import mlflow
import pytest

from ml.experiment import VigilExperiment


@pytest.fixture(autouse=True)
def _mlflow_tmp(tmp_path: Path) -> None:
    """
    Point MLflow at a temp directory for isolation
    """
    mlflow.set_tracking_uri(f"file:{tmp_path}/mlruns")


class TestVigilExperiment:

    def test_creates_run_with_id(self) -> None:
        """
        Entering the context manager creates an MLflow run with a non-None run ID.
        """
        with VigilExperiment("test-exp") as exp:
            assert exp.run_id is not None

    def test_run_id_is_none_before_enter(self) -> None:
        """
        run_id is None until the context manager is entered.
        """
        exp = VigilExperiment("test-exp")
        assert exp.run_id is None

    def test_log_params(self) -> None:
        """
        log_params writes key-value pairs to the MLflow run as strings.
        """
        with VigilExperiment("test-exp") as exp:
            exp.log_params({"lr": 0.001, "epochs": 10})
            run = mlflow.get_run(exp.run_id)
            assert run.data.params["lr"] == "0.001"
            assert run.data.params["epochs"] == "10"

    def test_log_metrics(self) -> None:
        """
        log_metrics stores numeric values on the MLflow run.
        """
        with VigilExperiment("test-exp") as exp:
            exp.log_metrics({"f1": 0.95, "loss": 0.02})
            run = mlflow.get_run(exp.run_id)
            assert run.data.metrics["f1"] == 0.95

    def test_log_artifact(self, tmp_path: Path) -> None:
        """
        log_artifact uploads a file so it appears in the run's artifact list.
        """
        artifact = tmp_path / "dummy.txt"
        artifact.write_text("test content")
        with VigilExperiment("test-exp") as exp:
            exp.log_artifact(artifact)
            run_id = exp.run_id
        client = mlflow.MlflowClient()
        artifacts = client.list_artifacts(run_id)
        names = [a.path for a in artifacts]
        assert "dummy.txt" in names

    def test_system_metadata_logged(self) -> None:
        """
        python_version and platform tags are added automatically on run start.
        """
        with VigilExperiment("test-exp") as exp:
            run = mlflow.get_run(exp.run_id)
            assert "python_version" in run.data.tags
            assert "platform" in run.data.tags

    def test_completed_status_on_success(self) -> None:
        """
        Run tagged with status='completed' when the context exits cleanly.
        """
        with VigilExperiment("test-exp") as exp:
            run_id = exp.run_id
        run = mlflow.get_run(run_id)
        assert run.data.tags["status"] == "completed"

    def test_failed_status_on_exception(self) -> None:
        """
        Run tagged with status='failed' and error message when an exception is raised.
        """
        run_id = None
        with pytest.raises(ValueError), VigilExperiment("test-exp") as exp:
            run_id = exp.run_id
            raise ValueError("boom")
        run = mlflow.get_run(run_id)
        assert run.data.tags["status"] == "failed"
        assert "boom" in run.data.tags["error"]
