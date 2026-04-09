"""
©AngelaMos | 2026
experiment.py

MLflow experiment context manager with automatic system
metadata logging

VigilExperiment wraps mlflow.start_run/end_run as a context
manager, recording Python version, platform, and git commit
hash on entry, and setting status/error tags on exit.
Provides log_params, log_metrics (with optional step), and
log_artifact convenience methods. _get_git_hash shells out
to git rev-parse --short HEAD

Connects to:
  ml/orchestrator  - used to wrap the full training run
"""

import platform
import subprocess
import sys
from pathlib import Path
from types import TracebackType

import mlflow


class VigilExperiment:
    """
    Context manager wrapping MLflow experiment runs
    with automatic system metadata logging
    """

    def __init__(self, experiment_name: str) -> None:
        self._experiment_name = experiment_name
        self._run: mlflow.ActiveRun | None = None
        self._run_id: str | None = None

    @property
    def run_id(self) -> str | None:
        """
        The MLflow run ID, set after entering context
        """
        return self._run_id

    def __enter__(self) -> VigilExperiment:
        mlflow.set_experiment(self._experiment_name)
        self._run = mlflow.start_run()
        self._run_id = self._run.info.run_id
        self._log_system_metadata()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if exc_type is not None:
            mlflow.set_tag("status", "failed")
            mlflow.set_tag("error", str(exc_val)[:500])
        else:
            mlflow.set_tag("status", "completed")
        mlflow.end_run()
        self._run = None

    def log_params(self, params: dict[str, object]) -> None:
        """
        Log a dictionary of parameters to the active run
        """
        mlflow.log_params(params)

    def log_metrics(
        self,
        metrics: dict[str, float],
        step: int | None = None,
    ) -> None:
        """
        Log a dictionary of metrics to the active run
        """
        mlflow.log_metrics(metrics, step=step)

    def log_artifact(self, path: Path | str) -> None:
        """
        Log a local file as an artifact
        """
        mlflow.log_artifact(str(path))

    def _log_system_metadata(self) -> None:
        """
        Record Python version and git commit hash
        """
        mlflow.set_tag("python_version", sys.version.split()[0])
        mlflow.set_tag("platform", platform.system())

        git_hash = _get_git_hash()
        if git_hash is not None:
            mlflow.set_tag("git_commit", git_hash)


def _get_git_hash() -> str | None:
    """
    Return the short git commit hash or None
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except FileNotFoundError:
        pass
    return None
