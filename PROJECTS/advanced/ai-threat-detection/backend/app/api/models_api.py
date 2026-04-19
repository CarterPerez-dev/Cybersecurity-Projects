"""
©AngelaMos | 2026
models_api.py

ML model status and retraining endpoints

GET /models/status returns models_loaded flag, detection
_mode (hybrid or rules), and active model metadata from
the database. POST /models/retrain acquires _retrain_lock
(returning 409 if already running), dispatches a
background retraining job that loads stored ThreatEvents,
labels them using review_label or score thresholds
(SCORE_ATTACK_THRESHOLD 0.5, SCORE_NORMAL_CEILING 0.3),
supplements with synthetic data if below MIN_TRAINING_
SAMPLES (200), runs TrainingOrchestrator, and writes
model metadata. _fallback_synthetic spawns a subprocess
CLI train command with lifecycle tracking via
_synthetic_process

Connects to:
  config.py              - settings.model_dir, ensemble
                            weights
  models/model_metadata  - ModelMetadata queries
  models/threat_event    - ThreatEvent training data
  ml/orchestrator        - TrainingOrchestrator
  ml/synthetic           - generate_mixed_dataset
  cli/main               - _write_metadata
"""

import asyncio
import logging
import subprocess
import uuid

from fastapi import APIRouter, BackgroundTasks, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import settings
from app.models.model_metadata import ModelMetadata
from app.models.threat_event import ThreatEvent

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/models", tags=["models"])

SCORE_ATTACK_THRESHOLD = 0.5
SCORE_NORMAL_CEILING = 0.3
MIN_TRAINING_SAMPLES = 200
SYNTHETIC_SUPPLEMENT_NORMAL = 500
SYNTHETIC_SUPPLEMENT_ATTACK = 250

_retrain_lock = asyncio.Lock()
_synthetic_process: subprocess.Popen[bytes] | None = None


@router.get("/status")
async def model_status(request: Request) -> dict[str, object]:
    """
    Return the status of active ML models
    """
    models_loaded = getattr(request.app.state, "models_loaded", False)
    detection_mode = getattr(request.app.state, "detection_mode", "rules")

    active_models: list[dict[str, object]] = []
    session_factory = getattr(request.app.state, "session_factory", None)
    if session_factory is not None:
        async with session_factory() as session:
            active_models = await _get_active_models(session)

    return {
        "models_loaded": models_loaded,
        "detection_mode": detection_mode,
        "active_models": active_models,
    }


@router.post("/retrain", status_code=202, response_model=None)
async def retrain(
    request: Request,
    background_tasks: BackgroundTasks,
) -> dict[str, object] | Response:
    """
    Dispatch a model retraining job using real stored
    threat events supplemented with synthetic data
    """
    if _retrain_lock.locked():
        return JSONResponse(
            status_code=409,
            content={"status": "conflict", "job_id": ""},
        )

    session_factory = getattr(request.app.state, "session_factory", None)
    if session_factory is None:
        return {"status": "error", "job_id": ""}

    job_id = uuid.uuid4().hex
    background_tasks.add_task(
        _retrain_from_db,
        job_id,
        session_factory,
    )
    return {"status": "accepted", "job_id": job_id}


async def _retrain_from_db(
    job_id: str,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """
    Pull stored threat events, build training arrays,
    supplement with synthetic data if needed, and run
    the full training pipeline
    """
    import dataclasses
    from pathlib import Path

    import numpy as np

    from ml.orchestrator import TrainingOrchestrator

    async with _retrain_lock:
        logger.info("Retrain job %s: loading stored events", job_id)

        async with session_factory() as session:
            count = (await session.execute(
                select(func.count()).select_from(ThreatEvent)
            )).scalar_one()

            if count == 0:
                logger.warning(
                    "Retrain job %s: no stored events, "
                    "using synthetic only",
                    job_id,
                )
                _fallback_synthetic(job_id)
                return

            rows = (await session.execute(
                select(ThreatEvent)
            )).scalars().all()

        vectors: list[list[float]] = []
        labels: list[int] = []

        for event in rows:
            if not event.feature_vector:
                continue

            if event.reviewed and event.review_label:
                label = (
                    1 if event.review_label == "true_positive"
                    else 0
                )
            elif event.threat_score >= SCORE_ATTACK_THRESHOLD:
                label = 1
            elif event.threat_score < SCORE_NORMAL_CEILING:
                label = 0
            else:
                continue

            vectors.append(event.feature_vector)
            labels.append(label)

        logger.info(
            "Retrain job %s: %d usable events from DB "
            "(normal=%d, attack=%d)",
            job_id,
            len(vectors),
            labels.count(0),
            labels.count(1),
        )

        from ml.synthetic import generate_mixed_dataset

        if len(vectors) < MIN_TRAINING_SAMPLES:
            syn_X, syn_y = generate_mixed_dataset(
                SYNTHETIC_SUPPLEMENT_NORMAL,
                SYNTHETIC_SUPPLEMENT_ATTACK,
            )
            X = np.concatenate([
                np.array(vectors, dtype=np.float32),
                syn_X,
            ]) if vectors else syn_X
            y = np.concatenate([
                np.array(labels, dtype=np.int32),
                syn_y,
            ]) if labels else syn_y
            logger.info(
                "Retrain job %s: supplemented with "
                "%d synthetic samples",
                job_id,
                len(syn_X),
            )
        else:
            X = np.array(vectors, dtype=np.float32)
            y = np.array(labels, dtype=np.int32)

        output_dir = Path(settings.model_dir)
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            lambda: TrainingOrchestrator(
                output_dir=output_dir,
            ).run(X, y),
        )

        logger.info(
            "Retrain job %s complete: passed_gates=%s",
            job_id,
            result.passed_gates,
        )

        try:
            from cli.main import _write_metadata

            metrics: dict[str, object] = (
                dataclasses.asdict(result.ensemble_metrics)
                if result.ensemble_metrics else {}
            )
            await _write_metadata(
                output_dir,
                len(X),
                metrics,
                result.mlflow_run_id,
                result.ae_metrics.get("ae_threshold"),
            )
        except Exception:
            logger.exception(
                "Retrain job %s: failed to write metadata",
                job_id,
            )


def _fallback_synthetic(job_id: str) -> None:
    """
    Run training with synthetic data only when no real
    events exist
    """
    global _synthetic_process  # noqa: PLW0603
    import sys

    if _synthetic_process is not None:
        if _synthetic_process.poll() is None:
            logger.info(
                "Retrain job %s: synthetic training already "
                "running (pid=%d)",
                job_id,
                _synthetic_process.pid,
            )
            return
        rc = _synthetic_process.returncode
        if rc != 0:
            logger.warning(
                "Previous synthetic training exited with %d",
                rc,
            )

    logger.info(
        "Retrain job %s: falling back to synthetic training",
        job_id,
    )
    _synthetic_process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "cli.main",
            "train",
            "--synthetic-normal",
            "1000",
            "--synthetic-attack",
            "500",
        ],
        start_new_session=True,
    )


async def _get_active_models(
    session: AsyncSession,
) -> list[dict[str, object]]:
    """
    Query all active model metadata records
    """
    query = select(ModelMetadata).where(
        ModelMetadata.is_active == True  # type: ignore[arg-type]  # noqa: E712
    )
    rows = (await session.execute(query)).scalars().all()
    return [{
        "model_type": row.model_type,
        "version": row.version,
        "training_samples": row.training_samples,
        "metrics": row.metrics,
        "threshold": row.threshold,
    } for row in rows]
