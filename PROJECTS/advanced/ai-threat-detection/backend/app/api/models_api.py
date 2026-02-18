"""
©AngelaMos | 2026
models_api.py
"""

import uuid

from fastapi import APIRouter

router = APIRouter(prefix="/models", tags=["models"])


@router.get("/status")
async def model_status() -> dict[str, object]:
    """
    Return the status of active ML models.
    """
    return {
        "active_models": [],
        "detection_mode": "rules-only",
        "note": "ML models available after Phase 2 training",
    }


@router.post("/retrain", status_code=202)
async def retrain() -> dict[str, object]:
    """
    Trigger an async model retraining job.
    """
    return {
        "status": "accepted",
        "job_id": uuid.uuid4().hex,
        "note": "Retraining not available in Phase 1",
    }
