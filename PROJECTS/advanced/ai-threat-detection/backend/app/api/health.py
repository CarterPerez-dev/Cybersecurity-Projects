"""
©AngelaMos | 2026
health.py
"""

import time

from fastapi import APIRouter, Request, Response
from sqlalchemy import text

from app.core.redis_manager import redis_manager

router = APIRouter()


@router.get("/health")
async def health(request: Request) -> dict[str, object]:
    """
    Liveness probe — returns 200 if the process is alive.
    """
    uptime = time.monotonic() - request.app.state.startup_time
    return {
        "status": "healthy",
        "uptime_seconds": round(uptime, 2),
        "pipeline_running": request.app.state.pipeline_running,
    }


@router.get("/ready")
async def ready(request: Request, response: Response) -> dict[str, object]:
    """
    Readiness probe — checks all service dependencies.
    """
    redis_ok = await _check_redis()
    database_ok = await _check_database(request)

    checks = {
        "database": "ok" if database_ok else "error",
        "redis": "ok" if redis_ok else "error",
        "models_loaded": getattr(request.app.state, "models_loaded", False),
    }

    all_ok = database_ok and redis_ok

    if not all_ok:
        response.status_code = 503

    return {
        "status": "ready" if all_ok else "not_ready",
        "checks": checks,
    }


async def _check_redis() -> bool:
    """
    Ping Redis and return connectivity status.
    """
    return await redis_manager.ping()


async def _check_database(request: Request) -> bool:
    """
    Verify database engine is connected and responsive.
    """
    engine = getattr(request.app.state, "db_engine", None)
    if engine is None:
        return False
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
