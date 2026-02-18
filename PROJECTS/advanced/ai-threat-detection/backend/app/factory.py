"""
©AngelaMos | 2026
factory.py
"""

import asyncio
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlmodel import SQLModel

from app.config import settings
from app.core.alerts.dispatcher import AlertDispatcher
from app.core.detection.rules import RuleEngine
from app.core.enrichment.geoip import GeoIPService
from app.core.ingestion.pipeline import Pipeline
from app.core.ingestion.tailer import LogTailer
from app.core.redis_manager import redis_manager
from app.models import model_metadata as _model_metadata_reg  # noqa: F401
from app.models import threat_event as _threat_event_reg  # noqa: F401

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Manage application startup and shutdown lifecycle.
    """
    app.state.startup_time = time.monotonic()
    app.state.pipeline_running = False

    engine = create_async_engine(settings.database_url)
    app.state.db_engine = engine
    app.state.session_factory = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    logger.info("Database tables verified")

    await redis_manager.connect()

    geoip = GeoIPService(settings.geoip_db_path)

    redis_client = redis_manager.client
    assert redis_client is not None

    dispatcher = AlertDispatcher(
        redis_client=redis_client,
        session_factory=app.state.session_factory,
    )

    pipeline = Pipeline(
        redis_client=redis_client,  # type: ignore[arg-type]
        rule_engine=RuleEngine(),
        geoip=geoip,
        on_result=dispatcher.dispatch,
        raw_queue_size=settings.raw_queue_size,
        parsed_queue_size=settings.parsed_queue_size,
        feature_queue_size=settings.feature_queue_size,
        alert_queue_size=settings.alert_queue_size,
    )
    await pipeline.start()

    tailer = None
    log_dir = Path(settings.nginx_log_path).resolve().parent
    if log_dir.is_dir():
        loop = asyncio.get_running_loop()
        tailer = LogTailer(settings.nginx_log_path, pipeline.raw_queue, loop)
        tailer.start()
    else:
        logger.warning("Log directory %s not found — tailer disabled", log_dir)

    app.state.pipeline = pipeline
    app.state.tailer = tailer
    app.state.geoip = geoip
    app.state.pipeline_running = True

    logger.info("AngelusVigil started — pipeline active")

    yield

    app.state.pipeline_running = False
    if tailer is not None:
        tailer.stop()
    await pipeline.stop()
    geoip.close()
    await redis_manager.disconnect()
    await engine.dispose()

    logger.info("AngelusVigil shut down cleanly")


def create_app() -> FastAPI:
    """
    Build and configure the AngelusVigil FastAPI application.
    """
    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        lifespan=lifespan,
    )

    app.state.startup_time = time.monotonic()
    app.state.pipeline_running = False

    from app.api.health import router as health_router
    from app.api.models_api import router as models_router
    from app.api.stats import router as stats_router
    from app.api.threats import router as threats_router
    from app.api.websocket import router as ws_router

    app.include_router(health_router)
    app.include_router(threats_router)
    app.include_router(stats_router)
    app.include_router(models_router)
    app.include_router(ws_router)

    return app
