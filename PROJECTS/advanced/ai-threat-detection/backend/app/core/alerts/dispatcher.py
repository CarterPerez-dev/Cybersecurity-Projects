"""
©AngelaMos | 2026
dispatcher.py
"""

import logging

import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.alerts import ALERTS_CHANNEL
from app.core.ingestion.pipeline import ScoredRequest
from app.schemas.websocket import WebSocketAlert
from app.services.threat_service import create_threat_event

logger = logging.getLogger(__name__)


class AlertDispatcher:
    """
    Routes scored threat events to storage, pub/sub, and structured logging.

    MEDIUM+ severity events are persisted to PostgreSQL and published
    to the Redis alerts channel for WebSocket relay.
    All events are logged to stdout.
    """

    def __init__(
        self,
        redis_client: aioredis.Redis[str],
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        self._redis = redis_client
        self._session_factory = session_factory

    async def dispatch(self, scored: ScoredRequest) -> None:
        """
        Handle a scored request from the pipeline's dispatch stage.
        """
        logger.info(
            "threat_event severity=%s score=%.2f ip=%s path=%s rules=%s",
            scored.rule_result.severity,
            scored.rule_result.threat_score,
            scored.entry.ip,
            scored.entry.path,
            scored.rule_result.matched_rules,
        )

        if scored.rule_result.severity in ("HIGH", "MEDIUM"):
            await self._store_event(scored)
            await self._publish_alert(scored)

    async def _store_event(self, scored: ScoredRequest) -> None:
        """
        Persist the scored request as a threat event in PostgreSQL.
        """
        async with self._session_factory() as session:
            await create_threat_event(session, scored)
            await session.commit()

    async def _publish_alert(self, scored: ScoredRequest) -> None:
        """
        Publish a real-time alert to the Redis pub/sub channel.
        """
        alert = WebSocketAlert(
            timestamp=scored.entry.timestamp,
            source_ip=scored.entry.ip,
            request_path=scored.entry.path,
            threat_score=scored.rule_result.threat_score,
            severity=scored.rule_result.severity,
            component_scores=scored.rule_result.component_scores,
        )
        await self._redis.publish(ALERTS_CHANNEL, alert.model_dump_json())
