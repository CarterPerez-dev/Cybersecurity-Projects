"""
©AngelaMos | 2026
websocket.py
"""

import asyncio
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.alerts import ALERTS_CHANNEL
from app.core.redis_manager import redis_manager

logger = logging.getLogger(__name__)

router = APIRouter()


@router.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket) -> None:
    """
    Stream real time threat alerts to connected WebSocket clients
    via Redis pub/sub relay.

    Each client gets its own Redis subscriber so this works correctly
    across multiple FastAPI workers.
    """
    await websocket.accept()

    redis = redis_manager.client
    if redis is None:
        await websocket.close(code=1011, reason="Redis not available")
        return

    pubsub = redis.pubsub()
    await pubsub.subscribe(ALERTS_CHANNEL)

    async def _relay() -> None:
        async for message in pubsub.listen():
            if message["type"] == "message":
                await websocket.send_text(message["data"])

    async def _receive() -> None:
        try:
            while True:
                await websocket.receive()
        except WebSocketDisconnect:
            pass

    relay_task = asyncio.create_task(_relay())
    receive_task = asyncio.create_task(_receive())

    try:
        done, pending = await asyncio.wait(
            [relay_task, receive_task],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
    finally:
        await pubsub.unsubscribe(ALERTS_CHANNEL)
        await pubsub.aclose()  # type: ignore[attr-defined]
        logger.debug("WebSocket client disconnected")
