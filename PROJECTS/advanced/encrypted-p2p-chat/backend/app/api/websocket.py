"""
ⒸAngelaMos | 2025
WebSocket endpoints for real time chat communication
"""

import json
import logging
from uuid import UUID

from fastapi import (
    APIRouter,
    WebSocket,
    WebSocketDisconnect,
    Query,
)
from app.core.websocket_manager import connection_manager
from app.services.websocket_service import websocket_service


logger = logging.getLogger(__name__)

router = APIRouter(prefix = "/ws", tags = ["websocket"])


@router.websocket("")
async def websocket_endpoint(
    websocket: WebSocket,
    user_id: str = Query(...),
) -> None:
    """
    Main WebSocket endpoint for real time messaging
    """
    try:
        user_uuid = UUID(user_id)
    except ValueError:
        logger.error("Invalid user_id format: %s", user_id)
        await websocket.close(code = 1008, reason = "Invalid user ID")
        return

    connected = await connection_manager.connect(websocket, user_uuid)

    if not connected:
        return

    try:
        while True:
            data = await websocket.receive_text()

            try:
                message = json.loads(data)
                await websocket_service.route_message(
                    websocket,
                    user_uuid,
                    message
                )
            except json.JSONDecodeError:
                logger.error(
                    "Invalid JSON from user %s: %s",
                    user_uuid,
                    data[: 100]
                )
                await websocket.send_json(
                    {
                        "type": "error",
                        "error_code": "invalid_json",
                        "error_message": "Invalid JSON format"
                    }
                )
            except Exception as e:
                logger.error("Error handling message from %s: %s", user_uuid, e)
                await websocket.send_json(
                    {
                        "type": "error",
                        "error_code": "processing_error",
                        "error_message": str(e)
                    }
                )

    except WebSocketDisconnect:
        logger.info("WebSocket disconnected for user %s", user_uuid)
    except Exception as e:
        logger.error("WebSocket error for user %s: %s", user_uuid, e)
    finally:
        await connection_manager.disconnect(websocket, user_uuid)
