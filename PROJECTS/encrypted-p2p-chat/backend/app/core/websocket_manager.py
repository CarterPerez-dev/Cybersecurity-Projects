"""
ⒸAngelaMos | 2025
WebSocket connection manager for real time messaging
"""

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import WebSocket

from app.config import (
    WS_HEARTBEAT_INTERVAL,
    WS_MAX_CONNECTIONS_PER_USER,
)
from app.core.surreal_manager import surreal_db
from app.schemas.surreal import LiveMessageUpdate
from app.schemas.websocket import (
    EncryptedMessageWS,
    ErrorMessageWS,
    WSHeartbeat,
)
from app.services.presence_service import presence_service


logger = logging.getLogger(__name__)


class ConnectionManager:
    """
    Manages WebSocket connections and message broadcasting
    """
    def __init__(self) -> None:
        """
        Initialize connection manager with empty connection pool
        """
        self.active_connections: dict[UUID, list[WebSocket]] = {}
        self.live_query_ids: dict[UUID, str] = {}
        self.heartbeat_tasks: dict[UUID, asyncio.Task] = {}

    async def connect(self, websocket: WebSocket, user_id: UUID) -> bool:
        """
        Accept WebSocket connection and register user
        """
        await websocket.accept()

        if user_id not in self.active_connections:
            self.active_connections[user_id] = []

        if len(self.active_connections[user_id]) >= WS_MAX_CONNECTIONS_PER_USER:
            logger.warning(
                "User %s exceeded max connections (%s)",
                user_id,
                WS_MAX_CONNECTIONS_PER_USER
            )
            await self._send_error(
                websocket,
                "max_connections",
                f"Maximum {WS_MAX_CONNECTIONS_PER_USER} connections per user"
            )
            await websocket.close()
            return False

        self.active_connections[user_id].append(websocket)
        logger.info(
            "User %s connected via WebSocket (total: %s)",
            user_id,
            len(self.active_connections[user_id])
        )

        try:
            await presence_service.set_user_online(user_id)
        except Exception as e:
            logger.error("Failed to set user %s online: %s", user_id, e)
            await self._send_error(
                websocket,
                "database_error",
                "Failed to initialize connection"
            )
            self.active_connections[user_id].remove(websocket)
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]
            await websocket.close()
            return False

        self.heartbeat_tasks[user_id] = asyncio.create_task(
            self._heartbeat_loop(websocket,
                                 user_id)
        )

        await self._subscribe_to_messages(user_id)

        return True

    async def disconnect(self, websocket: WebSocket, user_id: UUID) -> None:
        """
        Remove WebSocket connection and cleanup resources
        """
        if user_id in self.active_connections:
            if websocket in self.active_connections[user_id]:
                self.active_connections[user_id].remove(websocket)

            if not self.active_connections[user_id]:
                del self.active_connections[user_id]

                await presence_service.set_user_offline(user_id)

                if user_id in self.live_query_ids:
                    try:
                        await surreal_db.kill_live_query(
                            self.live_query_ids[user_id]
                        )
                    except Exception as e:
                        logger.error(
                            "Failed to kill live query for %s: %s",
                            user_id,
                            e
                        )
                    del self.live_query_ids[user_id]

                if user_id in self.heartbeat_tasks:
                    self.heartbeat_tasks[user_id].cancel()
                    del self.heartbeat_tasks[user_id]

                logger.info("User %s fully disconnected", user_id)
            else:
                logger.info(
                    "User %s connection closed (remaining: %s)",
                    user_id,
                    len(self.active_connections[user_id])
                )

    async def send_message(self, user_id: UUID, message: dict[str, Any]) -> None:
        """
        Send message to all connections for a specific user
        """
        if user_id not in self.active_connections:
            logger.debug("User %s not connected, cannot send message", user_id)
            return

        dead_connections = []

        for websocket in self.active_connections[user_id]:
            try:
                await websocket.send_json(message)
            except Exception as e:
                logger.error("Failed to send message to %s: %s", user_id, e)
                dead_connections.append(websocket)

        for dead_ws in dead_connections:
            await self.disconnect(dead_ws, user_id)

    async def broadcast_to_room(
        self,
        room_id: str,
        message: dict[str,
                      Any]
    ) -> None:
        """
        Broadcast message to all users in a room
        """
        online_users = await presence_service.get_room_online_users(room_id)

        for user_presence in online_users:
            try:
                user_id = UUID(user_presence["user_id"])
                await self.send_message(user_id, message)
            except Exception as e:
                logger.error(
                    "Failed to broadcast to user %s: %s",
                    user_presence['user_id'],
                    e
                )

    async def _heartbeat_loop(self, websocket: WebSocket, user_id: UUID) -> None:
        """
        Send periodic heartbeat pings to keep connection alive
        """
        try:
            while True:
                await asyncio.sleep(WS_HEARTBEAT_INTERVAL)

                if user_id not in self.active_connections:
                    break

                if websocket not in self.active_connections[user_id]:
                    break

                heartbeat = WSHeartbeat(timestamp = datetime.now(UTC))

                try:
                    await websocket.send_json(heartbeat.model_dump(mode = "json"))
                    await presence_service.update_last_seen(user_id)
                except Exception as e:
                    logger.error("Heartbeat failed for user %s: %s", user_id, e)
                    await self.disconnect(websocket, user_id)
                    break
        except asyncio.CancelledError:
            logger.debug("Heartbeat task cancelled for user %s", user_id)

    async def _subscribe_to_messages(self, user_id: UUID) -> None:
        """
        Subscribe to live message updates for the user
        """
        try:

            def message_callback(update: LiveMessageUpdate) -> None:
                """
                Handle incoming message from SurrealDB live query
                """
                asyncio.create_task(self._handle_live_message(user_id, update))

            live_id = await surreal_db.live_messages_for_user(
                user_id = str(user_id),
                callback = message_callback
            )

            self.live_query_ids[user_id] = live_id
            logger.debug("Subscribed to live messages for user %s", user_id)
        except Exception as e:
            logger.error("Failed to subscribe to messages for %s: %s", user_id, e)

    async def _handle_live_message(
        self,
        user_id: UUID,
        update: LiveMessageUpdate
    ) -> None:
        """
        Process live message update and forward to WebSocket
        """
        if update.action != "CREATE":
            return

        message_data = update.result

        ws_message = EncryptedMessageWS(
            message_id = message_data.id,
            sender_id = message_data.sender_id,
            recipient_id = str(user_id),
            room_id = message_data.room_id or "",
            content = "[Encrypted message - requires decryption]",
            ciphertext = message_data.ciphertext,
            nonce = message_data.nonce,
            header = message_data.header,
            sender_username = message_data.sender_username,
            timestamp = message_data.created_at
        )

        await self.send_message(user_id, ws_message.model_dump(mode = "json"))

    async def _send_error(
        self,
        websocket: WebSocket,
        error_code: str,
        error_message: str
    ) -> None:
        """
        Send error message to WebSocket connection
        """
        error = ErrorMessageWS(
            error_code = error_code,
            error_message = error_message,
            timestamp = datetime.now(UTC)
        )

        try:
            await websocket.send_json(error.model_dump(mode = "json"))
        except Exception as e:
            logger.error("Failed to send error message: %s", e)

    def get_active_users(self) -> list[UUID]:
        """
        Get list of all currently connected user IDs
        """
        return list(self.active_connections.keys())

    def get_connection_count(self, user_id: UUID) -> int:
        """
        Get number of active connections for a user
        """
        if user_id not in self.active_connections:
            return 0
        return len(self.active_connections[user_id])

    def is_user_connected(self, user_id: UUID) -> bool:
        """
        Check if user has any active connections
        """
        return user_id in self.active_connections and len(
            self.active_connections[user_id]
        ) > 0


connection_manager = ConnectionManager()
