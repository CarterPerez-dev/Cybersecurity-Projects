"""
ⒸAngelaMos | 2025
WebSocket service for handling real time message routing and processing
"""

import logging
from typing import Any
from uuid import UUID
from datetime import UTC, datetime

from fastapi import WebSocket

from app.config import (
    WS_MESSAGE_TYPE_ENCRYPTED,
    WS_MESSAGE_TYPE_PRESENCE,
    WS_MESSAGE_TYPE_RECEIPT,
    WS_MESSAGE_TYPE_TYPING,
)
from app.core.enums import PresenceStatus
from app.core.websocket_manager import connection_manager
from app.schemas.websocket import (
    EncryptedMessageWS,
    MessageSentWS,
    ReadReceiptWS,
    TypingIndicatorWS,
)
from app.models.Base import async_session_maker
from app.services.message_service import message_service
from app.services.presence_service import presence_service


logger = logging.getLogger(__name__)


class WebSocketService:
    """
    Service for processing WebSocket
    messages and routing to appropriate handlers
    """
    async def route_message(
        self,
        websocket: WebSocket,
        user_id: UUID,
        message: dict[str,
                      Any]
    ) -> None:
        """
        Route incoming WebSocket message
        to appropriate handler based on type
        """
        message_type = message.get("type")

        if not message_type:
            await websocket.send_json(
                {
                    "type": "error",
                    "error_code": "missing_type",
                    "error_message": "Message type is required"
                }
            )
            return

        if message_type == WS_MESSAGE_TYPE_ENCRYPTED:
            await self.handle_encrypted_message(user_id, message)
        elif message_type == WS_MESSAGE_TYPE_TYPING:
            await self.handle_typing_indicator(user_id, message)
        elif message_type == WS_MESSAGE_TYPE_PRESENCE:
            await self.handle_presence_update(user_id, message)
        elif message_type == WS_MESSAGE_TYPE_RECEIPT:
            await self.handle_read_receipt(user_id, message)
        elif message_type == "heartbeat":
            await self.handle_heartbeat(user_id)
        else:
            logger.warning(
                "Unknown message type from %s: %s",
                user_id,
                message_type
            )
            await websocket.send_json(
                {
                    "type": "error",
                    "error_code": "unknown_type",
                    "error_message": f"Unknown message type: {message_type}"
                }
            )

    async def handle_encrypted_message(
        self,
        user_id: UUID,
        message: dict[str,
                      Any]
    ) -> None:
        """
        Process client-encrypted message and forward to recipient (pass-through)
        """
        try:
            recipient_id = UUID(message.get("recipient_id"))
            room_id = message.get("room_id")
            ciphertext = message.get("ciphertext")
            nonce = message.get("nonce")
            header = message.get("header")
            temp_id = message.get("temp_id", "")

            if not ciphertext or not nonce or not header:
                logger.error("Missing encryption fields in message from %s", user_id)
                return

            if not room_id:
                logger.error("Missing room_id in message from %s", user_id)
                return

            async with async_session_maker() as session:
                result = await message_service.store_encrypted_message(
                    session,
                    user_id,
                    recipient_id,
                    ciphertext,
                    nonce,
                    header,
                    room_id,
                )

            ws_message = EncryptedMessageWS(
                message_id = result.id if hasattr(result, 'id') else "unknown",
                sender_id = str(user_id),
                recipient_id = str(recipient_id),
                room_id = room_id,
                content = "",
                ciphertext = ciphertext,
                nonce = nonce,
                header = header,
                sender_username = result.sender_username if hasattr(result, 'sender_username') else ""
            )

            is_recipient_connected = connection_manager.is_user_connected(recipient_id)
            logger.debug(
                "Sending to recipient %s - connected: %s",
                recipient_id,
                is_recipient_connected
            )

            await connection_manager.send_message(
                recipient_id,
                ws_message.model_dump(mode = "json")
            )
            logger.debug("Message sent to recipient %s", recipient_id)

            confirmation = MessageSentWS(
                temp_id = temp_id,
                message_id = result.id if hasattr(result, 'id') else "unknown",
                room_id = room_id,
                status = "sent",
                created_at = result.created_at if hasattr(result, 'created_at') else datetime.now(UTC)
            )

            await connection_manager.send_message(
                user_id,
                confirmation.model_dump(mode = "json")
            )

            logger.info(
                "Encrypted message forwarded: %s -> %s in room %s",
                user_id,
                recipient_id,
                room_id
            )

        except ValueError as e:
            logger.error(
                "Invalid UUID in encrypted message from %s: %s",
                user_id,
                e
            )
        except Exception as e:
            logger.error(
                "Failed to handle encrypted message from %s: %s",
                user_id,
                e
            )

    async def handle_typing_indicator(
        self,
        user_id: UUID,
        message: dict[str,
                      Any]
    ) -> None:
        """
        Process typing indicator and broadcast to room
        """
        try:
            room_id = message.get("room_id")
            is_typing = message.get("is_typing", False)

            if not room_id:
                logger.error(
                    "Missing room_id in typing indicator from %s",
                    user_id
                )
                return

            typing_msg = TypingIndicatorWS(
                user_id = str(user_id),
                room_id = room_id,
                is_typing = is_typing
            )

            await connection_manager.broadcast_to_room(
                room_id,
                typing_msg.model_dump(mode = "json")
            )

            logger.debug(
                "Typing indicator broadcast: %s in %s = %s",
                user_id,
                room_id,
                is_typing
            )

        except Exception as e:
            logger.error(
                "Failed to handle typing indicator from %s: %s",
                user_id,
                e
            )

    async def handle_presence_update(
        self,
        user_id: UUID,
        message: dict[str,
                      Any]
    ) -> None:
        """
        Process presence status update from client
        """
        try:
            status = message.get("status")

            if not status:
                logger.error("Missing status in presence update from %s", user_id)
                return

            try:
                presence_status = PresenceStatus(status)
            except ValueError:
                logger.warning(
                    "Invalid presence status from %s: %s",
                    user_id,
                    status
                )
                return

            if presence_status == PresenceStatus.ONLINE:
                await presence_service.set_user_online(user_id)
            elif presence_status == PresenceStatus.AWAY:
                await presence_service.set_user_away(user_id)
            elif presence_status == PresenceStatus.OFFLINE:
                await presence_service.set_user_offline(user_id)

            logger.debug(
                "Presence updated: %s -> %s",
                user_id,
                presence_status.value
            )

        except Exception as e:
            logger.error(
                "Failed to handle presence update from %s: %s",
                user_id,
                e
            )

    async def handle_read_receipt(
        self,
        user_id: UUID,
        message: dict[str,
                      Any]
    ) -> None:
        """
        Process read receipt and notify message sender
        """
        try:
            message_id = message.get("message_id")
            sender_id_str = message.get("sender_id")

            if not message_id or not sender_id_str:
                logger.error(
                    "Missing message_id or sender_id in receipt from %s",
                    user_id
                )
                return

            sender_id = UUID(sender_id_str)

            receipt_msg = ReadReceiptWS(
                message_id = message_id,
                user_id = str(user_id),
                read_at = datetime.now(UTC)
            )

            await connection_manager.send_message(
                sender_id,
                receipt_msg.model_dump(mode = "json")
            )

            logger.debug(
                "Read receipt sent: message %s read by %s",
                message_id,
                user_id
            )

        except ValueError as e:
            logger.error("Invalid UUID in read receipt from %s: %s", user_id, e)
        except Exception as e:
            logger.error("Failed to handle read receipt from %s: %s", user_id, e)

    async def handle_heartbeat(self, user_id: UUID) -> None:
        """
        Process heartbeat message and update user last seen
        """
        logger.debug("Heartbeat received from user %s", user_id)
        await presence_service.update_last_seen(user_id)


websocket_service = WebSocketService()
