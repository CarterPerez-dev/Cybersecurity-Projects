"""
ⒸAngelaMos | 2025
Pydantic schemas for WebSocket message types
"""

from typing import Any
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.config import (
    ENCRYPTED_CONTENT_MAX_LENGTH,
    MESSAGE_ID_MAX_LENGTH,
)


class BaseWSMessage(BaseModel):
    """
    Base WebSocket message with common fields
    """
    type: str
    timestamp: datetime | None = None


class EncryptedMessageWS(BaseWSMessage):
    """
    Encrypted message sent over WebSocket
    """
    type: str = "encrypted_message"
    message_id: str = Field(max_length = MESSAGE_ID_MAX_LENGTH)
    sender_id: str
    recipient_id: str
    room_id: str
    content: str = ""
    ciphertext: str = Field(max_length = ENCRYPTED_CONTENT_MAX_LENGTH)
    nonce: str
    header: str
    sender_username: str


class TypingIndicatorWS(BaseWSMessage):
    """
    Typing indicator message
    """
    type: str = "typing"
    user_id: str
    room_id: str
    is_typing: bool


class PresenceUpdateWS(BaseWSMessage):
    """
    User presence update message
    """
    type: str = "presence"
    user_id: str
    status: str
    last_seen: datetime


class ReadReceiptWS(BaseWSMessage):
    """
    Message read receipt
    """
    type: str = "receipt"
    message_id: str = Field(max_length = MESSAGE_ID_MAX_LENGTH)
    user_id: str
    read_at: datetime


class ErrorMessageWS(BaseWSMessage):
    """
    Error message sent over WebSocket
    """
    type: str = "error"
    error_code: str
    error_message: str
    details: dict[str, Any] | None = None


class WSConnectionRequest(BaseModel):
    """
    WebSocket connection request with auth token
    """
    user_id: UUID
    token: str | None = None


class WSHeartbeat(BaseModel):
    """
    WebSocket heartbeat ping/pong message
    """
    type: str = "heartbeat"
    timestamp: datetime


class RoomCreatedWS(BaseModel):
    """
    Room created notification sent over WebSocket
    """
    type: str = "room_created"
    room_id: str
    room_type: str
    name: str | None
    participants: list[dict[str, Any]]
    is_encrypted: bool
    created_at: str
    updated_at: str


class MessageSentWS(BaseWSMessage):
    """
    Confirmation sent back to sender after message is stored
    """
    type: str = "message_sent"
    temp_id: str
    message_id: str
    room_id: str
    status: str = "sent"
    created_at: datetime
