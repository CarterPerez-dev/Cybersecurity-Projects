"""
ⒸAngelaMos | 2025
Pydantic schemas for SurrealDB responses
"""

from datetime import datetime

from pydantic import BaseModel

from app.core.enums import PresenceStatus, RoomType


class MessageResponse(BaseModel):
    """
    Message response from SurrealDB
    """
    id: str
    room_id: str | None = None
    sender_id: str
    recipient_id: str
    ciphertext: str
    nonce: str
    header: str
    sender_username: str
    created_at: datetime | None = None
    updated_at: datetime | None = None


class RoomResponse(BaseModel):
    """
    Room response from SurrealDB
    """
    id: str
    name: str | None = None
    room_type: RoomType
    created_by: str
    created_at: datetime
    updated_at: datetime
    is_ephemeral: bool = False
    ttl_seconds: int | None = None


class PresenceResponse(BaseModel):
    """
    Presence response from SurrealDB
    """
    id: str
    user_id: str
    room_id: str | None = None
    status: PresenceStatus
    last_seen: datetime
    updated_at: datetime


class LiveQueryUpdate(BaseModel):
    """
    Live query update notification from SurrealDB
    """
    action: str
    result: MessageResponse | PresenceResponse | RoomResponse


class LiveMessageUpdate(BaseModel):
    """
    Live message update notification
    """
    action: str
    result: MessageResponse


class LivePresenceUpdate(BaseModel):
    """
    Live presence update notification
    """
    action: str
    result: PresenceResponse
