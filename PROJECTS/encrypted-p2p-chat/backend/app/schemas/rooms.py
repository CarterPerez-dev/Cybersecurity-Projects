"""
ⒸAngelaMos | 2025
Pydantic schemas for rooms API
"""

from pydantic import BaseModel

from app.core.enums import RoomType


class CreateRoomRequest(BaseModel):
    """
    Request to create a new room
    """
    creator_id: str
    participant_id: str
    room_type: RoomType = RoomType.DIRECT


class ParticipantResponse(BaseModel):
    """
    Participant in a room
    """
    user_id: str
    username: str
    display_name: str
    role: str = "member"
    joined_at: str


class RoomAPIResponse(BaseModel):
    """
    Room response for API
    """
    id: str
    type: RoomType
    name: str | None = None
    participants: list[ParticipantResponse]
    unread_count: int = 0
    is_encrypted: bool = True
    created_at: str
    updated_at: str


class RoomListResponse(BaseModel):
    """
    List of rooms response
    """
    rooms: list[RoomAPIResponse]
