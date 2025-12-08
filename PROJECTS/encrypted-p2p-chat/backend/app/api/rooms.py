"""
ⒸAngelaMos | 2025
Rooms API for creating and managing chat rooms
"""

import logging
from uuid import UUID
from datetime import UTC, datetime

from fastapi import (
    APIRouter, 
    Depends, 
    HTTPException, 
    status,
)
from sqlmodel.ext.asyncio.session import AsyncSession

from app.schemas.rooms import (
    CreateRoomRequest,
    ParticipantResponse,
    RoomAPIResponse,
    RoomListResponse,
)
from app.schemas.websocket import RoomCreatedWS
from app.core.enums import RoomType
from app.models.Base import get_session
from app.core.surreal_manager import surreal_db
from app.core.websocket_manager import connection_manager
from app.services.auth_service import auth_service


logger = logging.getLogger(__name__)


router = APIRouter(prefix = "/rooms", tags = ["rooms"])


@router.post("", status_code = status.HTTP_201_CREATED)
async def create_room(
    request: CreateRoomRequest,
    session: AsyncSession = Depends(get_session),
) -> RoomAPIResponse:
    """
    Create a new chat room
    """
    creator = await auth_service.get_user_by_id(
        session,
        UUID(request.creator_id),
    )

    if not creator:
        raise HTTPException(
            status_code = status.HTTP_404_NOT_FOUND,
            detail = "Creator not found",
        )

    participant = await auth_service.get_user_by_id(
        session,
        UUID(request.participant_id),
    )

    if not participant:
        raise HTTPException(
            status_code = status.HTTP_404_NOT_FOUND,
            detail = "Participant not found",
        )

    now = datetime.now(UTC)

    room_data = {
        "name": None,
        "room_type": request.room_type.value,
        "created_by": request.creator_id,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "is_ephemeral": request.room_type == RoomType.EPHEMERAL,
    }

    room = await surreal_db.create_room(room_data)

    await surreal_db.add_room_participant(room.id, request.creator_id, "owner")
    await surreal_db.add_room_participant(room.id, request.participant_id, "member")

    logger.info(
        "Created room %s with creator %s and participant %s",
        room.id,
        request.creator_id,
        request.participant_id,
    )

    participants_list = [
        ParticipantResponse(
            user_id = str(creator.id),
            username = creator.username,
            display_name = creator.display_name,
            role = "owner",
            joined_at = now.isoformat(),
        ),
        ParticipantResponse(
            user_id = str(participant.id),
            username = participant.username,
            display_name = participant.display_name,
            role = "member",
            joined_at = now.isoformat(),
        )
    ]

    room_ws_notification = RoomCreatedWS(
        room_id = room.id,
        room_type = room.room_type.value,
        name = creator.display_name,
        participants = [p.model_dump() for p in participants_list],
        is_encrypted = True,
        created_at = room.created_at.isoformat(),
        updated_at = room.updated_at.isoformat(),
    )

    await connection_manager.send_message(
        UUID(request.participant_id),
        room_ws_notification.model_dump(mode = "json"),
    )

    return RoomAPIResponse(
        id = room.id,
        type = RoomType(room.room_type),
        name = participant.display_name,
        participants = participants_list,
        unread_count = 0,
        is_encrypted = True,
        created_at = room.created_at.isoformat(),
        updated_at = room.updated_at.isoformat(),
    )


@router.get("", status_code = status.HTTP_200_OK)
async def list_rooms(
    user_id: str,
    session: AsyncSession = Depends(get_session),
) -> RoomListResponse:
    """
    List all rooms for the specified user
    """
    logger.info("list_rooms called for user_id: %s", user_id)

    user = await auth_service.get_user_by_id(session, UUID(user_id))

    if not user:
        raise HTTPException(
            status_code = status.HTTP_404_NOT_FOUND,
            detail = "User not found",
        )

    room_data_list = await surreal_db.get_rooms_for_user(user_id)
    logger.info("SurrealDB returned %d rooms for user %s", len(room_data_list), user_id)
    logger.info("Room data: %s", room_data_list)

    rooms: list[RoomAPIResponse] = []

    for room_data in room_data_list:
        if not room_data:
            continue

        room_id = str(room_data.get("id", ""))
        participants_data = await surreal_db.get_room_participants(room_id)

        participants: list[ParticipantResponse] = []

        for p_data in participants_data:
            p_user_id = p_data.get("user_id")
            if not p_user_id:
                continue

            p_user = await auth_service.get_user_by_id(session, UUID(p_user_id))
            if p_user:
                participants.append(
                    ParticipantResponse(
                        user_id = str(p_user.id),
                        username = p_user.username,
                        display_name = p_user.display_name,
                        role = p_data.get("role", "member"),
                        joined_at = str(p_data.get("joined_at", "")),
                    )
                )

        other_participant = next(
            (p for p in participants if p.user_id != user_id),
            None
        )
        room_name = other_participant.display_name if other_participant else None

        rooms.append(
            RoomAPIResponse(
                id = room_id,
                type = RoomType(room_data.get("room_type", "direct")),
                name = room_name,
                participants = participants,
                unread_count = 0,
                is_encrypted = True,
                created_at = str(room_data.get("created_at", "")),
                updated_at = str(room_data.get("updated_at", "")),
            )
        )

    return RoomListResponse(rooms = rooms)


@router.get("/{room_id}", status_code = status.HTTP_200_OK)
async def get_room(room_id: str) -> RoomAPIResponse:
    """
    Get a specific room
    """
    raise HTTPException(
        status_code = status.HTTP_404_NOT_FOUND,
        detail = "Room not found",
    )


@router.get("/{room_id}/messages", status_code = status.HTTP_200_OK)
async def get_room_messages(
    room_id: str,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """
    Get messages for a specific room
    """
    messages = await surreal_db.get_room_messages(room_id, limit, offset)
    return {
        "messages": [msg.model_dump(mode = "json") for msg in messages],
        "has_more": len(messages) == limit
    }


@router.delete("/{room_id}", status_code = status.HTTP_204_NO_CONTENT)
async def delete_room(room_id: str) -> None:
    """
    Delete a room
    """
    raise HTTPException(
        status_code = status.HTTP_404_NOT_FOUND,
        detail = "Room not found",
    )


