"""
©AngelaMos | 2026
rooms.py
"""

import logging
from collections.abc import Iterable
from datetime import UTC, datetime
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.config import (
    DEFAULT_MESSAGE_LIMIT,
    MAX_MESSAGE_LIMIT,
)
from app.core.dependencies import current_user
from app.core.enums import RoomType
from app.core.surreal_manager import surreal_db
from app.core.websocket_manager import connection_manager
from app.models.Base import get_session
from app.models.User import User
from app.schemas.rooms import (
    CreateRoomRequest,
    ParticipantResponse,
    RoomAPIResponse,
    RoomListResponse,
)
from app.schemas.websocket import RoomCreatedWS


logger = logging.getLogger(__name__)

router = APIRouter(prefix = "/rooms", tags = ["rooms"])


async def _hydrate_users(
    session: AsyncSession,
    user_ids: Iterable[str],
) -> dict[str,
          User]:
    """
    Bulk fetch users by id and return a mapping keyed by string uuid
    """
    unique_ids: list[UUID] = []
    seen: set[str] = set()
    for raw in user_ids:
        if not raw or raw in seen:
            continue
        try:
            unique_ids.append(UUID(raw))
            seen.add(raw)
        except ValueError:
            continue

    if not unique_ids:
        return {}

    statement = select(User).where(User.id.in_(unique_ids))
    result = await session.execute(statement)
    rows = result.scalars().all()
    return {str(u.id): u for u in rows}


def _build_participants(
    raw_participants: list[dict],
    users_by_id: dict[str,
                      User],
) -> list[ParticipantResponse]:
    """
    Translate SurrealDB participant rows into API response models
    """
    out: list[ParticipantResponse] = []
    for row in raw_participants:
        uid = row.get("user_id")
        if not uid:
            continue
        user = users_by_id.get(str(uid))
        if user is None:
            continue
        out.append(
            ParticipantResponse(
                user_id = str(user.id),
                username = user.username,
                display_name = user.display_name,
                role = row.get("role",
                               "member"),
                joined_at = str(row.get("joined_at",
                                        "")),
            )
        )
    return out


@router.post("", status_code = status.HTTP_201_CREATED)
async def create_room(
    body: CreateRoomRequest,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> RoomAPIResponse:
    """
    Create a new chat room with the current user as owner
    """
    try:
        participant_uuid = UUID(body.participant_id)
    except ValueError as exc:
        raise HTTPException(
            status_code = status.HTTP_400_BAD_REQUEST,
            detail = "participant_id must be a valid UUID",
        ) from exc

    if participant_uuid == user.id:
        raise HTTPException(
            status_code = status.HTTP_400_BAD_REQUEST,
            detail = "Cannot start a conversation with yourself",
        )

    statement = select(User).where(User.id == participant_uuid)
    result = await session.execute(statement)
    participant = result.scalar_one_or_none()
    if participant is None:
        raise HTTPException(
            status_code = status.HTTP_404_NOT_FOUND,
            detail = "Participant not found",
        )

    now = datetime.now(UTC)
    room_data = {
        "name": None,
        "room_type": body.room_type.value,
        "created_by": str(user.id),
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "is_ephemeral": body.room_type == RoomType.EPHEMERAL,
    }

    room = await surreal_db.create_room(room_data)
    await surreal_db.add_room_participant(room.id, str(user.id), "owner")
    await surreal_db.add_room_participant(room.id, str(participant.id), "member")

    participants_list = [
        ParticipantResponse(
            user_id = str(user.id),
            username = user.username,
            display_name = user.display_name,
            role = "owner",
            joined_at = now.isoformat(),
        ),
        ParticipantResponse(
            user_id = str(participant.id),
            username = participant.username,
            display_name = participant.display_name,
            role = "member",
            joined_at = now.isoformat(),
        ),
    ]

    notification = RoomCreatedWS(
        room_id = room.id,
        room_type = room.room_type.value,
        name = user.display_name,
        participants = [p.model_dump() for p in participants_list],
        is_encrypted = True,
        created_at = room.created_at.isoformat(),
        updated_at = room.updated_at.isoformat(),
    )
    await connection_manager.send_message(
        participant.id,
        notification.model_dump(mode = "json"),
    )

    logger.info(
        "Created room %s with creator %s and participant %s",
        room.id,
        user.id,
        participant.id,
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
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> RoomListResponse:
    """
    List rooms in which the current user is a participant
    """
    room_data_list = await surreal_db.get_rooms_for_user(str(user.id))

    all_participant_rows: list[list[dict]] = []
    user_ids: list[str] = []

    for room_data in room_data_list:
        if not room_data:
            all_participant_rows.append([])
            continue
        room_id = str(room_data.get("id", ""))
        rows = await surreal_db.get_room_participants(room_id)
        all_participant_rows.append(rows)
        for row in rows:
            uid = row.get("user_id")
            if uid:
                user_ids.append(str(uid))

    users_by_id = await _hydrate_users(session, user_ids)

    rooms: list[RoomAPIResponse] = []
    for room_data, raw_participants in zip(
        room_data_list, all_participant_rows, strict = False
    ):
        if not room_data:
            continue
        room_id = str(room_data.get("id", ""))
        participants = _build_participants(raw_participants, users_by_id)
        other_participant = next(
            (p for p in participants if p.user_id != str(user.id)),
            None,
        )
        room_name = (other_participant.display_name if other_participant else None)

        rooms.append(
            RoomAPIResponse(
                id = room_id,
                type = RoomType(room_data.get("room_type",
                                              "direct")),
                name = room_name,
                participants = participants,
                unread_count = 0,
                is_encrypted = True,
                created_at = str(room_data.get("created_at",
                                               "")),
                updated_at = str(room_data.get("updated_at",
                                               "")),
            )
        )

    return RoomListResponse(rooms = rooms)


async def _require_membership(
    room_id: str,
    user: User,
) -> None:
    """
    Ensure the current user is a member of the room
    """
    is_member = await surreal_db.is_room_participant(room_id, str(user.id))
    if not is_member:
        raise HTTPException(
            status_code = status.HTTP_403_FORBIDDEN,
            detail = "Not a member of this room",
        )


@router.get("/{room_id}", status_code = status.HTTP_200_OK)
async def get_room(
    room_id: str,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> RoomAPIResponse:
    """
    Return a single room the current user belongs to
    """
    await _require_membership(room_id, user)

    room_data = await surreal_db.get_room(room_id)
    if not room_data:
        raise HTTPException(
            status_code = status.HTTP_404_NOT_FOUND,
            detail = "Room not found",
        )

    raw_participants = await surreal_db.get_room_participants(room_id)
    users_by_id = await _hydrate_users(
        session,
        (row.get("user_id") for row in raw_participants)
    )
    participants = _build_participants(raw_participants, users_by_id)

    other_participant = next(
        (p for p in participants if p.user_id != str(user.id)),
        None,
    )
    room_name = other_participant.display_name if other_participant else None

    created_at = room_data.get("created_at")
    updated_at = room_data.get("updated_at")

    return RoomAPIResponse(
        id = str(room_data.get("id",
                               room_id)),
        type = RoomType(room_data.get("room_type",
                                      "direct")),
        name = room_name,
        participants = participants,
        unread_count = 0,
        is_encrypted = True,
        created_at = (
            created_at.isoformat() if hasattr(created_at,
                                              "isoformat") else str(created_at or "")
        ),
        updated_at = (
            updated_at.isoformat() if hasattr(updated_at,
                                              "isoformat") else str(updated_at or "")
        ),
    )


@router.get("/{room_id}/messages", status_code = status.HTTP_200_OK)
async def get_room_messages(
    room_id: str,
    user: User = Depends(current_user),
    limit: int = DEFAULT_MESSAGE_LIMIT,
    offset: int = 0,
) -> dict:
    """
    Return ciphertext messages for a room visible to the current user
    """
    await _require_membership(room_id, user)
    bounded_limit = max(1, min(limit, MAX_MESSAGE_LIMIT))
    messages = await surreal_db.get_room_messages(room_id, bounded_limit, offset)
    return {
        "messages": [msg.model_dump(mode = "json") for msg in messages],
        "has_more": len(messages) == bounded_limit,
    }


@router.delete("/{room_id}", status_code = status.HTTP_204_NO_CONTENT)
async def delete_room(
    room_id: str,
    user: User = Depends(current_user),
) -> None:
    """
    Delete a room owned by the current user along with its messages
    """
    raw_participants = await surreal_db.get_room_participants(room_id)
    if not raw_participants:
        raise HTTPException(
            status_code = status.HTTP_404_NOT_FOUND,
            detail = "Room not found",
        )

    is_owner = any(
        str(row.get("user_id")) == str(user.id) and row.get("role") == "owner"
        for row in raw_participants
    )
    if not is_owner:
        raise HTTPException(
            status_code = status.HTTP_403_FORBIDDEN,
            detail = "Only the room owner can delete it",
        )

    await surreal_db.delete_room(room_id)
    logger.info("Deleted room %s by user %s", room_id, user.id)
