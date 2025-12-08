"""
ⒸAngelaMos | 2025
SurrealDB manager with live queries for real time chat features
"""

import asyncio
import logging
from typing import Any
from collections.abc import Callable

from surrealdb import AsyncSurreal

from app.schemas.surreal import (
    LiveMessageUpdate,
    LivePresenceUpdate,
    MessageResponse,
    PresenceResponse,
    RoomResponse,
)
from app.config import DEFAULT_MESSAGE_LIMIT, settings
from app.core.enums import PresenceStatus


logger = logging.getLogger(__name__)


class SurrealDBManager:
    """
    SurrealDB connection manager with live query subscriptions
    """
    def __init__(self) -> None:
        """
        Initialize SurrealDB manager
        """
        self.db: AsyncSurreal | None = None
        self.live_queries: dict[str, str] = {}
        self._connected = False

    async def connect(self) -> None:
        """
        Establish connection to SurrealDB
        """
        if self._connected:
            return

        logger.warning(
            "SurrealDB connecting: URL=%s, NS=%s, DB=%s",
            settings.SURREAL_URL,
            settings.SURREAL_NAMESPACE,
            settings.SURREAL_DATABASE,
        )

        self.db = AsyncSurreal(settings.SURREAL_URL)
        await self.db.connect()

        await self.db.signin(
            {
                "username": settings.SURREAL_USER,
                "password": settings.SURREAL_PASSWORD,
            }
        )

        await self.db.use(
            settings.SURREAL_NAMESPACE,
            settings.SURREAL_DATABASE,
        )

        self._connected = True
        logger.warning(
            "SurrealDB connected successfully to %s/%s",
            settings.SURREAL_NAMESPACE,
            settings.SURREAL_DATABASE,
        )

    async def disconnect(self) -> None:
        """
        Close SurrealDB connection
        """
        if self.db and self._connected:
            await self.db.close()
            self._connected = False
            logger.info("Disconnected from SurrealDB")

    async def ensure_connected(self) -> None:
        """
        Ensure connection is established
        """
        if not self._connected:
            logger.warning("ensure_connected: Connection was lost, reconnecting...")
            await self.connect()
        else:
            logger.warning(
                "ensure_connected: Already connected (id=%s)",
                id(self.db)
            )

    async def _debug_connection_state(self) -> dict[str, Any]:
        """
        Debug helper to check current connection state
        """
        try:
            info_result = await self.db.query("INFO FOR DB")
            rooms_count = await self.db.query("SELECT count() FROM rooms GROUP ALL")
            participants_count = await self.db.query(
                "SELECT count() FROM room_participants GROUP ALL"
            )
            return {
                "db_info": info_result,
                "rooms_count": rooms_count,
                "participants_count": participants_count,
            }
        except Exception as e:
            return {"error": str(e)}

    def _extract_query_result(self, result: Any) -> list[dict[str, Any]]:
        """
        Extract query results from SurrealDB v2 response format

        SDK v2 can return:
        - Direct list of dicts: [{'field': 'value'}, ...]
        - Wrapped result: [{'result': [...]}]
        - Empty list: []
        """
        if not result:
            return []

        if not isinstance(result, list):
            return []

        if len(result) == 0:
            return []

        first_item = result[0]

        if isinstance(first_item, dict):
            if "result" in first_item:
                return first_item["result"] or []
            return result

        if isinstance(first_item, str):
            logger.warning("Query returned string instead of data: %s", first_item)
            return []

        return result

    async def create_message(
        self,
        message_data: dict[str,
                           Any]
    ) -> MessageResponse:
        """
        Create a new message in SurrealDB
        """
        await self.ensure_connected()
        logger.warning("create_message - data: %s", message_data)
        result = await self.db.create("messages", message_data)
        logger.warning("create_message - result: %s", result)
        result["id"] = str(result["id"])
        return MessageResponse(**result)

    async def get_room_messages(
        self,
        room_id: str,
        limit: int = DEFAULT_MESSAGE_LIMIT,
        offset: int = 0,
    ) -> list[MessageResponse]:
        """
        Get messages for a specific room with pagination
        """
        await self.ensure_connected()
        logger.warning("get_room_messages - room_id: %s", room_id)

        all_messages = await self.db.query("SELECT * FROM messages")
        logger.warning("get_room_messages - ALL messages in DB: %s", all_messages)

        query = """
            SELECT * FROM messages
            WHERE room_id = $room_id
            ORDER BY created_at DESC
            LIMIT $limit
            START $offset
        """
        result = await self.db.query(
            query,
            {
                "room_id": room_id,
                "limit": limit,
                "offset": offset,
            }
        )
        logger.warning("get_room_messages - RAW result: %s", result)
        messages = self._extract_query_result(result)
        logger.warning("get_room_messages - extracted messages: %s", messages)
        return [MessageResponse(**msg) for msg in messages]

    async def create_room(self, room_data: dict[str, Any]) -> RoomResponse:
        """
        Create a new chat room
        """
        await self.ensure_connected()
        query = "CREATE rooms CONTENT $data"
        logger.warning("create_room - executing query with data: %s", room_data)

        result = await self.db.query(query, {"data": room_data})
        logger.warning("create_room - RAW result type: %s", type(result))
        logger.warning("create_room - RAW result: %s", result)

        if isinstance(result, list) and len(result) > 0:
            first = result[0]
            logger.info("create_room - first element type: %s, value: %s", type(first), first)

            if isinstance(first, dict):
                if "result" in first and first["result"]:
                    room = first["result"][0] if isinstance(first["result"], list) else first["result"]
                elif "id" in first:
                    room = first
                else:
                    logger.error("create_room - unexpected dict structure: %s", first)
                    raise ValueError(f"Unexpected result structure: {first}")
            elif isinstance(first, list) and len(first) > 0:
                room = first[0]
            else:
                logger.error("create_room - unexpected first element: %s", first)
                raise ValueError(f"Unexpected result: {first}")

            room["id"] = str(room["id"])
            logger.info("create_room - final room: %s", room)
            return RoomResponse(**room)

        logger.error("create_room - no results returned: %s", result)
        raise ValueError(f"Failed to create room, result: {result}")

    async def add_room_participant(
        self,
        room_id: str,
        user_id: str,
        role: str = "member",
    ) -> None:
        """
        Add a participant to a room
        """
        await self.ensure_connected()
        from datetime import UTC, datetime

        query = """
            CREATE room_participants CONTENT {
                room_id: $room_id,
                user_id: $user_id,
                role: $role,
                joined_at: $joined_at
            } RETURN AFTER
        """
        params = {
            "room_id": room_id,
            "user_id": user_id,
            "role": role,
            "joined_at": datetime.now(UTC).isoformat(),
        }
        logger.warning("add_room_participant - params: %s", params)

        result = await self.db.query(query, params)
        logger.warning("add_room_participant result: %s", result)

        verify = await self.db.query("SELECT * FROM room_participants")
        logger.warning("VERIFY ALL room_participants: %s", verify)

        debug_state = await self._debug_connection_state()
        logger.warning("add_room_participant - DB STATE after insert: %s", debug_state)

    async def get_rooms_for_user(self, user_id: str) -> list[dict[str, Any]]:
        """
        Get all rooms a user is a participant of
        """
        await self.ensure_connected()

        debug_state = await self._debug_connection_state()
        logger.warning("get_rooms_for_user - DB STATE: %s", debug_state)

        participants_query = """
            SELECT room_id FROM room_participants WHERE user_id = $user_id
        """
        logger.warning("get_rooms_for_user - fetching participants for user_id: %s", user_id)
        result = await self.db.query(participants_query, {"user_id": user_id})
        logger.warning("get_rooms_for_user - RAW result: %s", result)
        participant_data = self._extract_query_result(result)
        logger.warning("Participant data after extract: %s", participant_data)

        if not participant_data:
            logger.warning("No room_participants found for user %s", user_id)
            return []

        room_ids = [p["room_id"] for p in participant_data if p.get("room_id")]
        logger.info("Room IDs to fetch: %s", room_ids)

        if not room_ids:
            logger.warning("No valid room_ids for user %s", user_id)
            return []

        rooms: list[dict[str, Any]] = []
        for room_id in room_ids:
            try:
                room = await self.db.select(room_id)
                if room:
                    if isinstance(room, list):
                        rooms.extend(room)
                    else:
                        rooms.append(room)
            except Exception as e:
                logger.warning("Failed to fetch room %s: %s", room_id, e)

        logger.info("Fetched %d rooms", len(rooms))
        return rooms

    async def get_room_participants(self, room_id: str) -> list[dict[str, Any]]:
        """
        Get all participants of a room
        """
        await self.ensure_connected()
        query = """
            SELECT * FROM room_participants
            WHERE room_id = $room_id OR room_id = type::string($room_id)
        """
        result = await self.db.query(query, {"room_id": room_id})
        return self._extract_query_result(result)

    async def get_user_rooms(self, user_id: str) -> list[RoomResponse]:
        """
        Get all rooms a user is part of using graph traversal
        """
        await self.ensure_connected()
        query = """
            SELECT ->member_of->rooms.* AS rooms
            FROM $user_id
        """
        result = await self.db.query(query, {"user_id": f"users:`{user_id}`"})
        data = self._extract_query_result(result)
        if data and isinstance(data[0], dict) and data[0].get("rooms"):
            return [RoomResponse(**room) for room in data[0]["rooms"]]
        return []

    async def update_presence(
        self,
        user_id: str,
        status: str,
        last_seen: str,
    ) -> None:
        """
        Update user presence status
        """
        await self.ensure_connected()
        await self.db.merge(
            f"presence:`{user_id}`",
            {
                "user_id": user_id,
                "status": status,
                "last_seen": last_seen,
                "updated_at": "time::now()",
            }
        )

    async def get_room_presence(self, room_id: str) -> list[PresenceResponse]:
        """
        Get presence for all users in a room
        """
        await self.ensure_connected()
        query = f"""
            SELECT ->member_of->rooms->has_members<-presence.* AS users
            FROM $room_id
            WHERE status = '{PresenceStatus.ONLINE.value}'
        """
        result = await self.db.query(query, {"room_id": f"rooms:`{room_id}`"})
        presence_list = self._extract_query_result(result)
        return [PresenceResponse(**p) for p in presence_list]

    async def live_messages(
        self,
        room_id: str,
        callback: Callable[[LiveMessageUpdate],
                           None],
    ) -> str:
        """
        Subscribe to live message updates for a room
        """
        await self.ensure_connected()
        query = f"LIVE SELECT * FROM messages WHERE room_id = '{room_id}'"

        def wrapper(data: dict[str, Any]) -> None:
            update = LiveMessageUpdate(**data)
            callback(update)

        live_id = await self.db.live(query, wrapper)
        self.live_queries[room_id] = live_id
        return live_id

    async def live_messages_for_user(
        self,
        user_id: str,
        callback: Callable[[LiveMessageUpdate],
                           None],
    ) -> str:
        """
        Subscribe to live message updates where user is the recipient
        """
        await self.ensure_connected()
        query = f"LIVE SELECT * FROM messages WHERE recipient_id = '{user_id}'"

        def wrapper(data: dict[str, Any]) -> None:
            update = LiveMessageUpdate(**data)
            callback(update)

        live_id = await self.db.live(query, wrapper)
        self.live_queries[f"user_{user_id}"] = live_id
        return live_id

    async def live_presence(
        self,
        room_id: str,
        callback: Callable[[LivePresenceUpdate],
                           None],
    ) -> str:
        """
        Subscribe to live presence updates for a room
        """
        await self.ensure_connected()
        query = f"LIVE SELECT * FROM presence WHERE room_id = '{room_id}'"

        def wrapper(data: dict[str, Any]) -> None:
            update = LivePresenceUpdate(**data)
            callback(update)

        live_id = await self.db.live(query, wrapper)
        self.live_queries[f"presence_{room_id}"] = live_id
        return live_id

    async def kill_live_query(self, live_id: str) -> None:
        """
        Stop a live query subscription
        """
        await self.ensure_connected()
        await self.db.kill(live_id)

        for key, query_id in list(self.live_queries.items()):
            if query_id == live_id:
                del self.live_queries[key]
                break

    async def create_ephemeral_room(
        self,
        room_data: dict[str,
                        Any],
        ttl_seconds: int,
    ) -> RoomResponse:
        """
        Create an ephemeral room that auto-deletes after TTL
        """
        await self.ensure_connected()
        room = await self.db.create("rooms", room_data)
        room_id = str(room["id"])
        room["id"] = room_id

        asyncio.create_task(self._schedule_room_deletion(room_id, ttl_seconds))
        return RoomResponse(**room)

    async def _schedule_room_deletion(
        self,
        room_id: str,
        ttl_seconds: int
    ) -> None:
        """
        Schedule automatic deletion of a room after TTL
        """
        await asyncio.sleep(ttl_seconds)
        await self.ensure_connected()
        await self.db.delete(room_id)
        logger.info(
            "Deleted ephemeral room %s after %ss TTL",
            room_id,
            ttl_seconds
        )


surreal_db = SurrealDBManager()
