"""
ⒸAngelaMos | 2025
Presence service for managing user online/offline status
"""

import logging
from datetime import UTC, datetime
from uuid import UUID

from app.core.enums import PresenceStatus
from app.core.exceptions import DatabaseError
from app.core.surreal_manager import surreal_db


logger = logging.getLogger(__name__)


class PresenceService:
    """
    Service for managing user presence status in real time
    """
    async def set_user_online(self, user_id: UUID) -> None:
        """
        Mark user as online and update last seen timestamp
        """
        try:
            await surreal_db.update_presence(
                user_id = str(user_id),
                status = PresenceStatus.ONLINE.value,
                last_seen = datetime.now(UTC).isoformat()
            )
            logger.info("User %s is now online", user_id)
        except Exception as e:
            logger.error("Failed to set user %s online: %s", user_id, e)
            raise DatabaseError(f"Failed to update presence: {str(e)}") from e

    async def set_user_offline(self, user_id: UUID) -> None:
        """
        Mark user as offline and update last seen timestamp
        """
        try:
            await surreal_db.update_presence(
                user_id = str(user_id),
                status = PresenceStatus.OFFLINE.value,
                last_seen = datetime.now(UTC).isoformat()
            )
            logger.info("User %s is now offline", user_id)
        except Exception as e:
            logger.error("Failed to set user %s offline: %s", user_id, e)
            raise DatabaseError(f"Failed to update presence: {str(e)}") from e

    async def set_user_away(self, user_id: UUID) -> None:
        """
        Mark user as away due to inactivity
        """
        try:
            await surreal_db.update_presence(
                user_id = str(user_id),
                status = PresenceStatus.AWAY.value,
                last_seen = datetime.now(UTC).isoformat()
            )
            logger.debug("User %s is now away", user_id)
        except Exception as e:
            logger.error("Failed to set user %s away: %s", user_id, e)
            raise DatabaseError(f"Failed to update presence: {str(e)}") from e

    async def update_last_seen(self, user_id: UUID) -> None:
        """
        Update user last seen timestamp without changing status
        """
        try:
            last_seen = datetime.now(UTC).isoformat()
            await surreal_db.db.merge(
                f"presence:`{user_id}`",
                {
                    "last_seen": last_seen,
                    "updated_at": "time::now()"
                }
            )
            logger.debug("Updated last seen for user %s", user_id)
        except Exception as e:
            logger.error("Failed to update last seen for %s: %s", user_id, e)

    async def get_user_presence(self, user_id: UUID) -> dict:
        """
        Get current presence status for a user
        """
        try:
            await surreal_db.ensure_connected()
            result = await surreal_db.db.select(f"presence:`{user_id}`")

            if not result:
                return {
                    "user_id": str(user_id),
                    "status": PresenceStatus.OFFLINE.value,
                    "last_seen": datetime.now(UTC).isoformat()
                }

            return {
                "user_id": result.get("user_id",
                                      str(user_id)),
                "status": result.get("status",
                                     PresenceStatus.OFFLINE.value),
                "last_seen":
                result.get("last_seen",
                           datetime.now(UTC).isoformat())
            }
        except Exception as e:
            logger.error("Failed to get presence for user %s: %s", user_id, e)
            return {
                "user_id": str(user_id),
                "status": PresenceStatus.OFFLINE.value,
                "last_seen": datetime.now(UTC).isoformat()
            }

    async def get_room_online_users(self, room_id: str) -> list[dict]:
        """
        Get all online users in a specific room
        """
        try:
            presence_list = await surreal_db.get_room_presence(room_id)

            return [
                {
                    "user_id": p.user_id,
                    "status": p.status,
                    "last_seen": p.last_seen.isoformat()
                } for p in presence_list
            ]
        except Exception as e:
            logger.error("Failed to get online users for room %s: %s", room_id, e)
            return []

    async def bulk_update_presence(
        self,
        user_ids: list[UUID],
        status: PresenceStatus
    ) -> None:
        """
        Update presence status for multiple users at once
        """
        for user_id in user_ids:
            try:
                await surreal_db.update_presence(
                    user_id = str(user_id),
                    status = status.value,
                    last_seen = datetime.now(UTC).isoformat()
                )
            except Exception as e:
                logger.error(
                    "Failed to bulk update presence for %s: %s",
                    user_id,
                    e
                )
                continue

        logger.info(
            "Bulk updated presence for %s users to %s",
            len(user_ids),
            status.value
        )


presence_service = PresenceService()
