"""
©AngelaMos | 2026
redis_manager.py
"""

import redis.asyncio as aioredis

from app.config import settings


class RedisManager:
    """
    Async Redis connection lifecycle manager.
    """

    def __init__(self) -> None:
        self._client: aioredis.Redis[str] | None = None

    async def connect(self) -> None:
        """
        Create the async Redis client from configured URL.
        """
        self._client = aioredis.from_url(
            settings.redis_url,
            decode_responses=True,
        )

    async def disconnect(self) -> None:
        """
        Close the Redis connection and release resources.
        """
        if self._client:
            await self._client.aclose()  # type: ignore[attr-defined]
            self._client = None

    @property
    def client(self) -> aioredis.Redis[str] | None:
        """
        Return the active Redis client or None if not connected.
        """
        return self._client

    async def ping(self) -> bool:
        """
        Check Redis connectivity via PING command.
        """
        if not self._client:
            return False
        try:
            return await self._client.ping()
        except Exception:
            return False


redis_manager = RedisManager()
