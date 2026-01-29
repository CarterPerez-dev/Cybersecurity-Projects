"""
ⒸAngelaMos | 2025
Redis manager for WebAuthn challenge storage with TTL
"""

import logging

import redis.asyncio as redis

from app.config import (
    settings,
    WEBAUTHN_CHALLENGE_TTL_SECONDS,
)


logger = logging.getLogger(__name__)


class RedisManager:
    """
    Redis manager for challenge storage with automatic expiration
    """
    def __init__(self) -> None:
        """
        Initialize Redis manager with connection pool
        """
        self.pool: redis.ConnectionPool | None = None
        self.client: redis.Redis | None = None

    async def connect(self) -> None:
        """
        Establish Redis connection with connection pooling
        """
        if self.pool is not None:
            return

        self.pool = redis.ConnectionPool.from_url(
            str(settings.REDIS_URL),
            max_connections = 50,
            decode_responses = False,
        )
        self.client = redis.Redis(connection_pool = self.pool)

        await self.client.ping()
        logger.info("Connected to Redis at %s", settings.REDIS_URL)

    async def disconnect(self) -> None:
        """
        Close Redis connection
        """
        if self.client:
            await self.client.aclose()
        if self.pool:
            await self.pool.aclose()
        logger.info("Disconnected from Redis")

    async def set_registration_challenge(
        self,
        user_id: str,
        challenge: bytes,
        ttl: int = WEBAUTHN_CHALLENGE_TTL_SECONDS,
    ) -> None:
        """
        Store registration challenge with TTL
        """
        if not self.client:
            raise RuntimeError("Redis client not connected")

        key = f"webauthn:reg_challenge:{user_id}"
        await self.client.setex(key, ttl, challenge.hex())
        logger.debug(
            "Stored registration challenge for user %s with %ss TTL",
            user_id,
            ttl
        )

    async def get_registration_challenge(self, user_id: str) -> bytes | None:
        """
        Retrieve and delete registration challenge (one-time use)
        """
        if not self.client:
            raise RuntimeError("Redis client not connected")

        key = f"webauthn:reg_challenge:{user_id}"

        async with self.client.pipeline() as pipe:
            await pipe.get(key)
            await pipe.delete(key)
            results = await pipe.execute()

        challenge_hex = results[0]
        if challenge_hex is None:
            return None

        return bytes.fromhex(challenge_hex.decode())

    async def set_authentication_challenge(
        self,
        user_id: str,
        challenge: bytes,
        ttl: int = WEBAUTHN_CHALLENGE_TTL_SECONDS,
    ) -> None:
        """
        Store authentication challenge with TTL
        """
        if not self.client:
            raise RuntimeError("Redis client not connected")

        key = f"webauthn:auth_challenge:{user_id}"
        await self.client.setex(key, ttl, challenge.hex())
        logger.debug(
            "Stored authentication challenge for user %s with %ss TTL",
            user_id,
            ttl
        )

    async def get_authentication_challenge(self, user_id: str) -> bytes | None:
        """
        Retrieve and delete authentication challenge (one-time use)
        """
        if not self.client:
            raise RuntimeError("Redis client not connected")

        key = f"webauthn:auth_challenge:{user_id}"

        async with self.client.pipeline() as pipe:
            await pipe.get(key)
            await pipe.delete(key)
            results = await pipe.execute()

        challenge_hex = results[0]
        if challenge_hex is None:
            return None

        return bytes.fromhex(challenge_hex.decode())

    async def set_value(
        self,
        key: str,
        value: str,
        ttl: int | None = None
    ) -> None:
        """
        Generic set with optional TTL
        """
        if not self.client:
            raise RuntimeError("Redis client not connected")

        if ttl:
            await self.client.setex(key, ttl, value)
        else:
            await self.client.set(key, value)

    async def get_value(self, key: str) -> str | None:
        """
        Generic get
        """
        if not self.client:
            raise RuntimeError("Redis client not connected")

        value = await self.client.get(key)
        return value.decode() if value else None

    async def delete_value(self, key: str) -> None:
        """
        Generic delete
        """
        if not self.client:
            raise RuntimeError("Redis client not connected")

        await self.client.delete(key)


redis_manager = RedisManager()
