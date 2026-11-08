"""
©AngelaMos | 2026
redis_manager.py
"""

import json
import logging

import redis.asyncio as redis
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes

from app.config import (
    settings,
    SESSION_TTL_SECONDS,
    WEBAUTHN_CHALLENGE_TTL_SECONDS,
)


logger = logging.getLogger(__name__)

REG_CONTEXT_PREFIX = "webauthn:reg_ctx:"
AUTH_CHALLENGE_PREFIX = "webauthn:auth_challenge:"
SESSION_PREFIX = "session:"


class RedisManager:
    """
    Redis manager for WebAuthn challenges and session tokens
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

    def _require_client(self) -> redis.Redis:
        """
        Return the active client or raise if not connected
        """
        if not self.client:
            raise RuntimeError("Redis client not connected")
        return self.client

    async def set_registration_context(
        self,
        username: str,
        challenge: bytes,
        user_handle: bytes,
        display_name: str,
        ttl: int = WEBAUTHN_CHALLENGE_TTL_SECONDS,
    ) -> None:
        """
        Store registration challenge plus user handle and display name
        """
        client = self._require_client()
        key = f"{REG_CONTEXT_PREFIX}{username}"
        payload = json.dumps(
            {
                "challenge": bytes_to_base64url(challenge),
                "user_handle": bytes_to_base64url(user_handle),
                "display_name": display_name,
            }
        )
        await client.setex(key, ttl, payload)
        logger.debug("Stored registration context for %s", username)

    async def take_registration_context(
        self,
        username: str,
    ) -> dict[str,
              bytes | str] | None:
        """
        Retrieve and delete the registration context atomically
        """
        client = self._require_client()
        key = f"{REG_CONTEXT_PREFIX}{username}"

        async with client.pipeline() as pipe:
            await pipe.get(key)
            await pipe.delete(key)
            results = await pipe.execute()

        raw = results[0]
        if raw is None:
            return None

        data = json.loads(raw.decode())
        return {
            "challenge": base64url_to_bytes(data["challenge"]),
            "user_handle": base64url_to_bytes(data["user_handle"]),
            "display_name": data["display_name"],
        }

    async def set_authentication_challenge(
        self,
        challenge: bytes,
        ttl: int = WEBAUTHN_CHALLENGE_TTL_SECONDS,
    ) -> None:
        """
        Store an authentication challenge keyed by the challenge bytes
        """
        client = self._require_client()
        key = f"{AUTH_CHALLENGE_PREFIX}{bytes_to_base64url(challenge)}"
        await client.set(key, b"1", ex = ttl, nx = True)
        logger.debug(
            "Stored authentication challenge with %ss TTL",
            ttl,
        )

    async def take_authentication_challenge(
        self,
        challenge: bytes,
    ) -> bool:
        """
        Atomically verify and consume an authentication challenge
        """
        client = self._require_client()
        key = f"{AUTH_CHALLENGE_PREFIX}{bytes_to_base64url(challenge)}"
        result = await client.delete(key)
        return result == 1

    async def create_session(
        self,
        token: str,
        user_id: str,
        ttl: int = SESSION_TTL_SECONDS,
    ) -> None:
        """
        Persist a session token bound to a user id with expiry
        """
        client = self._require_client()
        key = f"{SESSION_PREFIX}{token}"
        await client.setex(key, ttl, user_id)
        logger.debug("Created session for user %s", user_id)

    async def get_session_user(
        self,
        token: str,
    ) -> str | None:
        """
        Look up the user id for a session token if it is still valid
        """
        client = self._require_client()
        key = f"{SESSION_PREFIX}{token}"
        raw = await client.get(key)
        if raw is None:
            return None
        return raw.decode()

    async def delete_session(
        self,
        token: str,
    ) -> None:
        """
        Invalidate a session token
        """
        client = self._require_client()
        key = f"{SESSION_PREFIX}{token}"
        await client.delete(key)


redis_manager = RedisManager()
