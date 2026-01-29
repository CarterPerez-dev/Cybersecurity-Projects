"""
ⒸAngelaMos | 2025
redis_backend.py
"""
from __future__ import annotations

import time
from dataclasses import (
    dataclass,
    field,
)
from pathlib import Path
from typing import TYPE_CHECKING, Any

import redis.asyncio as redis
from redis.asyncio.connection import ConnectionPool
from redis.exceptions import (
    ConnectionError as RedisConnectionError,
)
from redis.exceptions import (
    ResponseError,
    TimeoutError,
)
from fastapi_420.exceptions import (
    StorageConnectionError,
    StorageError,
)
from fastapi_420.types import (
    RateLimitResult,
    StorageType,
    TokenBucketState,
    WindowState,
)

if TYPE_CHECKING:
    from fastapi_420.config import StorageSettings


LUA_SCRIPTS_DIR = Path(__file__).parent / "lua"


@dataclass
class RedisStorage:
    """
    Redis storage backend with atomic Lua script operations

    Uses EVALSHA with cached script hashes for optimal performance
    All rate limiting operations are atomic to prevent race conditions
    """

    url: str
    max_connections: int = 100
    socket_timeout: float = 5.0
    retry_on_timeout: bool = True
    decode_responses: bool = True

    _client: redis.Redis[Any] | None = field(default = None, repr = False)
    _pool: ConnectionPool[Any] | None = field(default = None, repr = False)
    _script_shas: dict[str,
                       str] = field(
                           default_factory = dict,
                           repr = False
                       )
    _scripts_loaded: bool = field(default = False, repr = False)

    @classmethod
    def from_settings(cls, settings: StorageSettings) -> RedisStorage:
        """
        Create storage instance from settings
        """
        if settings.REDIS_URL is None:
            raise StorageConnectionError(
                backend = StorageType.REDIS,
                original_error = ValueError("REDIS_URL is required"),
            )

        return cls(
            url = str(settings.REDIS_URL),
            max_connections = settings.REDIS_MAX_CONNECTIONS,
            socket_timeout = settings.REDIS_SOCKET_TIMEOUT,
            retry_on_timeout = settings.REDIS_RETRY_ON_TIMEOUT,
            decode_responses = settings.REDIS_DECODE_RESPONSES,
        )

    async def connect(self) -> None:
        """
        Establish Redis connection and load Lua scripts.
        """
        try:
            self._pool = ConnectionPool.from_url(
                self.url,
                max_connections = self.max_connections,
                socket_timeout = self.socket_timeout,
                retry_on_timeout = self.retry_on_timeout,
                decode_responses = self.decode_responses,
            )
            self._client = redis.Redis(connection_pool = self._pool)

            await self._client.ping()
            await self._load_scripts()

        except (RedisConnectionError, TimeoutError, OSError) as e:
            raise StorageConnectionError(
                backend = StorageType.REDIS,
                original_error = e,
            ) from e

    async def _load_scripts(self) -> None:
        """
        Load Lua scripts into Redis and cache their SHA1 hashes
        """
        if self._client is None:
            raise StorageError(
                operation = "load_scripts",
                backend = StorageType.REDIS,
                original_error = RuntimeError("Client not connected"),
            )

        script_files = {
            "sliding_window": LUA_SCRIPTS_DIR / "sliding_window.lua",
            "token_bucket": LUA_SCRIPTS_DIR / "token_bucket.lua",
            "fixed_window": LUA_SCRIPTS_DIR / "fixed_window.lua",
        }

        for name, path in script_files.items():
            script_content = path.read_text()
            sha = await self._client.script_load(script_content)  # type: ignore[no-untyped-call]
            self._script_shas[name] = sha

        self._scripts_loaded = True

    async def _ensure_connected(self) -> redis.Redis[Any]:
        """
        Ensure client is connected and scripts are loaded
        """
        if self._client is None:
            await self.connect()

        if self._client is None:
            raise StorageError(
                operation = "ensure_connected",
                backend = StorageType.REDIS,
                original_error = RuntimeError(
                    "Failed to establish connection"
                ),
            )

        return self._client

    async def _execute_script(
        self,
        script_name: str,
        keys: list[str],
        args: list[str | int | float],
    ) -> list[int | float]:
        """
        Execute a Lua script using EVALSHA
        """
        client = await self._ensure_connected()

        if script_name not in self._script_shas:
            raise StorageError(
                operation = "execute_script",
                backend = StorageType.REDIS,
                original_error = ValueError(
                    f"Unknown script: {script_name}"
                ),
            )

        sha = self._script_shas[script_name]

        try:
            result = await client.evalsha(sha, len(keys), *keys, *args)  # type: ignore[no-untyped-call]
            return result  # type: ignore[no-any-return]

        except ResponseError as e:
            if "NOSCRIPT" in str(e):
                await self._load_scripts()
                sha = self._script_shas[script_name]
                result = await client.evalsha(sha, len(keys), *keys, *args)  # type: ignore[no-untyped-call]
                return result  # type: ignore[no-any-return]
            raise StorageError(
                operation = "execute_script",
                backend = StorageType.REDIS,
                original_error = e,
            ) from e

        except (RedisConnectionError, TimeoutError) as e:
            raise StorageError(
                operation = "execute_script",
                backend = StorageType.REDIS,
                original_error = e,
            ) from e

    async def get_window_state(
        self,
        key: str,
        window_seconds: int,
    ) -> WindowState:
        """
        Get current sliding window state
        """
        client = await self._ensure_connected()
        now = time.time()
        current_window = int(now // window_seconds)
        previous_window = current_window - 1

        current_key = f"{key}:{current_window}"
        previous_key = f"{key}:{previous_window}"

        try:
            pipeline = client.pipeline()
            pipeline.get(current_key)
            pipeline.get(previous_key)
            results = await pipeline.execute()

            current_count = int(results[0]) if results[0] else 0
            previous_count = int(results[1]) if results[1] else 0

            return WindowState(
                current_count = current_count,
                previous_count = previous_count,
                current_window = current_window,
                window_seconds = window_seconds,
            )

        except (RedisConnectionError, TimeoutError) as e:
            raise StorageError(
                operation = "get_window_state",
                backend = StorageType.REDIS,
                original_error = e,
            ) from e

    async def increment(
        self,
        key: str,
        window_seconds: int,
        limit: int,
        timestamp: float | None = None,
    ) -> RateLimitResult:
        """
        Atomically check and increment counter using sliding window algorithm
        """
        now = timestamp if timestamp is not None else time.time()

        result = await self._execute_script(
            "sliding_window",
            keys = [key],
            args = [window_seconds,
                    limit,
                    now],
        )

        allowed = bool(result[0])
        remaining = int(result[1])
        reset_after = float(result[2])
        retry_after = float(result[3]) if result[3] else None

        return RateLimitResult(
            allowed = allowed,
            limit = limit,
            remaining = remaining,
            reset_after = reset_after,
            retry_after = retry_after if not allowed else None,
        )

    async def increment_fixed_window(
        self,
        key: str,
        window_seconds: int,
        limit: int,
        timestamp: float | None = None,
    ) -> RateLimitResult:
        """
        Atomically check and increment counter using fixed window algorithm
        """
        now = timestamp if timestamp is not None else time.time()

        result = await self._execute_script(
            "fixed_window",
            keys = [key],
            args = [window_seconds,
                    limit,
                    now],
        )

        allowed = bool(result[0])
        remaining = int(result[1])
        reset_after = float(result[2])
        retry_after = float(result[3]) if result[3] else None

        return RateLimitResult(
            allowed = allowed,
            limit = limit,
            remaining = remaining,
            reset_after = reset_after,
            retry_after = retry_after if not allowed else None,
        )

    async def get_token_bucket_state(
        self,
        key: str,
    ) -> TokenBucketState | None:
        """
        Get token bucket state if it exists
        """
        client = await self._ensure_connected()
        bucket_key = f"{key}:bucket"

        try:
            data = await client.hmget(
                bucket_key,
                "tokens",
                "last_refill",
                "capacity",
                "refill_rate"
            )

            if data[0] is None:
                return None

            return TokenBucketState(
                tokens = float(data[0]),
                last_refill = float(data[1]),  # type: ignore[arg-type]
                capacity = int(data[2]),  # type: ignore[arg-type]
                refill_rate = float(data[3]),  # type: ignore[arg-type]
            )

        except (RedisConnectionError, TimeoutError) as e:
            raise StorageError(
                operation = "get_token_bucket_state",
                backend = StorageType.REDIS,
                original_error = e,
            ) from e

    async def consume_token(
        self,
        key: str,
        capacity: int,
        refill_rate: float,
        tokens_to_consume: int = 1,
    ) -> RateLimitResult:
        """
        Attempt to consume tokens from bucket atomically
        """
        now = time.time()

        result = await self._execute_script(
            "token_bucket",
            keys = [key],
            args = [capacity,
                    refill_rate,
                    tokens_to_consume,
                    now],
        )

        allowed = bool(result[0])
        remaining = int(result[1])
        reset_after = float(result[2])
        retry_after = float(result[3]) if result[3] else None

        return RateLimitResult(
            allowed = allowed,
            limit = capacity,
            remaining = remaining,
            reset_after = reset_after,
            retry_after = retry_after if not allowed else None,
        )

    async def close(self) -> None:
        """
        Close Redis connection.
        """
        if self._client:
            await self._client.close()
            self._client = None

        if self._pool:
            await self._pool.disconnect()
            self._pool = None

        self._scripts_loaded = False
        self._script_shas.clear()

    async def health_check(self) -> bool:
        """
        Check if Redis connection is healthy
        """
        try:
            client = await self._ensure_connected()
            await client.ping()
            return True
        except (StorageError, RedisConnectionError, TimeoutError):
            return False

    @property
    def storage_type(self) -> StorageType:
        """
        Return storage type identifier
        """
        return StorageType.REDIS

    @property
    def is_connected(self) -> bool:
        """
        Check if client is connected
        """
        return self._client is not None and self._scripts_loaded
