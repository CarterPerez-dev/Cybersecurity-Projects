"""
ⒸAngelaMos | 2025
types.py
"""
# pylint: disable=unnecessary-ellipsis

from __future__ import annotations

from enum import StrEnum
from dataclasses import dataclass, field

from typing import (
    TYPE_CHECKING,
    Protocol,
    runtime_checkable,
)

if TYPE_CHECKING:
    from starlette.requests import Request


class Algorithm(StrEnum):
    """
    Rate limiting algorithm selection
    """
    SLIDING_WINDOW = "sliding_window"
    TOKEN_BUCKET = "token_bucket"
    FIXED_WINDOW = "fixed_window"
    LEAKY_BUCKET = "leaky_bucket"


class FingerprintLevel(StrEnum):
    """
    Preset fingerprinting intensity levels
    """
    STRICT = "strict"
    NORMAL = "normal"
    RELAXED = "relaxed"
    CUSTOM = "custom"


class DefenseMode(StrEnum):
    """
    Global circuit breaker defense strategies
    """
    ADAPTIVE = "adaptive"
    LOCKDOWN = "lockdown"
    CHALLENGE = "challenge"
    DISABLED = "disabled"


class StorageType(StrEnum):
    """
    Backend storage type selection
    """
    REDIS = "redis"
    MEMORY = "memory"


class Layer(StrEnum):
    """
    Rate limiting defense layers
    """
    USER = "user"
    ENDPOINT = "endpoint"
    GLOBAL = "global"


@dataclass(frozen = True, slots = True)
class RateLimitResult:
    """
    Result of a rate limit check operation
    """
    allowed: bool
    limit: int
    remaining: int
    reset_after: float
    retry_after: float | None = None

    @property
    def headers(self) -> dict[str, str]:
        """
        Generate IETF draft-compliant rate limit headers
        """
        hdrs = {
            "RateLimit-Limit": str(self.limit),
            "RateLimit-Remaining": str(max(0,
                                           self.remaining)),
            "RateLimit-Reset": str(int(self.reset_after)),
        }
        if self.retry_after is not None:
            hdrs["Retry-After"] = str(int(self.retry_after))
        return hdrs


@dataclass(frozen = True, slots = True)
class RateLimitRule:
    """
    A single rate limit rule defining requests allowed per time window
    """
    requests: int
    window_seconds: int

    def __post_init__(self) -> None:
        if self.requests <= 0:
            raise ValueError("requests must be positive")
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

    @classmethod
    def parse(cls, rule_string: str) -> RateLimitRule:
        """
        Parse rate limit string like '100/minute' or '1000/hour'
        """
        parts = rule_string.strip().lower().split("/")
        if len(parts) != 2:
            raise ValueError(f"Invalid rate limit format: {rule_string}")

        try:
            requests = int(parts[0])
        except ValueError as e:
            raise ValueError(f"Invalid request count: {parts[0]}") from e

        window_map = {
            "second": 1,
            "seconds": 1,
            "sec": 1,
            "s": 1,
            "minute": 60,
            "minutes": 60,
            "min": 60,
            "m": 60,
            "hour": 3600,
            "hours": 3600,
            "hr": 3600,
            "h": 3600,
            "day": 86400,
            "days": 86400,
            "d": 86400,
        }

        window_str = parts[1].strip()
        if window_str not in window_map:
            raise ValueError(f"Unknown time unit: {window_str}")

        return cls(
            requests = requests,
            window_seconds = window_map[window_str]
        )

    def __str__(self) -> str:
        if self.window_seconds == 1:
            unit = "second"
        elif self.window_seconds == 60:
            unit = "minute"
        elif self.window_seconds == 3600:
            unit = "hour"
        elif self.window_seconds == 86400:
            unit = "day"
        else:
            unit = f"{self.window_seconds}s"
        return f"{self.requests}/{unit}"


@dataclass(slots = True)
class FingerprintData:
    """
    Collected fingerprint data from a request
    """
    ip: str
    ip_normalized: str
    user_agent: str | None = None
    accept_language: str | None = None
    accept_encoding: str | None = None
    headers_hash: str | None = None
    auth_identifier: str | None = None
    tls_fingerprint: str | None = None
    geo_asn: str | None = None

    def to_composite_key(self, level: FingerprintLevel) -> str:
        """
        Generate composite fingerprint key based on level.
        """
        if level == FingerprintLevel.RELAXED:
            components = [self.ip_normalized]
            if self.auth_identifier:
                components.append(self.auth_identifier)
            return ":".join(filter(None, components))

        if level == FingerprintLevel.NORMAL:
            components = [
                self.ip_normalized,
                self.user_agent or "",
                self.auth_identifier or "",
            ]
            return ":".join(components)

        components = [
            self.ip_normalized,
            self.user_agent or "",
            self.accept_language or "",
            self.accept_encoding or "",
            self.headers_hash or "",
            self.auth_identifier or "",
            self.tls_fingerprint or "",
            self.geo_asn or "",
        ]
        return ":".join(components)


@dataclass(slots = True)
class WindowState:
    """
    State for sliding window counter algorithm
    """
    current_count: int = 0
    previous_count: int = 0
    current_window: int = 0
    window_seconds: int = 60

    def weighted_count(self, elapsed_ratio: float) -> float:
        """
        Calculate weighted count using sliding window interpolation.
        """
        return self.previous_count * (
            1 - elapsed_ratio
        ) + self.current_count


@dataclass(slots = True)
class TokenBucketState:
    """
    State for token bucket algorithm
    """
    tokens: float
    last_refill: float
    capacity: int
    refill_rate: float


@dataclass(slots = True)
class CircuitState:
    """
    Global circuit breaker state
    """
    is_open: bool = False
    failure_count: int = 0
    last_failure_time: float = 0.0
    half_open_requests: int = 0
    total_requests_in_window: int = 0


@dataclass(slots = True)
class DefenseContext:
    """
    Context passed to defense strategies
    """
    fingerprint: FingerprintData
    endpoint: str
    method: str
    is_authenticated: bool = False
    reputation_score: float = 1.0
    request_count_last_minute: int = 0


@dataclass(slots = True)
class RateLimitKey:
    """
    Structured rate limit key components
    """
    prefix: str = "ratelimit"
    version: str = "v1"
    layer: Layer = Layer.USER
    endpoint: str = ""
    identifier: str = ""
    window: int = 0

    def build(self) -> str:
        """
        Build the full Redis key string.
        """
        return f"{self.prefix}:{self.version}:{self.layer.value}:{self.endpoint}:{self.identifier}:{self.window}"


@runtime_checkable
class StorageBackend(Protocol):
    """
    Protocol for rate limit storage backends
    """
    async def get_window_state(
        self,
        key: str,
        window_seconds: int,
    ) -> WindowState:
        """
        Get current sliding window state
        """
        ...

    async def increment(
        self,
        key: str,
        window_seconds: int,
        limit: int,
        timestamp: float | None = None,
    ) -> RateLimitResult:
        """
        Atomically check and increment counter, returning result
        """
        ...

    async def get_token_bucket_state(
        self,
        key: str,
    ) -> TokenBucketState | None:
        """
        Get token bucket state if it exists
        """
        ...

    async def consume_token(
        self,
        key: str,
        capacity: int,
        refill_rate: float,
        tokens_to_consume: int = 1,
    ) -> RateLimitResult:
        """
        Attempt to consume tokens from bucket
        """
        ...

    async def close(self) -> None:
        """
        Close storage connections.
        """
        ...

    async def health_check(self) -> bool:
        """
        Check if storage backend is healthy
        """
        ...


@runtime_checkable
class Fingerprinter(Protocol):
    """
    Protocol for request fingerprinting strategies.
    """
    async def extract(self, request: Request) -> FingerprintData:
        """
        Extract fingerprint data from request.
        """
        ...


@runtime_checkable
class RateLimitAlgorithm(Protocol):
    """
    Protocol for rate limiting algorithms
    """
    async def check(
        self,
        storage: StorageBackend,
        key: str,
        rule: RateLimitRule,
        timestamp: float | None = None,
    ) -> RateLimitResult:
        """
        Check if request is allowed under rate limit
        """
        ...


@dataclass
class LimiterConfig:
    """
    Main configuration for the rate limiter.
    """
    default_rules: list[RateLimitRule] = field(default_factory = list)
    algorithm: Algorithm = Algorithm.SLIDING_WINDOW
    fingerprint_level: FingerprintLevel = FingerprintLevel.NORMAL
    defense_mode: DefenseMode = DefenseMode.ADAPTIVE
    fail_open: bool = True
    key_prefix: str = "ratelimit"
    include_headers: bool = True
    log_violations: bool = True

    global_limit: RateLimitRule | None = None
    endpoint_limits: dict[str,
                          list[RateLimitRule]] = field(
                              default_factory = dict
                          )

    def __post_init__(self) -> None:
        if not self.default_rules:
            self.default_rules = [
                RateLimitRule.parse("100/minute"),
                RateLimitRule.parse("1000/hour"),
            ]
