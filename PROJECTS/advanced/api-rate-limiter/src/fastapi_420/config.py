"""
ⒸAngelaMos | 2025
config.py
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Literal

from pydantic import (
    Field,
    RedisDsn,
    model_validator,
)
from pydantic_settings import (
    BaseSettings,
    SettingsConfigDict,
)
from fastapi_420.types import (
    Algorithm,
    DefenseMode,
    FingerprintLevel,
    RateLimitRule,
)


class StorageSettings(BaseSettings):
    """
    Storage backend configuration
    """
    model_config = SettingsConfigDict(
        env_prefix = "RATELIMIT_",
        env_file = ".env",
        env_file_encoding = "utf-8",
        extra = "ignore",
    )

    REDIS_URL: RedisDsn | None = None
    REDIS_MAX_CONNECTIONS: Annotated[int, Field(ge = 1, le = 1000)] = 100
    REDIS_SOCKET_TIMEOUT: Annotated[float,
                                    Field(ge = 0.1,
                                          le = 60.0)] = 5.0
    REDIS_RETRY_ON_TIMEOUT: bool = True
    REDIS_DECODE_RESPONSES: bool = True

    MEMORY_MAX_KEYS: Annotated[int,
                               Field(ge = 100,
                                     le = 10_000_000)] = 100_000
    MEMORY_CLEANUP_INTERVAL: Annotated[int, Field(ge = 1, le = 3600)] = 60

    FALLBACK_TO_MEMORY: bool = True


class FingerprintSettings(BaseSettings):
    """
    Fingerprinting configuration
    """
    model_config = SettingsConfigDict(
        env_prefix = "RATELIMIT_FP_",
        env_file = ".env",
        env_file_encoding = "utf-8",
        extra = "ignore",
    )

    LEVEL: FingerprintLevel = FingerprintLevel.NORMAL
    USE_IP: bool = True
    USE_USER_AGENT: bool = True
    USE_ACCEPT_HEADERS: bool = False
    USE_HEADER_ORDER: bool = False
    USE_AUTH: bool = True
    USE_TLS: bool = False
    USE_GEO: bool = False

    IPV6_PREFIX_LENGTH: Annotated[int, Field(ge = 32, le = 128)] = 64
    TRUSTED_PROXIES: list[str] = []
    TRUST_X_FORWARDED_FOR: bool = False


class DefenseSettings(BaseSettings):
    """
    DDoS defense layer configuration
    """
    model_config = SettingsConfigDict(
        env_prefix = "RATELIMIT_DEFENSE_",
        env_file = ".env",
        env_file_encoding = "utf-8",
        extra = "ignore",
    )

    MODE: DefenseMode = DefenseMode.ADAPTIVE
    GLOBAL_LIMIT: str = "50000/minute"
    CIRCUIT_THRESHOLD: Annotated[int, Field(ge = 1)] = 10000
    CIRCUIT_WINDOW: Annotated[int, Field(ge = 1, le = 3600)] = 60
    CIRCUIT_RECOVERY_TIME: Annotated[int, Field(ge = 1, le = 3600)] = 30

    ADAPTIVE_REDUCTION_FACTOR: Annotated[float,
                                         Field(ge = 0.1,
                                               le = 1.0)] = 0.5
    ENDPOINT_LIMIT_MULTIPLIER: Annotated[int, Field(ge = 1, le = 100)] = 10
    LOCKDOWN_ALLOW_AUTHENTICATED: bool = True
    LOCKDOWN_ALLOW_KNOWN_GOOD: bool = True

    @model_validator(mode = "after")
    def validate_global_limit(self) -> DefenseSettings:
        """
        Validate global limit can be parsed.
        """
        RateLimitRule.parse(self.GLOBAL_LIMIT)
        return self


class RateLimiterSettings(BaseSettings):
    """
    Main rate limiter settings with environment variable support
    """
    model_config = SettingsConfigDict(
        env_prefix = "RATELIMIT_",
        env_file = ".env",
        env_file_encoding = "utf-8",
        extra = "ignore",
    )

    ENABLED: bool = True
    ALGORITHM: Algorithm = Algorithm.SLIDING_WINDOW
    DEFAULT_LIMIT: str = "100/minute"
    DEFAULT_LIMITS: list[str] = ["100/minute", "1000/hour"]
    FAIL_OPEN: bool = True
    KEY_PREFIX: str = "ratelimit"
    KEY_VERSION: str = "v1"
    INCLUDE_HEADERS: bool = True
    LOG_VIOLATIONS: bool = True
    ENVIRONMENT: Literal["development",
                         "staging",
                         "production"] = "development"

    HTTP_420_MESSAGE: str = "Enhance your calm"
    HTTP_420_DETAIL: str = "Rate limit exceeded. Take a breather."

    endpoint_limits: dict[str, list[RateLimitRule]] = {}

    storage: StorageSettings = StorageSettings()
    fingerprint: FingerprintSettings = FingerprintSettings()
    defense: DefenseSettings = DefenseSettings()

    @model_validator(mode = "after")
    def validate_limits(self) -> RateLimiterSettings:
        """
        Validate all limit strings can be parsed
        """
        RateLimitRule.parse(self.DEFAULT_LIMIT)
        for limit in self.DEFAULT_LIMITS:
            RateLimitRule.parse(limit)
        return self

    @model_validator(mode = "after")
    def validate_production_settings(self) -> RateLimiterSettings:
        """
        Enforce stricter settings in production
        """
        if self.ENVIRONMENT == "production":  # noqa: SIM102
            if self.storage.REDIS_URL is None and not self.storage.FALLBACK_TO_MEMORY:
                raise ValueError(
                    "Production requires Redis URL or FALLBACK_TO_MEMORY=True"
                )
        return self

    def get_default_rules(self) -> list[RateLimitRule]:
        """
        Parse and return default rate limit rules
        """
        return [
            RateLimitRule.parse(limit) for limit in self.DEFAULT_LIMITS
        ]

    def get_global_limit_rule(self) -> RateLimitRule:
        """
        Parse and return global defense limit rule
        """
        return RateLimitRule.parse(self.defense.GLOBAL_LIMIT)


@lru_cache
def get_settings() -> RateLimiterSettings:
    """
    Cached settings instance
    """
    return RateLimiterSettings()
