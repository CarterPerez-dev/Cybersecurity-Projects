"""
ⒸAngelaMos | 2025
All environment variables and constants are centralized here
"""

from typing import Literal
from functools import lru_cache

from pydantic import (
    PostgresDsn,
    RedisDsn,
    field_validator,
    ValidationInfo,
)
from pydantic_settings import (
    BaseSettings,
    SettingsConfigDict,
)


# User field lengths
USERNAME_MIN_LENGTH = 3
USERNAME_MAX_LENGTH = 50
DISPLAY_NAME_MIN_LENGTH = 1
DISPLAY_NAME_MAX_LENGTH = 100
DEVICE_NAME_MAX_LENGTH = 100
PREKEY_MAX_LENGTH = 500

# User search
USER_SEARCH_MIN_LENGTH = 2
USER_SEARCH_DEFAULT_LIMIT = 10
USER_SEARCH_MAX_LIMIT = 50

# Credential field lengths
CREDENTIAL_ID_MAX_LENGTH = 512
PUBLIC_KEY_MAX_LENGTH = 1024
AAGUID_MAX_LENGTH = 64
ATTESTATION_TYPE_MAX_LENGTH = 50
TRANSPORT_MAX_LENGTH = 200

# Message field lengths
MESSAGE_ID_MAX_LENGTH = 64
ROOM_ID_MAX_LENGTH = 64
ENCRYPTED_CONTENT_MAX_LENGTH = 50000

# Pagination defaults
DEFAULT_MESSAGE_LIMIT = 50
MAX_MESSAGE_LIMIT = 200

# WebSocket message types
WS_MESSAGE_TYPE_ENCRYPTED = "encrypted_message"
WS_MESSAGE_TYPE_TYPING = "typing"
WS_MESSAGE_TYPE_PRESENCE = "presence"
WS_MESSAGE_TYPE_RECEIPT = "receipt"
WS_MESSAGE_TYPE_ERROR = "error"

# Encryption key field lengths
IDENTITY_KEY_LENGTH = 64
SIGNED_PREKEY_LENGTH = 64
ONE_TIME_PREKEY_LENGTH = 64
SIGNATURE_LENGTH = 128
RATCHET_STATE_MAX_LENGTH = 100000

# Encryption constants
X25519_KEY_SIZE = 32
ED25519_KEY_SIZE = 32
ED25519_SIGNATURE_SIZE = 64
AES_GCM_KEY_SIZE = 32
AES_GCM_NONCE_SIZE = 12
HKDF_OUTPUT_SIZE = 32

# Double Ratchet limits
MAX_SKIP_MESSAGE_KEYS = 1000
MAX_CACHED_MESSAGE_KEYS = 2000
DEFAULT_ONE_TIME_PREKEY_COUNT = 100
SIGNED_PREKEY_ROTATION_HOURS = 48
SIGNED_PREKEY_RETENTION_DAYS = 7

# Server defaults
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8000

# WebAuthn challenge settings
WEBAUTHN_CHALLENGE_TTL_SECONDS = 600
WEBAUTHN_CHALLENGE_BYTES = 32

# Application metadata
APP_VERSION = "1.0.0"
APP_STATUS = "running"
APP_DESCRIPTION = "End to end encrypted P2P chat with Double Ratchet and WebAuthn"

# Middleware settings
GZIP_MINIMUM_SIZE = 1000


class Settings(BaseSettings):
    """
    Application settings with environment variable support
    """
    model_config = SettingsConfigDict(
        env_file = "../../.env",
        env_file_encoding = "utf-8",
        case_sensitive = False,
        extra = "ignore",
    )

    ENV: Literal["development", "production", "testing"] = "development"
    DEBUG: bool = True
    APP_NAME: str = "encrypted-p2p-chat"
    SECRET_KEY: str

    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "chat_auth"
    POSTGRES_USER: str = "chat_user"
    POSTGRES_PASSWORD: str = ""
    DATABASE_URL: PostgresDsn | None = None
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 40

    SURREAL_HOST: str = "localhost"
    SURREAL_PORT: int = 8000
    SURREAL_USER: str = "root"
    SURREAL_PASSWORD: str
    SURREAL_NAMESPACE: str = "chat"
    SURREAL_DATABASE: str = "production"
    SURREAL_URL: str | None = None

    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: str = ""
    REDIS_URL: RedisDsn | None = None

    RP_ID: str = "localhost"
    RP_NAME: str = "Encrypted P2P Chat"
    RP_ORIGIN: str = "http://localhost:3000"

    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:5173"]

    WS_HEARTBEAT_INTERVAL: int = 30
    WS_MAX_CONNECTIONS_PER_USER: int = 5

    KEY_ROTATION_DAYS: int = 90
    MAX_SKIPPED_MESSAGE_KEYS: int = 1000

    RATE_LIMIT_MESSAGES_PER_MINUTE: int = 60
    RATE_LIMIT_AUTH_ATTEMPTS: int = 5

    @field_validator("DATABASE_URL", mode = "before")
    @classmethod
    def assemble_db_connection(cls, v: str | None, info: ValidationInfo) -> str:
        """
        Build PostgreSQL connection URL if not provided
        """
        if v:
            return v
        data = info.data
        return (
            f"postgresql+asyncpg://{data['POSTGRES_USER']}:{data['POSTGRES_PASSWORD']}"
            f"@{data['POSTGRES_HOST']}:{data['POSTGRES_PORT']}/{data['POSTGRES_DB']}"
        )

    @field_validator("SURREAL_URL", mode = "before")
    @classmethod
    def assemble_surreal_connection(
        cls,
        v: str | None,
        info: ValidationInfo
    ) -> str:
        """
        Build SurrealDB WebSocket URL if not provided
        """
        if v:
            return v
        data = info.data
        return f"ws://{data['SURREAL_HOST']}:{data['SURREAL_PORT']}"

    @field_validator("REDIS_URL", mode = "before")
    @classmethod
    def assemble_redis_connection(
        cls,
        v: str | None,
        info: ValidationInfo
    ) -> str:
        """
        Build Redis connection URL if not provided
        """
        if v:
            return v
        data = info.data
        password_part = f":{data['REDIS_PASSWORD']}@" if data["REDIS_PASSWORD"
                                                              ] else ""
        return f"redis://{password_part}{data['REDIS_HOST']}:{data['REDIS_PORT']}"

    @property
    def is_production(self) -> bool:
        """
        Check if running in production environment
        """
        return self.ENV == "production"

    @property
    def is_development(self) -> bool:
        """
        Check if running in development environment
        """
        return self.ENV == "development"


@lru_cache
def get_settings() -> Settings:
    """
    Get cached settings instance using lru_cache
    """
    return Settings()  # type: ignore[call-arg]


settings = get_settings()

# Export settings fields as module-level constants for imports
WS_HEARTBEAT_INTERVAL = settings.WS_HEARTBEAT_INTERVAL
WS_MAX_CONNECTIONS_PER_USER = settings.WS_MAX_CONNECTIONS_PER_USER
