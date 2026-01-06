"""
ⒸAngelaMos | 2026
config.py
"""

from pathlib import Path
from typing import Literal
from functools import lru_cache

from pydantic import (
    EmailStr,
    Field,
    RedisDsn,
    SecretStr,
    PostgresDsn,
    model_validator,
)
from pydantic_settings import (
    BaseSettings,
    SettingsConfigDict,
)

from core.constants import (
    API_PREFIX,
    API_VERSION,
    ASSET_DESCRIPTION_MAX_LENGTH,
    ASSET_IDENTIFIER_MAX_LENGTH,
    BIO_MAX_LENGTH,
    COMMENT_MAX_LENGTH,
    COMPANY_NAME_MAX_LENGTH,
    CURRENCY_MAX_LENGTH,
    CWE_ID_MAX_LENGTH,
    DEVICE_ID_MAX_LENGTH,
    DEVICE_NAME_MAX_LENGTH,
    EMAIL_MAX_LENGTH,
    FILENAME_MAX_LENGTH,
    FULL_NAME_MAX_LENGTH,
    IP_ADDRESS_MAX_LENGTH,
    MIME_TYPE_MAX_LENGTH,
    PASSWORD_HASH_MAX_LENGTH,
    PASSWORD_MAX_LENGTH,
    PASSWORD_MIN_LENGTH,
    PROGRAM_DESCRIPTION_MAX_LENGTH,
    PROGRAM_NAME_MAX_LENGTH,
    PROGRAM_RULES_MAX_LENGTH,
    PROGRAM_SLUG_MAX_LENGTH,
    REPORT_DESCRIPTION_MAX_LENGTH,
    REPORT_IMPACT_MAX_LENGTH,
    REPORT_STEPS_MAX_LENGTH,
    REPORT_TITLE_MAX_LENGTH,
    STORAGE_PATH_MAX_LENGTH,
    TOKEN_HASH_LENGTH,
    WEBSITE_MAX_LENGTH,
)
from core.enums import (
    AssetType,
    Environment,
    HealthStatus,
    ProgramStatus,
    ProgramVisibility,
    ReportStatus,
    SafeEnum,
    Severity,
    TokenType,
    UserRole,
)


__all__ = [
    "API_PREFIX",
    "API_VERSION",
    "ASSET_DESCRIPTION_MAX_LENGTH",
    "ASSET_IDENTIFIER_MAX_LENGTH",
    "BIO_MAX_LENGTH",
    "COMMENT_MAX_LENGTH",
    "COMPANY_NAME_MAX_LENGTH",
    "CURRENCY_MAX_LENGTH",
    "CWE_ID_MAX_LENGTH",
    "DEVICE_ID_MAX_LENGTH",
    "DEVICE_NAME_MAX_LENGTH",
    "EMAIL_MAX_LENGTH",
    "FILENAME_MAX_LENGTH",
    "FULL_NAME_MAX_LENGTH",
    "IP_ADDRESS_MAX_LENGTH",
    "MIME_TYPE_MAX_LENGTH",
    "PASSWORD_HASH_MAX_LENGTH",
    "PASSWORD_MAX_LENGTH",
    "PASSWORD_MIN_LENGTH",
    "PROGRAM_DESCRIPTION_MAX_LENGTH",
    "PROGRAM_NAME_MAX_LENGTH",
    "PROGRAM_RULES_MAX_LENGTH",
    "PROGRAM_SLUG_MAX_LENGTH",
    "REPORT_DESCRIPTION_MAX_LENGTH",
    "REPORT_IMPACT_MAX_LENGTH",
    "REPORT_STEPS_MAX_LENGTH",
    "REPORT_TITLE_MAX_LENGTH",
    "STORAGE_PATH_MAX_LENGTH",
    "TOKEN_HASH_LENGTH",
    "WEBSITE_MAX_LENGTH",
    "AssetType",
    "Environment",
    "HealthStatus",
    "ProgramStatus",
    "ProgramVisibility",
    "ReportStatus",
    "SafeEnum",
    "Settings",
    "Severity",
    "TokenType",
    "UserRole",
    "get_settings",
    "settings",
]

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_ENV_FILE = _PROJECT_ROOT / ".env"


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables
    """
    model_config = SettingsConfigDict(
        env_file = _ENV_FILE,
        env_file_encoding = "utf-8",
        case_sensitive = False,
        extra = "ignore",
    )

    APP_NAME: str = "bug-bounty-platform"
    APP_VERSION: str = "1.0.0"
    APP_SUMMARY: str = "Developed CarterPerez-dev"
    APP_DESCRIPTION: str = "FastAPI async first boilerplate - JWT, Asyncdb, PostgreSQL"
    APP_CONTACT_NAME: str = "AngelaMos LLC"
    APP_CONTACT_EMAIL: str = "support@certgames.com"
    APP_LICENSE_NAME: str = "MIT"
    APP_LICENSE_URL: str = "https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/LICENSE"

    ENVIRONMENT: Environment = Environment.DEVELOPMENT
    DEBUG: bool = False

    HOST: str = "0.0.0.0"
    PORT: int = 8000
    RELOAD: bool = True

    DATABASE_URL: PostgresDsn
    DB_POOL_SIZE: int = Field(default = 20, ge = 5, le = 100)
    DB_MAX_OVERFLOW: int = Field(default = 10, ge = 0, le = 50)
    DB_POOL_TIMEOUT: int = Field(default = 30, ge = 10)
    DB_POOL_RECYCLE: int = Field(default = 1800, ge = 300)

    SECRET_KEY: SecretStr = Field(..., min_length = 32)
    JWT_ALGORITHM: Literal["HS256", "HS384", "HS512"] = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default = 15, ge = 5, le = 60)
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default = 7, ge = 1, le = 30)

    ADMIN_EMAIL: EmailStr | None = None

    REDIS_URL: RedisDsn | None = None

    CORS_ORIGINS: list[str] = ["*"]
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: list[str] = [
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS"
    ]
    CORS_ALLOW_HEADERS: list[str] = ["*"]

    RATE_LIMIT_DEFAULT: str = "100/minute"
    RATE_LIMIT_AUTH: str = "20/minute"

    PAGINATION_DEFAULT_SIZE: int = Field(default = 20, ge = 1, le = 100)
    PAGINATION_MAX_SIZE: int = Field(default = 100, ge = 1, le = 500)

    LOG_LEVEL: Literal["DEBUG",
                       "INFO",
                       "WARNING",
                       "ERROR",
                       "CRITICAL"] = "INFO"
    LOG_JSON_FORMAT: bool = True

    @model_validator(mode = "after")
    def validate_production_settings(self) -> "Settings":
        """
        Enforce security constraints in production environment.
        """
        if self.ENVIRONMENT == Environment.PRODUCTION:
            if self.DEBUG:
                raise ValueError("DEBUG must be False in production")
            if self.CORS_ORIGINS == ["*"]:
                raise ValueError(
                    "CORS_ORIGINS cannot be ['*'] in production"
                )
        return self


@lru_cache
def get_settings() -> Settings:
    """
    Cached settings instance to avoid repeated env parsing
    """
    return Settings()


settings = get_settings()
