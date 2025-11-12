"""
ⒸAngelaMos | 2025
All environment variables and constants are centralized here
"""

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables

    All magic numbers and configuration values are defined here to avoid
    hardcoding throughout the application
    """

    model_config = SettingsConfigDict(
        env_file = "../.env",
        env_file_encoding = "utf-8",
        case_sensitive = True
    )

    # Application metadata
    APP_NAME: str = "API Security Tester"
    VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Database configuration
    DATABASE_URL: str
    POSTGRES_USER: str = "apiuser"
    POSTGRES_PASSWORD: str = "apipass"
    POSTGRES_DB: str = "apisecurity"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432

    # Security - JWT
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440  # 24 hours

    # Backend server
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000

    # CORS origins (comma-separated string)
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    # Scanner configuration - Default values
    DEFAULT_MAX_REQUESTS: int = 100
    DEFAULT_TIMEOUT_SECONDS: int = 10
    DEFAULT_RETRY_COUNT: int = 3

    # Scanner rate limiting (outgoing requests)
    SCANNER_RATE_LIMIT_THRESHOLD: int = 100
    SCANNER_RATE_LIMIT_WINDOW_SECONDS: int = 60

    # API endpoint rate limiting (incoming requests - slowapi format)
    API_RATE_LIMIT_LOGIN: str = "20/minute"
    API_RATE_LIMIT_REGISTER: str = "15/minute"
    API_RATE_LIMIT_SCAN: str = "15/minute"
    API_RATE_LIMIT_DEFAULT: str = "100/minute"

    # Pagination
    DEFAULT_PAGINATION_LIMIT: int = 100
    MAX_PAGINATION_LIMIT: int = 1000

    # Field validation constants
    PASSWORD_MIN_LENGTH: int = 8
    PASSWORD_MAX_LENGTH: int = 100
    EMAIL_MAX_LENGTH: int = 255
    URL_MAX_LENGTH: int = 2048

    # Scanner timeouts and limits
    SCANNER_MAX_CONCURRENT_REQUESTS: int = 50
    SCANNER_CONNECTION_TIMEOUT: int = 180
    SCANNER_READ_TIMEOUT: int = 180

    # Scanner request spacing and timing
    DEFAULT_JITTER_MS: int = 100
    DEFAULT_RETRY_WAIT_SECONDS: int = 60
    DEFAULT_BASELINE_SAMPLES: int = 10

    @property
    def cors_origins_list(self) -> list[str]:
        """
        Convert comma separated CORS origins string to list
        """
        return [
            origin.strip() for origin in self.CORS_ORIGINS.split(",")
        ]


@lru_cache
def get_settings() -> Settings:
    """
    Get cached settings instance.

    The @lru_cache decorator ensures settings are loaded only once
    and cached for the application lifetime.

    Returns:
        Settings: Application settings instance
    """
    return Settings()


settings = get_settings()
