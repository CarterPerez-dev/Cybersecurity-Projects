"""
AngelaMos | 2026
config.py

Application settings loaded from environment variables and a .env file

Defines the Settings class using pydantic-settings, covering server
host/port, database path, XOR encryption key, CORS origins, and log
level. The module-level settings singleton is shared across the app.

Connects to:
  database.py - reads DATABASE_PATH
  beacon/router.py - reads XOR_KEY
  __main__.py - reads HOST, PORT, APP_NAME, LOG_LEVEL
"""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    APP_NAME: str = "C2 Beacon Server"
    APP_VERSION: str = "1.0.0"

    ENVIRONMENT: Literal["development", "production"] = "development"
    DEBUG: bool = False

    HOST: str = "0.0.0.0"
    PORT: int = 8000
    RELOAD: bool = True

    DATABASE_PATH: Path = Path("data/c2.db")

    XOR_KEY: str = Field(
        default = "c2-beacon-default-key-change-me",
        min_length = 8,
    )

    CORS_ORIGINS: list[str] = [
        "http://localhost",
        "http://localhost:47430",
        "http://localhost:47432",
    ]

    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"


@lru_cache
def get_settings() -> Settings:
    """
    Cached settings instance to avoid repeated env parsing
    """
    return Settings()


settings = get_settings()
