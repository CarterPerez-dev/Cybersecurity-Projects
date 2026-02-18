"""
©AngelaMos | 2026
config.py
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application configuration loaded from environment variables.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    app_name: str = "AngelusVigil"
    env: str = "development"
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8000
    api_key: str = ""
    log_level: str = "INFO"

    database_url: str = "postgresql+asyncpg://vigil:changeme@localhost:5432/angelusvigil"

    redis_url: str = "redis://localhost:6379"

    geoip_db_path: str = "/usr/share/GeoIP/GeoLite2-City.mmdb"

    nginx_log_path: str = "/var/log/nginx/access.log"

    raw_queue_size: int = 1000
    parsed_queue_size: int = 500
    feature_queue_size: int = 200
    alert_queue_size: int = 100

    batch_size: int = 32
    batch_timeout_ms: int = 50


settings = Settings()
