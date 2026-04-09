"""
©AngelaMos | 2026
config.py

Pydantic-settings application configuration loaded from
environment variables and .env file

Defines the Settings model with defaults for: server
(host 0.0.0.0, port 8000, debug, log_level), database
(postgresql+asyncpg URL), Redis URL, GeoIP MaxMind
database path, nginx log path, pipeline queue sizes
(raw 1000, parsed 500, feature 200, alert 100), batch
settings (size 32, timeout 50ms), and ML configuration
(model_dir, detection_mode, ensemble weights for
autoencoder/random-forest/isolation-forest at 0.40/0.40
/0.20, ae_threshold_percentile 99.5, MLflow tracking
URI). Exports a module-level singleton settings instance

Connects to:
  factory.py        - consumed in lifespan and create_app
  __main__.py       - server host/port/reload
  core/ingestion/   - queue sizes, log path
  core/detection/   - model_dir, ensemble weights
  core/enrichment/  - geoip_db_path
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

    model_dir: str = "data/models"
    detection_mode: str = "rules"
    ensemble_weight_ae: float = 0.40
    ensemble_weight_rf: float = 0.40
    ensemble_weight_if: float = 0.20
    ae_threshold_percentile: float = 99.5
    mlflow_tracking_uri: str = "file:./mlruns"


settings = Settings()
