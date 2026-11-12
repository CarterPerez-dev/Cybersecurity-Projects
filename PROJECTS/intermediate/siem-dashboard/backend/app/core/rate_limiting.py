"""
©AngelaMos | 2026
rate_limiting.py

Flask-Limiter setup with Redis storage

Creates the module-level limiter instance keyed by remote address
and backed by Redis. init_limiter attaches it to the Flask app and
registers a JSON 429 handler. The limiter is imported directly by
route files that apply tighter per-endpoint limits.

Key exports:
  limiter - Flask-Limiter instance applied as a decorator in routes
  init_limiter - attaches limiter to the app and registers 429 handler

Connects to:
  config.py - reads REDIS_URL, RATELIMIT_* settings
  __init__.py - calls init_limiter
  routes/auth.py - imports limiter for stricter auth rate limits
"""

from typing import Any

import structlog
from flask import Flask, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from app.config import settings


logger = structlog.get_logger()

limiter = Limiter(
    key_func = get_remote_address,
    storage_uri = settings.REDIS_URL,
    strategy = settings.RATELIMIT_STRATEGY,
    default_limits = [settings.RATELIMIT_DEFAULT],
    headers_enabled = settings.RATELIMIT_HEADERS_ENABLED,
    swallow_errors = settings.RATELIMIT_SWALLOW_ERRORS,
)


def init_limiter(app: Flask) -> None:
    limiter.init_app(app)

    @app.errorhandler(429)
    def handle_rate_limit(e: Any) -> tuple[Any, int]:
        logger.warning("rate_limit_exceeded", description = str(e.description))
        response = jsonify(
            {
                "error": "RateLimitExceeded",
                "message": "Too many requests",
                "retry_after": getattr(e,
                                       "retry_after",
                                       None),
            }
        )
        if hasattr(e, "retry_after") and e.retry_after:
            response.headers["Retry-After"] = str(e.retry_after)
        return response, 429
