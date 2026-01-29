"""
ⒸAngelaMos | 2025
rate_limit.py
"""

import jwt
from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request

from config import settings


def get_identifier(request: Request) -> str:
    """
    Get rate limit identifier

    Uses user ID if authenticated, otherwise falls back to IP address
    (Will add more fingerprinting if needed depending on project)
    """
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        try:
            token = auth_header.split(" ")[1]
            payload = jwt.decode(
                token,
                options = {"verify_signature": False},
            )
            user_id = payload.get("sub")
            if user_id:
                return f"user:{user_id}"
        except Exception:
            pass

    return get_remote_address(request)


limiter = Limiter(
    key_func = get_identifier,
    storage_uri = str(settings.REDIS_URL) if settings.REDIS_URL else None,
    default_limits = [settings.RATE_LIMIT_DEFAULT],
    headers_enabled = True,
    in_memory_fallback_enabled = True,
)
