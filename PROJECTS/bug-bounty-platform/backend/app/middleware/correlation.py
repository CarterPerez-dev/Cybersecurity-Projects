"""
ⒸAngelaMos | 2025
correlation.py
"""

import uuid
from collections.abc import (
    Awaitable,
    Callable,
)
import structlog
from starlette.requests import Request
from starlette.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware


RequestResponseEndpoint = Callable[[Request], Awaitable[Response]]


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """
    Correlation ID to requests for distributed tracing
    """
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        correlation_id = request.headers.get(
            "X-Correlation-ID",
            str(uuid.uuid4())
        )

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            correlation_id = correlation_id,
            method = request.method,
            path = request.url.path,
        )

        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        return response
