"""
©AngelaMos | 2026
middleware.py
"""

import json


CONTENT_LENGTH = b"content-length"
PAYLOAD_TOO_LARGE = 413


class BodySizeLimitMiddleware:
    """
    Reject request bodies larger than a byte cap before they are parsed
    """
    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if self._declared_length(scope) > self.max_bytes:
            await self._reject(send)
            return
        await self.app(scope, self._bounded(receive), send)

    def _declared_length(self, scope) -> int:
        for key, value in scope.get("headers", []):
            if key.lower() == CONTENT_LENGTH:
                try:
                    return int(value)
                except ValueError:
                    return 0
        return 0

    def _bounded(self, receive):
        seen = 0

        async def bounded_receive():
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.max_bytes:
                    return {"type": "http.disconnect"}
            return message

        return bounded_receive

    async def _reject(self, send) -> None:
        body = json.dumps({"detail": "request body too large"}).encode()
        await send(
            {
                "type":
                "http.response.start",
                "status":
                PAYLOAD_TOO_LARGE,
                "headers": [
                    (b"content-type",
                     b"application/json"),
                    (b"content-length",
                     str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
