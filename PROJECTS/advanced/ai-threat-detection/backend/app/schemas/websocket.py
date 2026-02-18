"""
©AngelaMos | 2026
websocket.py
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class WebSocketAlert(BaseModel):
    """
    Real-time threat alert broadcast over WebSocket.
    """

    event: Literal["threat"] = "threat"
    timestamp: datetime
    source_ip: str
    request_path: str
    threat_score: float
    severity: str
    component_scores: dict[str, float]
