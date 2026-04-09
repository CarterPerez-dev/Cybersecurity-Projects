"""
©AngelaMos | 2026
websocket.py

Pydantic model for real-time WebSocket threat alert
payloads

WebSocketAlert carries event type (Literal "threat"),
timestamp, source_ip, request_method, request_path,
threat_score, severity, and component_scores. Serialized
via model_dump_json for Redis pub/sub broadcast

Connects to:
  core/alerts/dispatcher - constructs and publishes alerts
  api/websocket          - relayed to connected clients
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
    request_method: str
    request_path: str
    threat_score: float
    severity: str
    component_scores: dict[str, float]
