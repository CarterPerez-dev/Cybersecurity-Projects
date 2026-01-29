"""
ⒸAngelaMos | 2025
Application enums for type safety
"""

from enum import Enum


class MessageStatus(str, Enum):
    """
    Message delivery status
    """
    SENDING = "sending"
    SENT = "sent"
    DELIVERED = "delivered"
    READ = "read"
    FAILED = "failed"


class PresenceStatus(str, Enum):
    """
    User presence status
    """
    ONLINE = "online"
    AWAY = "away"
    OFFLINE = "offline"


class RoomType(str, Enum):
    """
    Chat room types
    """
    DIRECT = "direct"
    GROUP = "group"
    EPHEMERAL = "ephemeral"
