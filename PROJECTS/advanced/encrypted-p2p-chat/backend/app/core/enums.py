"""
ⒸAngelaMos | 2025
Application enums for type safety
"""

from enum import StrEnum


class MessageStatus(StrEnum):
    """
    Message delivery status
    """
    SENDING = "sending"
    SENT = "sent"
    DELIVERED = "delivered"
    READ = "read"
    FAILED = "failed"


class PresenceStatus(StrEnum):
    """
    User presence status
    """
    ONLINE = "online"
    AWAY = "away"
    OFFLINE = "offline"


class RoomType(StrEnum):
    """
    Chat room types
    """
    DIRECT = "direct"
    GROUP = "group"
    EPHEMERAL = "ephemeral"
