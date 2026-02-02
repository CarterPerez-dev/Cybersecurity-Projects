"""
ⒸAngelaMos | 2026
constants.py

Centralized constants and
configuration values for network traffic analyzer
"""

from enum import IntEnum
from typing import Final


class Ports(IntEnum):
    """
    Standard network port numbers for protocol identification
    """
    HTTP = 80
    HTTPS = 443
    DNS = 53


class TimeConstants:
    """
    Time-related constants for duration formatting
    """
    SECONDS_PER_MINUTE: Final[int] = 60
    SECONDS_PER_HOUR: Final[int] = 3600


class ByteUnits:
    """
    Byte unit conversion constants
    """
    BYTES_PER_KB: Final[float] = 1024.0
    UNITS: Final[tuple[str, ...]] = ("B", "KB", "MB", "GB", "TB", "PB")


class CaptureDefaults:
    """
    Default values for packet capture operations
    """
    QUEUE_SIZE: Final[int] = 10_000
    QUEUE_TIMEOUT_SECONDS: Final[float] = 0.1
    THREAD_JOIN_TIMEOUT_SECONDS: Final[float] = 2.0
    BANDWIDTH_SAMPLE_INTERVAL_SECONDS: Final[float] = 1.0


class ChartDefaults:
    """
    Default values for matplotlib chart generation
    """
    DPI: Final[int] = 150
    FONT_SIZE_SMALL: Final[int] = 9
    FONT_SIZE_MEDIUM: Final[int] = 11
    FONT_SIZE_LARGE: Final[int] = 14
    FIGSIZE_STANDARD: Final[tuple[int, int]] = (12, 6)
    FIGSIZE_TALL: Final[tuple[int, int]] = (12, 8)
    FIGSIZE_WIDE: Final[tuple[int, int]] = (14, 6)
    FIGSIZE_SQUARE: Final[tuple[int, int]] = (10, 8)
    LINE_WIDTH_THIN: Final[float] = 0.5
    LINE_WIDTH_NORMAL: Final[int] = 2
    MARKER_SIZE: Final[int] = 3
    BAR_HEIGHT: Final[float] = 0.4
    GRID_ALPHA: Final[float] = 0.3


class ProtocolColors:
    """
    Unified color scheme for both Rich console and matplotlib charts
    """
    RICH: Final[dict[str,
                     str]] = {
                         "TCP": "cyan",
                         "UDP": "green",
                         "ICMP": "yellow",
                         "DNS": "magenta",
                         "HTTP": "blue",
                         "HTTPS": "blue",
                         "ARP": "red",
                         "OTHER": "white",
                     }

    HEX: Final[dict[str,
                    str]] = {
                        "TCP": "#3498db",
                        "UDP": "#2ecc71",
                        "ICMP": "#f1c40f",
                        "DNS": "#9b59b6",
                        "HTTP": "#e74c3c",
                        "HTTPS": "#1abc9c",
                        "ARP": "#e67e22",
                        "OTHER": "#95a5a6",
                    }


class DefaultIPs:
    """
    Default IP address values
    """
    UNKNOWN: Final[str] = "0.0.0.0"


class PortRange:
    """
    Valid port number range for validation
    """
    MIN: Final[int] = 0
    MAX: Final[int] = 65535


class NpcapPaths:
    """
    Windows Npcap installation paths for permission checking
    """
    SYSTEM32: Final[str] = r"C:\Windows\System32\Npcap\wpcap.dll"
    SYSWOW64: Final[str] = r"C:\Windows\SysWOW64\Npcap\wpcap.dll"


__all__ = [
    "ByteUnits",
    "CaptureDefaults",
    "ChartDefaults",
    "DefaultIPs",
    "NpcapPaths",
    "PortRange",
    "Ports",
    "ProtocolColors",
    "TimeConstants",
]
