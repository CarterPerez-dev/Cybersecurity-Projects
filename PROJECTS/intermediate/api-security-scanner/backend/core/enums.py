"""
Enum definitions for the application for type safety
"""

from enum import StrEnum


class ScanStatus(StrEnum):
    """
    Enum for scan result status
    """

    VULNERABLE = "vulnerable"
    SAFE = "safe"
    ERROR = "error"


class Severity(StrEnum):
    """
    Enum for vulnerability severity levels
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TestType(StrEnum):
    """
    Enum for available security test types
    """

    RATE_LIMIT = "rate_limit"
    AUTH = "auth"
    SQLI = "sqli"
    IDOR = "idor"
