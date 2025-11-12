"""
Enum definitions for the application for type safety
"""

from enum import Enum


class ScanStatus(str, Enum):
    """
    Enum for scan result status
    """
    VULNERABLE = "vulnerable"
    SAFE = "safe"
    ERROR = "error"


class Severity(str, Enum):
    """
    Enum for vulnerability severity levels
    """
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TestType(str, Enum):
    """
    Enum for available security test types
    """
    RATE_LIMIT = "rate_limit"
    AUTH = "auth"
    SQLI = "sqli"
    IDOR = "idor"
