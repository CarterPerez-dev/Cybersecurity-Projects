"""
ⒸAngelaMos | 2025
enums.py
"""

from enum import Enum


class Environment(str, Enum):
    """
    Application environment
    """
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class TokenType(str, Enum):
    """
    JWT token types
    """
    ACCESS = "access"


class HealthStatus(str, Enum):
    """
    Health check status values
    """
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    DEGRADED = "degraded"
