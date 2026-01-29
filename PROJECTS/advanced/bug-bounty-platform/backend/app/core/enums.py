"""
ⒸAngelaMos | 2025
enums.py
"""

from enum import Enum
from typing import Any

import sqlalchemy as sa


def enum_values_callable(enum_class: type[Enum]) -> list[str]:
    """
    Returns enum VALUES (not names) for SQLAlchemy storage

    Prevents the common trap where SQLAlchemy stores enum NAMES by default,
    causing database breakage if you rename an enum member
    """
    return [str(item.value) for item in enum_class]


class SafeEnum(sa.Enum):
    """
    SQLAlchemy Enum type that stores VALUES and handles unknown values gracefully

    https://blog.wrouesnel.com/posts/sqlalchemy-enums-careful-what-goes-into-the-database/
    """
    def __init__(self, *enums: type[Enum], **kw: Any) -> None:
        if "values_callable" not in kw:
            kw["values_callable"] = enum_values_callable
        super().__init__(*enums, **kw)
        self._unknown_value = (
            kw["_adapted_from"]._unknown_value
            if "_adapted_from" in kw else kw.get("unknown_value")
        )

    def _object_value_for_elem(self, elem: str) -> Enum:
        """
        Override to return unknown_value instead of raising LookupError
        """
        try:
            return self._object_lookup[elem]
        except LookupError:
            if self._unknown_value is not None:
                return self._unknown_value
            raise


class Environment(str, Enum):
    """
    Application environment.
    """
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class UserRole(str, Enum):
    """
    User roles for authorization.
    """
    UNKNOWN = "unknown"
    USER = "user"
    COMPANY = "company"
    ADMIN = "admin"


class TokenType(str, Enum):
    """
    JWT token types.
    """
    ACCESS = "access"
    REFRESH = "refresh"


class HealthStatus(str, Enum):
    """
    Health check status values.
    """
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    DEGRADED = "degraded"


class ProgramStatus(str, Enum):
    """
    Bug bounty program lifecycle status.
    """
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    CLOSED = "closed"


class ProgramVisibility(str, Enum):
    """
    Bug bounty program visibility level.
    """
    PUBLIC = "public"
    PRIVATE = "private"
    INVITE_ONLY = "invite_only"


class AssetType(str, Enum):
    """
    Type of asset in a bug bounty program scope.
    """
    DOMAIN = "domain"
    API = "api"
    MOBILE_APP = "mobile_app"
    SOURCE_CODE = "source_code"
    HARDWARE = "hardware"
    OTHER = "other"


class Severity(str, Enum):
    """
    Vulnerability severity levels aligned with CVSS.
    """
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ReportStatus(str, Enum):
    """
    Vulnerability report lifecycle status.
    """
    NEW = "new"
    TRIAGING = "triaging"
    NEEDS_MORE_INFO = "needs_more_info"
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    INFORMATIVE = "informative"
    NOT_APPLICABLE = "not_applicable"
    RESOLVED = "resolved"
    DISCLOSED = "disclosed"
