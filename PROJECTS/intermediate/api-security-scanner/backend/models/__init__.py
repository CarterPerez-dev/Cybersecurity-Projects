"""
ⒸAngelaMos | 2025
Database models package
"""

from .Base import BaseModel

from .User import User
from .Scan import Scan
from .TestResult import TestResult


__all__ = [
    "BaseModel",
    "User",
    "Scan",
    "TestResult",
]
