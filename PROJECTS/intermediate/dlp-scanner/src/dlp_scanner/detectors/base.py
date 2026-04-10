"""
©AngelaMos | 2026
base.py
"""


import re
from dataclasses import dataclass, field
from typing import Protocol
from collections.abc import Callable


@dataclass(frozen = True, slots = True)
class DetectionRule:
    """
    A single detection rule combining regex, validation, and context
    """
    rule_id: str
    rule_name: str
    pattern: re.Pattern[str]
    base_score: float
    context_keywords: list[str] = field(default_factory = list)
    validator: Callable[[str], bool] | None = None
    compliance_frameworks: list[str] = field(default_factory = list)
    severity_override: str | None = None


@dataclass(frozen = True, slots = True)
class DetectorMatch:
    """
    A raw match from a detector before scoring
    """
    rule_id: str
    rule_name: str
    start: int
    end: int
    matched_text: str
    score: float
    context_keywords: list[str] = field(default_factory = list)
    compliance_frameworks: list[str] = field(default_factory = list)


class Detector(Protocol):
    """
    Protocol for all detection strategies
    """
    def detect(self, text: str) -> list[DetectorMatch]:
        """
        Scan text and return all matches
        """
        ...
