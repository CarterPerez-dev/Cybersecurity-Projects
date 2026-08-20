"""
©AngelaMos | 2026
verdict.py
"""

from enum import IntEnum, StrEnum

from pydantic import BaseModel, ConfigDict

from not_sandboxed.context import Context


class Severity(IntEnum):
    """
    How much a scored finding weighs, ordered so a policy can set a
    threshold against it
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Decision(StrEnum):
    """
    What the firewall concluded about one inspection
    """

    ALLOW = "allow"
    SANITIZE = "sanitize"
    BLOCK = "block"


class Finding(BaseModel):
    """
    One rule firing, naming itself so a consumer can say which layer
    and which rule decided
    """

    model_config = ConfigDict(frozen = True)

    layer: str
    rule: str
    severity: Severity
    invariant: bool
    span_index: int | None = None
    evidence: str = ""


class Verdict(BaseModel):
    """
    The result of one inspection, carrying every finding that fired
    """

    model_config = ConfigDict(frozen = True)

    decision: Decision
    findings: tuple[Finding, ...] = ()
    policy_id: str = ""
    elapsed_ms: float = 0.0
    sanitized: Context | None = None

    @property
    def blocked_by(self) -> tuple[Finding, ...]:
        """
        The findings that actually forced this decision
        """
        return tuple(f for f in self.findings if f.invariant)
