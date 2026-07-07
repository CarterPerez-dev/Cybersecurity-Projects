"""
models.py

The data types shared across the tool: Severity, Finding, AuditReport.

Keeping these in one place means the checks, the output layer, and the
tests all agree on what a finding looks like. The risk score lives on the
report rather than in the output code so it is testable without going
through Rich.

Key exports:
  Severity - ordered severity levels with a numeric weight
  Finding - a single issue found in a token
  AuditReport - the full result of auditing one token

Connects to:
  checks.py - produces Finding objects
  output.py - renders AuditReport to console or JSON
"""

from dataclasses import dataclass, field
from enum import Enum

from jwt_auditor.decoder import DecodedToken


class Severity(Enum):
    """
    Severity levels ordered from worst to least.

    The weight drives the risk score. The rank drives sorting and is derived
    from declaration order so the enum stays the single source of truth.
    """

    CRITICAL = ("critical", 10.0)
    HIGH = ("high", 7.0)
    MEDIUM = ("medium", 4.0)
    LOW = ("low", 2.0)
    INFO = ("info", 0.5)

    def __init__(self, label: str, weight: float) -> None:
        self.label = label
        self.weight = weight

    @property
    def rank(self) -> int:
        """Position in declaration order, 0 for the most severe."""
        return list(Severity).index(self)


@dataclass
class Finding:
    """
    One issue discovered while auditing a token.

    check_id is a short stable slug (for example "alg-none") so JSON output
    consumers can match findings without parsing the human title.
    """

    check_id: str
    title: str
    severity: Severity
    detail: str
    evidence: str = ""
    recommendation: str = ""


@dataclass
class AuditReport:
    """The complete outcome of auditing a single token."""

    token: DecodedToken
    findings: list[Finding] = field(default_factory = list)

    @property
    def sorted_findings(self) -> list[Finding]:
        """Findings ordered most severe first, stable within a severity."""
        return sorted(self.findings, key = lambda f: f.severity.rank)

    @property
    def highest_severity(self) -> Severity | None:
        """The worst severity present, or None when nothing was found."""
        if not self.findings:
            return None
        return min((f.severity for f in self.findings), key = lambda s: s.rank)

    @property
    def risk_score(self) -> float:
        """
        A 0 to 10 risk score derived from the findings.

        The worst finding sets the floor. Each additional finding adds a
        little, because five medium issues are worse than one. The total is
        capped at 10. A clean token scores 0.0.
        """
        if not self.findings:
            return 0.0
        base = max(f.severity.weight for f in self.findings)
        extra = 0.4 * (len(self.findings) - 1)
        return round(min(10.0, base + extra), 1)

    def counts_by_severity(self) -> dict[Severity, int]:
        """Return how many findings fall under each severity level."""
        counts = {severity: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts
