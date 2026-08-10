"""
©AngelaMos | 2026
policy.py
"""

from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict

from not_sandboxed.verdict import Decision, Finding, Severity


class Policy(BaseModel):
    """
    Which layers run and how heavy a scored finding has to be before
    it blocks
    """

    model_config = ConfigDict(frozen = True)

    policy_id: str = "default"
    block_threshold: Severity = Severity.HIGH
    strict_data: bool = True
    normalize_enabled: bool = True
    ingress_enabled: bool = True
    provenance_enabled: bool = True
    toolauth_enabled: bool = True
    egress_enabled: bool = True


def decide(
    findings: Sequence[Finding],
    policy: Policy,
) -> Decision:
    """
    Resolve findings into a decision, keeping invariant violations out
    of the scored comparison entirely
    """
    if any(finding.invariant for finding in findings):
        return Decision.BLOCK

    scored = [
        finding.severity
        for finding in findings
        if not finding.invariant and finding.severity > Severity.INFO
    ]
    if scored and max(scored) >= policy.block_threshold:
        return Decision.BLOCK

    return Decision.ALLOW
