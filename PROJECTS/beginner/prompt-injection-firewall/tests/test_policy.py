"""
©AngelaMos | 2026
test_policy.py
"""

from not_sandboxed.policy import Policy, decide
from not_sandboxed.verdict import Decision, Finding, Severity


def _finding(
    severity: Severity,
    invariant: bool,
    rule: str = "rule",
) -> Finding:
    return Finding(
        layer = "test",
        rule = rule,
        severity = severity,
        invariant = invariant,
        span_index = None,
        evidence = "",
    )


def test_invariant_finding_forces_block_below_threshold() -> None:
    policy = Policy(block_threshold = Severity.CRITICAL)
    findings = [_finding(Severity.LOW, invariant = True)]
    assert decide(findings, policy) is Decision.BLOCK


def test_scored_finding_below_threshold_allows() -> None:
    policy = Policy(block_threshold = Severity.HIGH)
    findings = [_finding(Severity.MEDIUM, invariant = False)]
    assert decide(findings, policy) is Decision.ALLOW


def test_scored_finding_at_threshold_blocks() -> None:
    policy = Policy(block_threshold = Severity.HIGH)
    findings = [_finding(Severity.HIGH, invariant = False)]
    assert decide(findings, policy) is Decision.BLOCK


def test_no_findings_allows() -> None:
    assert decide([], Policy()) is Decision.ALLOW


def test_info_findings_never_block() -> None:
    policy = Policy(block_threshold = Severity.INFO)
    findings = [
        _finding(
            Severity.INFO,
            invariant = False,
            rule = "layer-disabled"
        )
    ]
    assert decide(findings, policy) is Decision.ALLOW


def test_severity_is_ordered() -> None:
    assert Severity.INFO < Severity.LOW < Severity.MEDIUM
    assert Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
