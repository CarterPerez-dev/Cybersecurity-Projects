"""Tests for the shared data models and risk scoring."""

from jwt_auditor.decoder import decode
from jwt_auditor.models import AuditReport, Finding, Severity
from tests.conftest import build_hs_token


def _finding(sev: Severity, check_id: str = "x") -> Finding:
    return Finding(check_id = check_id, title = "t", severity = sev, detail = "d")


def test_severity_weight_and_rank_order() -> None:
    assert Severity.CRITICAL.weight > Severity.INFO.weight
    assert Severity.CRITICAL.rank < Severity.HIGH.rank < Severity.INFO.rank


def test_empty_report_scores_zero() -> None:
    token = decode(build_hs_token({"sub": "x"}))
    report = AuditReport(token = token, findings = [])
    assert report.risk_score == 0.0
    assert report.highest_severity is None


def test_single_critical_scores_ten() -> None:
    token = decode(build_hs_token({"sub": "x"}))
    report = AuditReport(token = token, findings = [_finding(Severity.CRITICAL)])
    assert report.risk_score == 10.0


def test_score_is_capped_at_ten() -> None:
    token = decode(build_hs_token({"sub": "x"}))
    findings = [_finding(Severity.CRITICAL, f"c{i}") for i in range(5)]
    report = AuditReport(token = token, findings = findings)
    assert report.risk_score == 10.0


def test_extra_findings_raise_score() -> None:
    token = decode(build_hs_token({"sub": "x"}))
    one = AuditReport(token = token, findings = [_finding(Severity.LOW, "a")])
    two = AuditReport(
        token = token,
        findings = [_finding(Severity.LOW,
                             "a"),
                    _finding(Severity.LOW,
                             "b")],
    )
    assert two.risk_score > one.risk_score


def test_sorted_findings_are_worst_first() -> None:
    token = decode(build_hs_token({"sub": "x"}))
    report = AuditReport(
        token = token,
        findings = [
            _finding(Severity.LOW,
                     "a"),
            _finding(Severity.CRITICAL,
                     "b")
        ],
    )
    assert next(f.severity for f in report.sorted_findings) is Severity.CRITICAL


def test_counts_by_severity() -> None:
    token = decode(build_hs_token({"sub": "x"}))
    report = AuditReport(
        token = token,
        findings = [_finding(Severity.HIGH,
                             "a"),
                    _finding(Severity.HIGH,
                             "b")],
    )
    counts = report.counts_by_severity()
    assert counts[Severity.HIGH] == 2
    assert counts[Severity.LOW] == 0
