"""Tests for the individual checks and the audit orchestrator."""

from jwt_auditor import checks
from jwt_auditor.decoder import decode
from jwt_auditor.models import Severity
from tests.conftest import (
    FIXED_NOW,
    ONE_DAY,
    ONE_HOUR,
    build_bare_alg_token,
    build_hs_token,
    build_none_token,
    build_unsigned_token,
)


def _ids(findings: list) -> set[str]:
    return {f.check_id for f in findings}


def test_alg_none_is_critical() -> None:
    token = decode(build_none_token({"sub": "x"}))
    findings = checks.check_alg_none(token)
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].check_id == "alg-none"


def test_alg_none_ignores_signed_token() -> None:
    token = decode(build_hs_token({"sub": "x"}))
    assert checks.check_alg_none(token) == []


def test_unknown_algorithm_flagged() -> None:
    token = decode(build_bare_alg_token({"sub": "x"}, alg = "HS999"))
    findings = checks.check_unknown_algorithm(token)
    assert findings[0].check_id == "alg-unknown"


def test_known_algorithm_not_flagged() -> None:
    token = decode(build_hs_token({"sub": "x"}))
    assert checks.check_unknown_algorithm(token) == []


def test_unsigned_real_alg_is_high() -> None:
    token = decode(build_unsigned_token({"sub": "x"}, alg = "HS256"))
    findings = checks.check_unsigned(token)
    assert findings[0].severity is Severity.HIGH
    assert findings[0].check_id == "empty-signature"


def test_unsigned_ignores_none_alg() -> None:
    token = decode(build_none_token({"sub": "x"}))
    assert checks.check_unsigned(token) == []


def test_weak_secret_recovered() -> None:
    token = decode(build_hs_token({"sub": "x"}, secret = "secret"))
    findings = checks.check_weak_hmac_secret(token, ["secret", "other"])
    assert findings[0].severity is Severity.CRITICAL
    assert "secret" in findings[0].evidence


def test_strong_secret_not_recovered() -> None:
    token = decode(build_hs_token({"sub": "x"}, secret = "k4Jd9-random-XYZ"))
    assert checks.check_weak_hmac_secret(token, ["secret", "admin"]) == []


def test_missing_exp_is_medium() -> None:
    token = decode(build_hs_token({"sub": "x"}))
    findings = checks.check_expiration(token, FIXED_NOW, 24.0)
    assert findings[0].check_id == "missing-exp"
    assert findings[0].severity is Severity.MEDIUM


def test_expired_token_is_info() -> None:
    token = decode(build_hs_token({"sub": "x", "exp": FIXED_NOW - ONE_HOUR}))
    findings = checks.check_expiration(token, FIXED_NOW, 24.0)
    assert findings[0].check_id == "expired"


def test_long_lifetime_is_low() -> None:
    payload = {"sub": "x", "iat": FIXED_NOW, "exp": FIXED_NOW + 5 * ONE_DAY}
    token = decode(build_hs_token(payload))
    findings = checks.check_expiration(token, FIXED_NOW, 24.0)
    assert findings[0].check_id == "long-lifetime"


def test_normal_lifetime_has_no_finding() -> None:
    payload = {"sub": "x", "iat": FIXED_NOW, "exp": FIXED_NOW + ONE_HOUR}
    token = decode(build_hs_token(payload))
    assert checks.check_expiration(token, FIXED_NOW, 24.0) == []


def test_future_iat_flagged() -> None:
    token = decode(build_hs_token({"sub": "x", "iat": FIXED_NOW + ONE_DAY}))
    findings = checks.check_time_sanity(token, FIXED_NOW)
    assert "future-iat" in _ids(findings)


def test_bool_claim_is_not_treated_as_timestamp() -> None:
    # exp = True must not be read as the integer 1
    token = decode(build_hs_token({"sub": "x", "exp": True}))
    findings = checks.check_expiration(token, FIXED_NOW, 24.0)
    assert findings[0].check_id == "missing-exp"


def test_missing_claims_reported() -> None:
    token = decode(build_hs_token({"foo": "bar"}))
    findings = checks.check_missing_claims(token)
    assert findings[0].check_id == "missing-claims"


def test_all_claims_present_not_reported() -> None:
    token = decode(build_hs_token({"iss": "a", "aud": "b", "sub": "c"}))
    assert checks.check_missing_claims(token) == []


def test_sensitive_claim_flagged() -> None:
    token = decode(build_hs_token({"sub": "x", "user_password": "hunter2"}))
    findings = checks.check_sensitive_data(token)
    assert findings[0].severity is Severity.HIGH


def test_audit_terrible_token_scores_high() -> None:
    token = decode(build_none_token({"password": "p"}))
    report = checks.audit(token, now = FIXED_NOW)
    ids = _ids(report.findings)
    assert "alg-none" in ids
    assert "sensitive-claim" in ids
    assert report.risk_score >= 9.0
    assert report.highest_severity is Severity.CRITICAL


def test_audit_clean_token_scores_low() -> None:
    payload = {
        "iss": "auth.example.com",
        "aud": "api.example.com",
        "sub": "user-123",
        "iat": FIXED_NOW,
        "exp": FIXED_NOW + ONE_HOUR,
    }
    token = decode(
        build_hs_token(payload,
                       secret = "k4Jd9-random-XYZ-not-in-list")
    )
    report = checks.audit(token, now = FIXED_NOW)
    assert report.findings == []
    assert report.risk_score == 0.0
    assert report.highest_severity is None


def test_audit_uses_builtin_wordlist_by_default() -> None:
    token = decode(
        build_hs_token({
            "iss": "a",
            "aud": "b",
            "sub": "c"
        },
                       secret = "admin")
    )
    report = checks.audit(token, now = FIXED_NOW)
    assert "weak-hmac-secret" in _ids(report.findings)
