"""End to end tests for the CLI commands via Typer's CliRunner."""

import json

from typer.testing import CliRunner

from jwt_auditor.main import app
from tests.conftest import build_hs_token, build_none_token


runner = CliRunner()


def test_decode_prints_payload() -> None:
    token = build_hs_token({"sub": "alice"})
    result = runner.invoke(app, ["decode", token])
    assert result.exit_code == 0
    assert "alice" in result.stdout


def test_decode_json_is_parseable() -> None:
    token = build_hs_token({"sub": "alice", "role": "admin"})
    result = runner.invoke(app, ["decode", token, "--json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["payload"]["role"] == "admin"
    assert data["signature"]["algorithm"] == "HS256"


def test_invalid_token_exits_two() -> None:
    result = runner.invoke(app, ["decode", "not-a-jwt"])
    assert result.exit_code == 2


def test_audit_none_token_fails_and_reports_critical() -> None:
    token = build_none_token({"sub": "x"})
    result = runner.invoke(app, ["audit", token])
    assert result.exit_code == 1
    assert "CRITICAL" in result.stdout


def test_audit_json_contains_findings() -> None:
    token = build_none_token({"user_password": "p"})
    result = runner.invoke(app, ["audit", token, "--json"])
    data = json.loads(result.stdout)
    ids = {f["id"] for f in data["findings"]}
    assert "alg-none" in ids
    assert data["risk_score"] > 0


def test_audit_clean_token_passes() -> None:
    payload = {"iss": "a", "aud": "b", "sub": "c"}
    token = build_hs_token(payload, secret = "k4Jd9-random-XYZ-not-in-list")
    # No exp means one medium finding, below the default high fail level.
    result = runner.invoke(app, ["audit", token])
    assert result.exit_code == 0


def test_audit_fail_level_medium_trips_on_missing_exp() -> None:
    payload = {"iss": "a", "aud": "b", "sub": "c"}
    token = build_hs_token(payload, secret = "k4Jd9-random-XYZ-not-in-list")
    result = runner.invoke(app, ["audit", token, "--fail-level", "medium"])
    assert result.exit_code == 1


def test_crack_finds_weak_secret() -> None:
    token = build_hs_token({"sub": "x"}, secret = "changeme")
    result = runner.invoke(app, ["crack", token])
    assert result.exit_code == 0
    assert "changeme" in result.stdout


def test_crack_reports_no_match_for_strong_secret() -> None:
    token = build_hs_token({"sub": "x"}, secret = "k4Jd9-random-XYZ-not-in-list")
    result = runner.invoke(app, ["crack", token])
    assert result.exit_code == 1


def test_crack_rejects_non_hmac_token() -> None:
    # An RS256 token has no shared secret, so crack should refuse it.
    from tests.conftest import build_bare_alg_token

    rs_token = build_bare_alg_token({"sub": "x"}, alg = "RS256")
    result = runner.invoke(app, ["crack", rs_token])
    assert result.exit_code == 1


def test_audit_reads_token_from_stdin() -> None:
    token = build_none_token({"sub": "x"})
    result = runner.invoke(app, ["audit"], input = token)
    assert result.exit_code == 1
    assert "CRITICAL" in result.stdout


def test_audit_reads_token_from_stdin_with_dash() -> None:
    # A literal "-" argument means read from stdin, the usual idiom.
    token = build_none_token({"sub": "x"})
    result = runner.invoke(app, ["audit", "-"], input = token)
    assert result.exit_code == 1
    assert "CRITICAL" in result.stdout
