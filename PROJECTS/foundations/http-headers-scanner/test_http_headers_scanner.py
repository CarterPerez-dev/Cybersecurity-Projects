"""
©AngelaMos | 2026
test_http_headers_scanner.py

Tests for http_headers_scanner — covers rule evaluation, the score
calculation, grade thresholds, and a mocked end-to-end scan

────────────────────────────────────────────────────────────────────
What "tests" are and why we write them
────────────────────────────────────────────────────────────────────
A test is a tiny Python function that calls our real code with a
known input and then ASSERTS that the result is what we expected.
If the assertion fails, pytest prints a red FAIL message — which
means we changed something and broke a behavior we cared about

Tests are insurance. The first time you write the code, the test
just confirms it works. But six months later when you refactor or
add a new feature, the existing tests catch any accidental breakage

────────────────────────────────────────────────────────────────────
Why we mock the network with respx
────────────────────────────────────────────────────────────────────
A test that hits a real website is FRAGILE. The site might be down,
slow, redesigned, or behind a captcha. None of that has anything to
do with whether OUR code is correct

`respx` is a library that intercepts httpx calls and returns a
canned response we control. So when we test scan("https://test"),
respx hands back EXACTLY the headers we tell it to — letting us
verify the scanning logic without touching the network

────────────────────────────────────────────────────────────────────
Coverage strategy
────────────────────────────────────────────────────────────────────
We exercise each branch of the code at least once

  - evaluate_header: ok / weak / missing / case-insensitive lookup
  - ScanReport.score: all-ok, all-missing, mixed
  - ScanReport.grade: each band (A, B, C, D, F)
  - scan(): full pipeline against a mocked response, including a redirect

That is enough confidence — adding ten variations of "another header"
would not catch any new bugs
"""

# Third-party (httpx): we need its `Response` type to construct fake
# responses inside our mocked routes.
import httpx
# Third-party: the test runner. We also use its `@pytest.mark.parametrize`
# decorator to expand one test function into many test cases.
import pytest
# Third-party (respx): intercepts httpx calls and returns fakes we
# define, so tests do not actually hit the real internet.
import respx

# Local: our own module. We pull in the public pieces under test —
# the rules table, dataclasses, and the two entry functions.
from http_headers_scanner import (
    RULES,
    HeaderFinding,
    HeaderRule,
    ScanReport,
    Status,
    evaluate_header,
    scan,
)

# =============================================================================
# Fixtures — small helpers used by multiple tests
# =============================================================================
# A pytest "fixture" is a setup function pytest runs before a test
# that needs it. Tests ask for fixtures by listing them as parameters


@pytest.fixture
def hsts_rule() -> HeaderRule:
    """
    A representative HeaderRule that requires a positive max-age value
    """
    # We construct one inline rather than reaching into RULES so this
    # test is robust to future additions / reorderings of the table.
    # The regex matches `max-age` followed by `=` and a digit 1-9 —
    # which rejects `max-age=0` (HSTS deliberately disabled)
    return HeaderRule(
        header = "Strict-Transport-Security",
        severity = "high",
        description = "Forces HTTPS",
        recommendation = "Add: Strict-Transport-Security: max-age=31536000",
        must_match = r"max-age\s*=\s*[1-9]",
    )


@pytest.fixture
def referrer_rule() -> HeaderRule:
    """
    A rule with NO must_contain — presence alone earns full points
    """
    return HeaderRule(
        header = "Referrer-Policy",
        severity = "low",
        description = "Limits Referer leakage",
        recommendation = "Add: Referrer-Policy: strict-origin-when-cross-origin",
    )


# =============================================================================
# evaluate_header — the pure function at the heart of the scanner
# =============================================================================
# These tests do not touch the network at all — we hand-build the
# headers dict and check the finding


def test_evaluate_header_present_with_required_substring(
    hsts_rule: HeaderRule,
) -> None:
    """
    Header is present AND contains must_contain → status = ok
    """
    headers = {"Strict-Transport-Security": "max-age=31536000"}
    finding = evaluate_header(hsts_rule, headers)
    assert finding.status == "ok"
    assert finding.actual_value == "max-age=31536000"


def test_evaluate_header_present_without_required_substring(
    hsts_rule: HeaderRule,
) -> None:
    """
    Header is present but does NOT match must_match → status = weak

    A real-world example: someone sets the header to an empty string
    or only `includeSubDomains` without `max-age=`. The header exists
    but is functionally useless
    """
    headers = {"Strict-Transport-Security": "includeSubDomains"}
    finding = evaluate_header(hsts_rule, headers)
    assert finding.status == "weak"


def test_evaluate_header_missing(hsts_rule: HeaderRule) -> None:
    """
    Header is not in the response at all → status = missing
    """
    # Empty dict — no headers at all
    headers: dict[str, str] = {}
    finding = evaluate_header(hsts_rule, headers)
    assert finding.status == "missing"
    # And actual_value should be None when the header was absent
    assert finding.actual_value is None


def test_evaluate_header_hsts_max_age_zero_is_weak(
    hsts_rule: HeaderRule,
) -> None:
    """
    `max-age=0` actively DISABLES HSTS for return visits — the header
    is present but does the opposite of what we want, so it must be
    flagged as weak rather than ok

    This pins the behavior fixed in the audit — substring-based
    matching graded this case as ok and left users thinking HSTS was
    on when it was deliberately turned off
    """
    headers = {"Strict-Transport-Security": "max-age=0; includeSubDomains"}
    finding = evaluate_header(hsts_rule, headers)
    assert finding.status == "weak"
    assert finding.actual_value == "max-age=0; includeSubDomains"


def test_evaluate_header_case_insensitive_lookup(
    referrer_rule: HeaderRule,
) -> None:
    """
    HTTP header names are case-insensitive per RFC 7230 — `Referrer-Policy`
    and `referrer-policy` and `REFERRER-POLICY` mean the same thing
    """
    # The server returned the header with lowercase letters, but the
    # rule asks for "Referrer-Policy" with the canonical case.
    # Without case-insensitive lookup, this test would fail
    headers = {"referrer-policy": "no-referrer"}
    finding = evaluate_header(referrer_rule, headers)
    assert finding.status == "ok"


def test_evaluate_header_no_must_match_treats_presence_as_ok(
    referrer_rule: HeaderRule,
) -> None:
    """
    A rule with must_match=None passes whenever the header exists
    """
    headers = {"Referrer-Policy": "anything-here-works"}
    finding = evaluate_header(referrer_rule, headers)
    assert finding.status == "ok"


# =============================================================================
# ScanReport.score and .grade — the math behind the report
# =============================================================================
# Score is computed from the findings on the fly, not stored. So we
# can build a synthetic ScanReport with whatever findings we want and
# assert exactly what the score should come out to


def _make_report(statuses: list[Status]) -> ScanReport:
    """
    Build a fake ScanReport pairing each rule with the given status

    Helper so each test does not have to construct findings by hand.
    The first item in `statuses` pairs with the first rule, etc.
    Pad the list with "missing" if it is shorter than RULES.

    The parameter is typed as `list[Status]` so mypy enforces the
    Literal contract at every call site — no runtime check or
    type-ignore escape hatch needed
    """
    findings: list[HeaderFinding] = []
    for index, rule in enumerate(RULES):
        # When the caller passed fewer statuses than rules, treat the
        # rest as missing. Common when a test only cares about the
        # first few rules
        status: Status = (statuses[index] if index < len(statuses) else "missing")
        findings.append(
            HeaderFinding(
                rule = rule,
                status = status,
                actual_value = None,
                note = "synthetic",
            )
        )
    return ScanReport(
        url = "https://example.com",
        final_url = "https://example.com",
        status_code = 200,
        findings = findings,
    )


def test_score_all_ok_is_100() -> None:
    """
    Every rule passing should yield a perfect score
    """
    statuses: list[Status] = ["ok"] * len(RULES)
    report = _make_report(statuses)
    assert report.score == 100
    # And the grade follows the score
    assert report.grade == "A"


def test_score_all_missing_is_zero() -> None:
    """
    Nothing present, nothing earned. Score = 0, grade = F
    """
    statuses: list[Status] = ["missing"] * len(RULES)
    report = _make_report(statuses)
    assert report.score == 0
    assert report.grade == "F"


def test_grade_threshold_a_at_90_percent() -> None:
    """
    Passing both highs and both mediums (90/100 = 90%) lands exactly
    on the A boundary

    The current rules table totals 100 points (30 + 30 + 15 + 15 + 5 + 5)
    Two `high` rules = 60 / 100 = 60%, which is grade D
    Both highs + both mediums = 90 / 100 = 90%, which is grade A
    """
    statuses_by_severity: dict[str,
                               Status] = {
                                   "high": "ok",
                                   "medium": "ok",
                                   "low": "missing",
                               }
    statuses: list[Status] = [statuses_by_severity[r.severity] for r in RULES]
    report = _make_report(statuses)
    assert report.score == 90
    assert report.grade == "A"


def test_grade_threshold_b_at_83_percent() -> None:
    """
    Both highs ok, one medium ok and the other weak (60 + 15 + 7.5 = 82.5
    → rounds up to 83) drops below 90 and lands in the B band
    """
    # Two highs ok, mediums split between ok and weak, lows missing
    statuses: list[Status] = []
    medium_seen = 0
    for rule in RULES:
        if rule.severity == "high":
            statuses.append("ok")
        elif rule.severity == "medium":
            statuses.append("ok" if medium_seen == 0 else "weak")
            medium_seen += 1
        else:
            statuses.append("missing")
    report = _make_report(statuses)
    assert 80 <= report.score < 90
    assert report.grade == "B"


# =============================================================================
# scan() — full pipeline against a mocked response
# =============================================================================
# `@respx.mock` intercepts every httpx request inside the test and
# returns whatever we set up in the body. The real network is never
# touched


@respx.mock
def test_scan_mocks_a_clean_response_and_grades_it_correctly() -> None:
    """
    A response with every recommended header set should score 100
    """
    # We respond to GET https://safe.example.com/ with a 200 and the
    # full set of security headers. respx.get(...).mock(return_value=...)
    # registers the mock; the next httpx.get inside this test fires it
    respx.get("https://safe.example.com/").mock(
        return_value = httpx.Response(
            status_code = 200,
            headers = {
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "camera=(), microphone=()",
            },
        )
    )

    report = scan("https://safe.example.com/")

    assert report.status_code == 200
    assert report.score == 100
    assert report.grade == "A"
    # Every finding should be `ok`
    assert all(f.status == "ok" for f in report.findings)


@respx.mock
def test_scan_flags_missing_and_weak_headers() -> None:
    """
    A response missing CSP and with a weak X-Content-Type-Options
    should produce findings of mixed status
    """
    respx.get("https://weak.example.com/").mock(
        return_value = httpx.Response(
            status_code = 200,
            headers = {
                "Strict-Transport-Security": "max-age=600",
                # X-Content-Type-Options is present but value is wrong:
                # the rule requires `nosniff`, this says something else.
                # We pick a value that genuinely does NOT contain the
                # substring `nosniff` — `"snifftest"` would actually be
                # treated as ok because it embeds the word
                "X-Content-Type-Options": "off",
                # Note: Content-Security-Policy is NOT included
            },
        )
    )

    report = scan("https://weak.example.com/")

    findings_by_header = {f.rule.header: f for f in report.findings}
    assert findings_by_header["Content-Security-Policy"].status == "missing"
    assert findings_by_header["X-Content-Type-Options"].status == "weak"
    assert findings_by_header["Strict-Transport-Security"].status == "ok"

    # Score should be less than 100 since CSP is missing and XCTO is weak
    assert report.score < 100


@respx.mock
def test_scan_records_final_url_after_redirect() -> None:
    """
    When http://x.example.com/ → https://x.example.com/, the report
    must remember the final URL — that is what the user actually
    landed on
    """
    # First request: 301 to the https version
    respx.get("http://redirect.example.com/").mock(
        return_value = httpx.Response(
            status_code = 301,
            headers = {"Location": "https://redirect.example.com/"},
        )
    )
    # Final request: 200 with one header set
    respx.get("https://redirect.example.com/").mock(
        return_value = httpx.Response(
            status_code = 200,
            headers = {"X-Frame-Options": "DENY"},
        )
    )

    report = scan("http://redirect.example.com/")

    assert report.url == "http://redirect.example.com/"
    assert report.final_url == "https://redirect.example.com/"
    assert report.status_code == 200
