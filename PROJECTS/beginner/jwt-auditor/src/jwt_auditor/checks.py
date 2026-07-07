"""
checks.py

The individual security checks and the audit() orchestrator that runs them.

Each check is a small function that takes a DecodedToken and returns zero or
more Findings. They do not print anything and they do not depend on Rich, so
they are trivial to unit test. audit() wires them together, passes in the
current time and any optional inputs, and collects everything into an
AuditReport.

Key exports:
  audit - run every check and return an AuditReport
  the individual check_* functions, exported for focused testing

Connects to:
  decoder.py - operates on a DecodedToken
  signatures.py - the secret and confusion checks call into it
  wordlist.py - default secrets and sensitive claim names
  models.py - builds Finding and AuditReport
"""

import time
from collections.abc import Iterable
from typing import Any

from jwt_auditor.decoder import DecodedToken
from jwt_auditor.models import AuditReport, Finding, Severity
from jwt_auditor.signatures import (
    crack_hmac_secret,
    key_confusion_secret,
    supported_hmac_algs,
)
from jwt_auditor.wordlist import COMMON_SECRETS, SENSITIVE_CLAIM_KEYS

# Registered JOSE signing algorithms (RFC 7518). Anything outside this set is
# suspicious: either a typo, a custom scheme, or an attacker probing.
_KNOWN_ALGS: frozenset[str] = frozenset(
    {
        "HS256",
        "HS384",
        "HS512",
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512",
        "PS256",
        "PS384",
        "PS512",
        "EdDSA",
        "none",
    }
)

_ASYMMETRIC_PREFIXES: tuple[str, ...] = ("RS", "ES", "PS")

# Tokens that live longer than this without a stated reason are flagged.
_DEFAULT_MAX_LIFETIME_HOURS = 24.0
# A little slack so tokens issued a second in the future by clock skew do not
# trip the "issued in the future" check.
_CLOCK_SKEW_SECONDS = 60.0


def _as_timestamp(payload: dict[str, Any], claim: str) -> float | None:
    """Return a numeric claim as a float, or None if absent or not a number."""
    value = payload.get(claim)
    if isinstance(value, bool):  # bool is an int subclass, reject it explicitly
        return None
    if isinstance(value, int | float):
        return float(value)
    return None


def check_alg_none(token: DecodedToken) -> list[Finding]:
    """Flag the alg none downgrade, where a token carries no signature."""
    if token.algorithm.lower() != "none":
        return []
    return [
        Finding(
            check_id = "alg-none",
            title = "Algorithm is 'none' (unsigned token)",
            severity = Severity.CRITICAL,
            detail = (
                "The header declares alg 'none', meaning the token is not "
                "signed at all. A server that honors this accepts any payload "
                "an attacker types, including admin claims."
            ),
            evidence = f"header.alg = {token.header.get('alg')!r}",
            recommendation = (
                "Reject 'none' outright. Verify against an explicit allowlist "
                "of algorithms and never let the token pick its own."
            ),
        )
    ]


def check_unknown_algorithm(token: DecodedToken) -> list[Finding]:
    """Flag an alg value that is not a registered JOSE algorithm."""
    alg = token.algorithm
    if not alg:
        return [
            Finding(
                check_id = "alg-missing",
                title = "Header has no 'alg' field",
                severity = Severity.MEDIUM,
                detail =
                "Every JWS header must declare an algorithm. This one does not.",
                evidence = f"header keys = {sorted(token.header)}",
                recommendation =
                "Treat a header with no alg as invalid and reject it.",
            )
        ]
    if alg in _KNOWN_ALGS:
        return []
    return [
        Finding(
            check_id = "alg-unknown",
            title = f"Unrecognized algorithm {alg!r}",
            severity = Severity.MEDIUM,
            detail = (
                "The alg is not a registered JOSE algorithm. It may be a typo, "
                "a homegrown scheme, or an attacker probing what the server "
                "will accept."
            ),
            evidence = f"header.alg = {alg!r}",
            recommendation =
            "Verify against a fixed allowlist of known algorithms.",
        )
    ]


def check_unsigned(token: DecodedToken) -> list[Finding]:
    """Flag a token whose signature segment is empty but alg is not none."""
    if token.algorithm.lower() == "none":
        return []  # handled by check_alg_none, do not double report
    if token.signature:
        return []
    return [
        Finding(
            check_id = "empty-signature",
            title = "Signature segment is empty",
            severity = Severity.HIGH,
            detail = (
                "The token declares a real algorithm but carries no signature "
                "bytes. Nothing about the payload is protected."
            ),
            evidence = f"alg {token.algorithm!r} with 0 signature bytes",
            recommendation = "Reject tokens with a missing signature.",
        )
    ]


def check_weak_hmac_secret(
    token: DecodedToken,
    candidates: Iterable[str],
) -> list[Finding]:
    """Try to recover the HMAC secret from a wordlist. A hit is critical."""
    if token.algorithm not in supported_hmac_algs():
        return []
    found = crack_hmac_secret(token, candidates)
    if found is None:
        return []
    return [
        Finding(
            check_id = "weak-hmac-secret",
            title = "HMAC secret recovered from wordlist",
            severity = Severity.CRITICAL,
            detail = (
                "The signing secret was guessed offline. Anyone with the token "
                "and this secret can mint valid tokens with any claims they want."
            ),
            evidence = f"secret = {found!r}",
            recommendation = (
                "Rotate the secret immediately. Use a long random key, at least "
                "32 bytes from a CSPRNG, and store it outside the codebase."
            ),
        )
    ]


def check_key_confusion(
    token: DecodedToken,
    public_key_pem: bytes | None,
) -> list[Finding]:
    """
    Warn about RS/ES/PS tokens and, if given a public key, prove confusion.

    Without a key we can only warn, because the attack depends on how the
    server verifies. With the server's public key we can show whether the
    token verifies when the public key is used as an HMAC secret.
    """
    alg = token.algorithm
    is_asymmetric = alg.startswith(_ASYMMETRIC_PREFIXES)

    if public_key_pem is not None:
        match = key_confusion_secret(token, public_key_pem)
        if match is not None:
            return [
                Finding(
                    check_id = "key-confusion",
                    title = "Token verifies with the public key as an HMAC secret",
                    severity = Severity.CRITICAL,
                    detail = (
                        "This is the RS256 to HS256 confusion attack. The server "
                        "trusts the header algorithm, so an attacker signs an "
                        "HS256 token using the public RSA key, which is not secret."
                    ),
                    evidence = match,
                    recommendation = (
                        "Pin the expected algorithm on the server. Do not let the "
                        "token header choose between HMAC and RSA verification."
                    ),
                )
            ]

    if is_asymmetric:
        return [
            Finding(
                check_id = "asymmetric-alg-review",
                title = f"Asymmetric algorithm {alg} needs a pinned verifier",
                severity = Severity.LOW,
                detail = (
                    "Asymmetric tokens are fine when the server pins the "
                    "algorithm. They become a problem when it accepts the "
                    "header's choice, which enables the HMAC confusion attack. "
                    "Supply the public key with --public-key to test directly."
                ),
                evidence = f"header.alg = {alg!r}",
                recommendation =
                "Confirm the verifier hardcodes the expected algorithm.",
            )
        ]
    return []


def check_expiration(
    token: DecodedToken,
    now: float,
    max_lifetime_hours: float,
) -> list[Finding]:
    """Check exp: missing, already expired, or an unusually long lifetime."""
    findings: list[Finding] = []
    exp = _as_timestamp(token.payload, "exp")

    if exp is None:
        findings.append(
            Finding(
                check_id = "missing-exp",
                title = "No expiration claim",
                severity = Severity.MEDIUM,
                detail = (
                    "The token has no exp, so it is valid forever. A leaked "
                    "token stays useful until the secret is rotated."
                ),
                evidence = "payload has no 'exp'",
                recommendation =
                "Set a short exp, minutes to hours for access tokens.",
            )
        )
        return findings

    if exp < now:
        findings.append(
            Finding(
                check_id = "expired",
                title = "Token is already expired",
                severity = Severity.INFO,
                detail =
                "The exp is in the past. A correct server already rejects it.",
                evidence = f"exp {_fmt_ts(exp)} is before now {_fmt_ts(now)}",
                recommendation =
                "No action if your server checks exp. Confirm that it does.",
            )
        )
        return findings

    iat = _as_timestamp(token.payload, "iat")
    lifetime_seconds = exp - iat if iat is not None else exp - now
    lifetime_hours = lifetime_seconds / 3600.0
    if lifetime_hours > max_lifetime_hours:
        findings.append(
            Finding(
                check_id = "long-lifetime",
                title = "Token lifetime is long",
                severity = Severity.LOW,
                detail = (
                    f"This token is valid for about {lifetime_hours:.1f} hours. "
                    "Long lived access tokens widen the window for a stolen "
                    "token to be used."
                ),
                evidence =
                f"lifetime ~= {lifetime_hours:.1f}h (threshold {max_lifetime_hours:.0f}h)",
                recommendation =
                "Shorten access token lifetime and use refresh tokens.",
            )
        )
    return findings


def check_time_sanity(token: DecodedToken, now: float) -> list[Finding]:
    """Flag iat or nbf values that sit in the future beyond clock skew."""
    findings: list[Finding] = []
    iat = _as_timestamp(token.payload, "iat")
    if iat is not None and iat > now + _CLOCK_SKEW_SECONDS:
        findings.append(
            Finding(
                check_id = "future-iat",
                title = "Issued-at time is in the future",
                severity = Severity.LOW,
                detail = (
                    "The iat claim is later than now. That points to a clock "
                    "problem or a hand edited token."
                ),
                evidence = f"iat {_fmt_ts(iat)} is after now {_fmt_ts(now)}",
                recommendation =
                "Reject tokens issued in the future beyond small skew.",
            )
        )
    nbf = _as_timestamp(token.payload, "nbf")
    if nbf is not None and nbf > now + _CLOCK_SKEW_SECONDS:
        findings.append(
            Finding(
                check_id = "future-nbf",
                title = "Not-before time is in the future",
                severity = Severity.INFO,
                detail = "The nbf claim means the token is not valid yet.",
                evidence = f"nbf {_fmt_ts(nbf)} is after now {_fmt_ts(now)}",
                recommendation =
                "Expected for pre-issued tokens. Confirm it is intentional.",
            )
        )
    return findings


def check_missing_claims(token: DecodedToken) -> list[Finding]:
    """Note common registered claims that are absent."""
    recommended = {
        "iss": "issuer, so the verifier can confirm who minted the token",
        "aud": "audience, so a token for one service is rejected by another",
        "sub": "subject, the identity the token is about",
    }
    absent = [name for name in recommended if name not in token.payload]
    if not absent:
        return []
    listed = ", ".join(f"{name} ({recommended[name]})" for name in absent)
    return [
        Finding(
            check_id = "missing-claims",
            title = "Recommended claims are missing",
            severity = Severity.INFO,
            detail = (
                "These registered claims are not present. They are not required "
                "by the spec, but leaving them out removes checks a verifier "
                f"could otherwise make: {listed}."
            ),
            evidence = f"missing = {absent}",
            recommendation =
            "Add and validate iss, aud, and sub where they apply.",
        )
    ]


def check_sensitive_data(token: DecodedToken) -> list[Finding]:
    """Flag claim names that suggest secrets are riding in the payload."""
    hits = [
        key for key in token.payload
        if any(marker in key.lower() for marker in SENSITIVE_CLAIM_KEYS)
    ]
    if not hits:
        return []
    return [
        Finding(
            check_id = "sensitive-claim",
            title = "Payload may contain sensitive data",
            severity = Severity.HIGH,
            detail = (
                "A JWT payload is only base64url encoded, not encrypted. Anyone "
                "holding the token reads these claims in plain text."
            ),
            evidence = f"suspicious claim names = {hits}",
            recommendation = (
                "Never put passwords, keys, or PII in a JWT. Store them server "
                "side and reference by an opaque id."
            ),
        )
    ]


def audit(
    token: DecodedToken,
    *,
    now: float | None = None,
    wordlist: Iterable[str] | None = None,
    public_key_pem: bytes | None = None,
    max_lifetime_hours: float = _DEFAULT_MAX_LIFETIME_HOURS,
) -> AuditReport:
    """
    Run every check against a token and return the collected report.

    now defaults to the wall clock. Tests pass a fixed value so time based
    checks are deterministic. wordlist defaults to the built in COMMON_SECRETS.
    """
    current = time.time() if now is None else now
    secrets = COMMON_SECRETS if wordlist is None else wordlist

    findings: list[Finding] = []
    findings += check_alg_none(token)
    findings += check_unknown_algorithm(token)
    findings += check_unsigned(token)
    findings += check_weak_hmac_secret(token, secrets)
    findings += check_key_confusion(token, public_key_pem)
    findings += check_expiration(token, current, max_lifetime_hours)
    findings += check_time_sanity(token, current)
    findings += check_missing_claims(token)
    findings += check_sensitive_data(token)

    return AuditReport(token = token, findings = findings)


def _fmt_ts(value: float) -> str:
    """Format a unix timestamp as a readable UTC string for evidence text."""
    stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(value))
    return f"{stamp} UTC"
