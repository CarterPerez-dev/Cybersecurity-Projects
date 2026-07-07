"""
wordlist.py

The built in list of weak HMAC secrets and the sensitive claim patterns.

The secrets here are the ones that actually show up. "your-256-bit-secret"
is the placeholder from the jwt.io debugger that people ship to production.
"secret", "changeme", and single dictionary words are what you get when a
developer picks a key by hand instead of generating one. This list is small
on purpose. It exists so the audit command finds the obvious cases with no
setup. Point at a real wordlist with --wordlist when you want depth.

Key exports:
  COMMON_SECRETS - built in weak HMAC secrets to try
  SENSITIVE_CLAIM_KEYS - claim names that should never hold real values
  load_wordlist - read newline separated secrets from a file

Connects to:
  checks.py - the weak secret and sensitive data checks read these
  main.py - the crack command falls back to COMMON_SECRETS
"""

from pathlib import Path


COMMON_SECRETS: tuple[str,
                      ...] = (
                          "secret",
                          "password",
                          "changeme",
                          "admin",
                          "test",
                          "jwt",
                          "key",
                          "private",
                          "secretkey",
                          "supersecret",
                          "your-256-bit-secret",
                          "your-384-bit-secret",
                          "your-512-bit-secret",
                          "s3cr3t",
                          "123456",
                          "12345678",
                          "qwerty",
                          "letmein",
                          "default",
                          "token",
                          "hmac",
                          "signature",
                          "root",
                          "0000",
                      )


# Claim names that suggest sensitive data is being carried in the payload.
# A JWT payload is only base64url encoded, so anyone holding the token can
# read these. Matched case insensitively against claim keys.
SENSITIVE_CLAIM_KEYS: tuple[str,
                            ...] = (
                                "password",
                                "passwd",
                                "pwd",
                                "secret",
                                "api_key",
                                "apikey",
                                "access_key",
                                "private_key",
                                "ssn",
                                "social_security",
                                "credit_card",
                                "card_number",
                                "cvv",
                                "pin",
                                "bank_account",
                                "session_secret",
                            )


def load_wordlist(path: Path) -> list[str]:
    """
    Read a wordlist file into a list of candidate secrets.

    Blank lines are skipped. Everything else is kept verbatim, including
    leading or trailing spaces stripped only at the line ends, because a
    secret can legitimately contain internal spaces.
    """
    lines = path.read_text(encoding = "utf-8", errors = "replace").splitlines()
    return [line for line in (raw.strip() for raw in lines) if line]
