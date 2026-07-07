"""
jwt-auditor

A command line tool that decodes JSON Web Tokens and audits them for the
security mistakes that show up again and again: the alg none downgrade,
weak HMAC secrets, the RS256 to HS256 confusion attack, tokens that never
expire, and secrets carried in the payload.

Everything runs offline against a token string. No network, no PyJWT.

Public surface:
  decode - parse a token into its pieces (from decoder)
  audit - run the full check suite (from checks)
  AuditReport, Finding, Severity - the result types (from models)

Connects to:
  decoder.py - token parsing
  checks.py - the audit orchestrator
  models.py - shared data types
"""

from jwt_auditor.checks import audit
from jwt_auditor.decoder import DecodedToken, InvalidTokenError, decode
from jwt_auditor.models import AuditReport, Finding, Severity


__version__ = "0.1.0"
__all__ = [
    "AuditReport",
    "DecodedToken",
    "Finding",
    "InvalidTokenError",
    "Severity",
    "audit",
    "decode",
]
