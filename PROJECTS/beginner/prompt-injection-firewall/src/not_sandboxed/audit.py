"""
©AngelaMos | 2026
audit.py
"""

import hashlib

import orjson

from not_sandboxed import config
from not_sandboxed.context import Context, Span
from not_sandboxed.verdict import Finding, Verdict


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()
                          ).hexdigest()[: config.AUDIT_DIGEST_CHARS]


def _span_entry(span: Span) -> dict[str, str | None]:
    origin = span.origin
    return {
        "trust":
        str(span.trust),
        "origin":
        (f"{origin.channel}:{origin.ref}" if origin is not None else None),
    }


def _finding_entry(finding: Finding) -> dict[str, object]:
    return {
        "layer": finding.layer,
        "rule": finding.rule,
        "severity": finding.severity.name,
        "invariant": finding.invariant,
        "span_index": finding.span_index,
        "evidence_digest": _digest(finding.evidence),
    }


def audit_record(verdict: Verdict, ctx: Context) -> bytes:
    """
    Serialise one inspection as a JSONL line that carries no attacker
    content, so the log is safe to keep
    """
    payload = {
        "policy_id": verdict.policy_id,
        "decision": str(verdict.decision),
        "elapsed_ms": round(verdict.elapsed_ms,
                            3),
        "spans": [_span_entry(span) for span in ctx.spans],
        "findings":
        [_finding_entry(finding) for finding in verdict.findings],
    }
    return orjson.dumps(payload) + b"\n"
