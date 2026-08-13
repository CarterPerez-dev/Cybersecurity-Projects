"""
©AngelaMos | 2026
audit.py
"""

import hashlib
import os
from pathlib import Path

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
        "origin": (
            f"{origin.channel}:{_digest(origin.ref)}"
            if origin is not None else None
        ),
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

    The origin ref is digested along with the evidence because in proxy
    mode it comes straight out of the request body
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


class AuditLog:
    """
    An append-only JSONL sink that writes nothing at all when no path
    is configured, so the default posture keeps no records
    """
    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        if path is not None:
            path.parent.mkdir(parents = True, exist_ok = True)

    @property
    def enabled(self) -> bool:
        """
        Whether this log has somewhere to write
        """
        return self.path is not None

    def write(self, verdict: Verdict, ctx: Context) -> None:
        """
        Append one record, doing nothing when the log is disabled
        """
        if self.path is None:
            return

        with self.path.open("ab") as sink:
            sink.write(audit_record(verdict, ctx))


def audit_log_from_env(variable: str) -> AuditLog:
    """
    Build the sink named by an environment variable, disabled when the
    variable is unset or empty
    """
    raw = os.environ.get(variable, "").strip()
    return AuditLog(Path(raw) if raw else None)
