"""
©AngelaMos | 2026
provenance.py
"""

from not_sandboxed import config
from not_sandboxed.context import Context, Trust
from not_sandboxed.normalize.unicode import normalize_unicode
from not_sandboxed.normalize.unwrap import unwrap
from not_sandboxed.policy import Policy
from not_sandboxed.verdict import Finding, Severity


class ProvenanceLayer:
    """
    The boundary between data and instruction, enforced by a delimiter
    the data cannot predict
    """

    name = config.LAYER_PROVENANCE

    def inspect(
        self,
        ctx: Context,
        policy: Policy,
    ) -> list[Finding]:
        """
        Refuse any untrusted span that contains this request's fence
        nonce, which it has no legitimate way to know
        """
        findings: list[Finding] = []

        for index, span in enumerate(ctx.spans):
            if span.trust is not Trust.DATA:
                continue
            readable = unwrap(normalize_unicode(span.text).text).text
            if ctx.nonce in readable or ctx.nonce in span.text:
                findings.append(
                    Finding(
                        layer = config.LAYER_PROVENANCE,
                        rule = config.RULE_NONCE_FORGERY,
                        severity = Severity.CRITICAL,
                        invariant = True,
                        span_index = index,
                        evidence = "fence nonce present in DATA",
                    )
                )

        return findings
