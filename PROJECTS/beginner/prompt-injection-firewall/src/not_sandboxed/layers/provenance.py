"""
©AngelaMos | 2026
provenance.py
"""

from not_sandboxed import config
from not_sandboxed.context import Context, Trust
from not_sandboxed.normalize.views import readings, strip_noise
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
        needle = strip_noise(ctx.nonce).casefold()

        for index, span in enumerate(ctx.spans):
            if span.trust is not Trust.DATA:
                continue
            if self._carries(span.text, needle):
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

    def _carries(self, text: str, needle: str) -> bool:
        return any(
            needle in strip_noise(reading).casefold()
            for reading in readings(text, config.MAX_INGRESS_VARIANTS)
        )
