"""
©AngelaMos | 2026
normalize.py
"""

from not_sandboxed import config
from not_sandboxed.context import Context, Trust
from not_sandboxed.normalize.unicode import normalize_unicode
from not_sandboxed.normalize.unwrap import unwrap
from not_sandboxed.policy import Policy
from not_sandboxed.verdict import Finding


class NormalizeLayer:
    """
    The pre-pass that makes text legible, reporting every transform it
    needed rather than deciding anything
    """

    name = config.LAYER_NORMALIZE

    def inspect(
        self,
        ctx: Context,
        policy: Policy,
    ) -> list[Finding]:
        """
        Report the hiding places found in every span the operator did
        not author
        """
        findings: list[Finding] = []

        for index, span in enumerate(ctx.spans):
            if span.trust is Trust.SYSTEM:
                continue

            unicode_result = normalize_unicode(span.text)
            unwrap_result = unwrap(unicode_result.text)

            for finding in (
                    *unicode_result.findings,
                    *unwrap_result.findings,
            ):
                findings.append(
                    finding.model_copy(update = {"span_index": index})
                )

        return findings
