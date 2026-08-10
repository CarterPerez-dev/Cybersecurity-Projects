"""
©AngelaMos | 2026
ingress.py
"""

import re
from typing import Final

from not_sandboxed import config
from not_sandboxed.context import Context, Trust
from not_sandboxed.normalize.unicode import normalize_unicode
from not_sandboxed.normalize.unwrap import unwrap
from not_sandboxed.policy import Policy
from not_sandboxed.verdict import Finding, Severity


_IMPERATIVES: Final = tuple(
    re.compile(pattern,
               re.IGNORECASE)
    for pattern in config.DATA_IMPERATIVE_PATTERNS
)


class IngressLayer:
    """
    Best-effort text inspection, scoped to untrusted spans because the
    same sentence is ordinary from a user and hostile from a document
    """

    name = config.LAYER_INGRESS

    def inspect(
        self,
        ctx: Context,
        policy: Policy,
    ) -> list[Finding]:
        """
        Report template-token forgery and instruction-shaped text
        found inside untrusted content
        """
        findings: list[Finding] = []

        for index, span in enumerate(ctx.spans):
            if span.trust is not Trust.DATA:
                continue
            findings.extend(self._inspect_span(span.text, index))

        return findings

    def _inspect_span(
        self,
        text: str,
        index: int,
    ) -> list[Finding]:
        readable = unwrap(normalize_unicode(text).text).text
        findings: list[Finding] = []

        for marker in config.CHAT_TEMPLATE_MARKERS:
            if marker in readable:
                findings.append(
                    Finding(
                        layer = config.LAYER_INGRESS,
                        rule = config.RULE_TEMPLATE_MARKER,
                        severity = Severity.HIGH,
                        invariant = False,
                        span_index = index,
                        evidence = marker,
                    )
                )
                break

        for pattern in _IMPERATIVES:
            match = pattern.search(readable)
            if match is not None:
                findings.append(
                    Finding(
                        layer = config.LAYER_INGRESS,
                        rule = config.RULE_DATA_IMPERATIVE,
                        severity = Severity.MEDIUM,
                        invariant = False,
                        span_index = index,
                        evidence = match.group(0),
                    )
                )
                break

        return findings
