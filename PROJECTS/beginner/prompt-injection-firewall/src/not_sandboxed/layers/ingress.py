"""
©AngelaMos | 2026
ingress.py
"""

import re
from typing import Final

from not_sandboxed import config
from not_sandboxed.context import Context, Trust
from not_sandboxed.normalize.views import readings
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
        readable = readings(text, config.MAX_INGRESS_VARIANTS)
        findings: list[Finding] = []

        marker = self._first_marker(readable)
        if marker is not None:
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

        hit = self._first_imperative(readable)
        if hit is not None:
            findings.append(
                Finding(
                    layer = config.LAYER_INGRESS,
                    rule = config.RULE_DATA_IMPERATIVE,
                    severity = Severity.MEDIUM,
                    invariant = False,
                    span_index = index,
                    evidence = hit,
                )
            )

        return findings

    def _first_marker(self, readable: set[str]) -> str | None:
        for marker in config.CHAT_TEMPLATE_MARKERS:
            if any(marker in reading for reading in readable):
                return marker
        return None

    def _first_imperative(self, readable: set[str]) -> str | None:
        for pattern in _IMPERATIVES:
            for reading in sorted(readable):
                match = pattern.search(reading)
                if match is not None:
                    return match.group(0)
        return None
