"""
©AngelaMos | 2026
egress.py
"""

import re
from collections.abc import Iterable, Sequence
from typing import Final
from urllib.parse import urlsplit

from not_sandboxed import config
from not_sandboxed.normalize.views import readings, strip_noise
from not_sandboxed.verdict import Finding, Severity


_URL: Final = re.compile(config.URL_PATTERN)


def variants(text: str) -> set[str]:
    """
    Every reading of this text the canary matcher has to consider
    """
    return readings(text, config.MAX_VARIANTS)


def _host_of(candidate: str) -> str:
    if candidate.startswith(config.PROTOCOL_RELATIVE_PREFIX):
        candidate = f"{config.URL_SCHEME_PREFIX}{candidate}"
    return urlsplit(candidate).hostname or ""


class EgressLayer:
    """
    The last boundary, where a registered secret must not leave in any
    encoding and untrusted hosts must not be contacted
    """

    name = config.LAYER_EGRESS

    def __init__(
        self,
        canaries: Sequence[str] = (),
        allowed_hosts: Sequence[str] = (),
    ) -> None:
        self.canaries = tuple(
            canary for canary in canaries
            if len(strip_noise(canary)) >= config.MIN_CANARY_LENGTH
        )
        self.rejected = tuple(
            canary for canary in canaries
            if len(strip_noise(canary)) < config.MIN_CANARY_LENGTH
        )
        self.allowed_hosts = tuple(host.lower() for host in allowed_hosts)

    def _allows(self, host: str) -> bool:
        for allowed in self.allowed_hosts:
            if allowed.startswith(config.HOST_SUFFIX_MARKER):
                if host == allowed[1 :] or host.endswith(allowed):
                    return True
            elif host == allowed:
                return True
        return False

    def inspect_text(self, text: str) -> list[Finding]:
        """
        Report a registered secret leaving in any encoding, and any URL
        aimed at a host the policy does not allow
        """
        if len(text) > config.MAX_EGRESS_BYTES:
            return [
                Finding(
                    layer = config.LAYER_EGRESS,
                    rule = config.RULE_OUTPUT_TOO_LARGE,
                    severity = Severity.CRITICAL,
                    invariant = True,
                    evidence = f"{len(text)} chars",
                )
            ]

        findings: list[Finding] = []
        findings.extend(self._canary_findings(text))
        findings.extend(self._url_findings(text))
        return findings

    def _canary_findings(self, text: str) -> Iterable[Finding]:
        if not self.canaries:
            return

        readable = {
            strip_noise(view).casefold()
            for view in variants(text)
        }

        for canary in self.canaries:
            needle = strip_noise(canary).casefold()
            if any(needle in reading for reading in readable):
                yield Finding(
                    layer = config.LAYER_EGRESS,
                    rule = config.RULE_CANARY_LEAK,
                    severity = Severity.CRITICAL,
                    invariant = True,
                    evidence = canary,
                )

    def _url_findings(self, text: str) -> Iterable[Finding]:
        for match in _URL.finditer(text):
            host = _host_of(match.group(0)).lower()
            if not self._allows(host):
                yield Finding(
                    layer = config.LAYER_EGRESS,
                    rule = config.RULE_URL_EGRESS,
                    severity = Severity.CRITICAL,
                    invariant = True,
                    evidence = host,
                )
