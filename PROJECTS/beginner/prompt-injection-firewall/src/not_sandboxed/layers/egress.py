"""
©AngelaMos | 2026
egress.py
"""

import codecs
import re
from collections.abc import Callable, Iterable, Sequence
from typing import Final
from urllib.parse import urlsplit

from not_sandboxed import config
from not_sandboxed.normalize.unicode import normalize_unicode
from not_sandboxed.normalize.unwrap import unwrap
from not_sandboxed.verdict import Finding, Severity


_URL: Final = re.compile(config.URL_PATTERN)


def _strip_noise(text: str) -> str:
    return "".join(char for char in text if char.isalnum())


def _strip_separators(text: str) -> str:
    return "".join(
        char for char in text if char not in config.SEPARATOR_CHARS
        and char not in config.ZERO_WIDTH_CHARS
    )


def _rot13(text: str) -> str:
    return codecs.encode(text, "rot13")


def _normalized(text: str) -> str:
    return normalize_unicode(text).text


def _unwrapped(text: str) -> str:
    return unwrap(text).text


_VIEWS: Final[tuple[Callable[[str],
                             str],
                    ...]] = (
                        _normalized,
                        _unwrapped,
                        _strip_separators,
                        _strip_noise,
                        _rot13,
                        lambda text: text[::-1],
                    )


def variants(text: str) -> set[str]:
    """
    Every reading of this text reachable by undoing separators,
    reversal, rot13, and transport encodings in any order

    A fixed pipeline cannot do this: base64 of a dashed secret needs
    decode before strip, and a dashed base64 secret needs strip before
    decode, so the search has to close over the orderings
    """
    seen = {text}
    frontier = [text]

    for _ in range(config.MAX_VARIANT_ROUNDS):
        produced: list[str] = []
        for candidate in frontier:
            for view in _VIEWS:
                try:
                    derived = view(candidate)
                except (ValueError, UnicodeError):
                    continue
                if derived and derived not in seen:
                    seen.add(derived)
                    produced.append(derived)
                if len(seen) >= config.MAX_VARIANTS:
                    return seen
        if not produced:
            break
        frontier = produced

    return seen


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
            if len(canary) >= config.MIN_CANARY_LENGTH
        )
        self.allowed_hosts = tuple(allowed_hosts)

    def inspect_text(self, text: str) -> list[Finding]:
        """
        Report a registered secret leaving in any encoding, and any URL
        aimed at a host the policy does not allow
        """
        findings: list[Finding] = []
        findings.extend(self._canary_findings(text))
        findings.extend(self._url_findings(text))
        return findings

    def _canary_findings(self, text: str) -> Iterable[Finding]:
        if not self.canaries:
            return

        readings = {
            _strip_noise(view).casefold()
            for view in variants(text)
        }

        for canary in self.canaries:
            needle = _strip_noise(canary).casefold()
            if any(needle in reading for reading in readings):
                yield Finding(
                    layer = config.LAYER_EGRESS,
                    rule = config.RULE_CANARY_LEAK,
                    severity = Severity.CRITICAL,
                    invariant = True,
                    evidence = canary,
                )

    def _url_findings(self, text: str) -> Iterable[Finding]:
        for match in _URL.finditer(text):
            host = urlsplit(match.group(0)).hostname or ""
            if host not in self.allowed_hosts:
                yield Finding(
                    layer = config.LAYER_EGRESS,
                    rule = config.RULE_URL_EGRESS,
                    severity = Severity.CRITICAL,
                    invariant = True,
                    evidence = host,
                )
