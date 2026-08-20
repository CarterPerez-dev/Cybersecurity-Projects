"""
©AngelaMos | 2026
views.py
"""

import codecs
from collections.abc import Callable
from typing import Final

from not_sandboxed import config
from not_sandboxed.normalize.unicode import normalize_unicode
from not_sandboxed.normalize.unwrap import embedded_decodes, unwrap


def strip_noise(text: str) -> str:
    """
    Keep only alphanumerics, which is the most aggressive reading and
    the one a separated secret survives
    """
    return "".join(char for char in text if char.isalnum())


def strip_separators(text: str) -> str:
    """
    Drop the characters an attacker inserts to break a literal match,
    keeping the structural characters a decoder still needs
    """
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


def _embedded(text: str) -> str:
    return " ".join(embedded_decodes(text))


def _reversed(text: str) -> str:
    return text[::-1]


_VIEWS: Final[tuple[Callable[[str],
                             str],
                    ...]] = (
                        _normalized,
                        _unwrapped,
                        _embedded,
                        strip_separators,
                        strip_noise,
                        _rot13,
                        _reversed,
                    )


def readings(text: str, max_variants: int) -> set[str]:
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
                if len(seen) >= max_variants:
                    return seen
        if not produced:
            break
        frontier = produced

    return seen
