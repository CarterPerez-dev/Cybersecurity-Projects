"""
©AngelaMos | 2026
unwrap.py
"""

import base64
import binascii
import quopri
import urllib.parse
from collections.abc import Callable

from pydantic import BaseModel, ConfigDict

from not_sandboxed import config
from not_sandboxed.verdict import Finding, Severity


class UnwrapResult(BaseModel):
    """
    Text with its transport encodings peeled off, and how many layers
    had to come off to read it
    """

    model_config = ConfigDict(frozen = True)

    text: str
    depth: int = 0
    findings: tuple[Finding, ...] = ()


def _printable_ratio(text: str) -> float:
    considered = [
        char for char in text if char not in config.ZERO_WIDTH_CHARS
        and char not in config.BIDI_CONTROLS
    ]
    if not considered:
        return 0.0
    printable = sum(
        1 for char in considered if char.isprintable() or char in "\n\r\t"
    )
    return printable / len(considered)


def _looks_decoded(candidate: str) -> bool:
    return (
        bool(candidate)
        and _printable_ratio(candidate) >= config.MIN_PRINTABLE_RATIO
    )


def _mostly(text: str, alphabet: frozenset[str]) -> bool:
    stripped = text.strip()
    if len(stripped) < config.MIN_ENCODED_LENGTH:
        return False
    return all(char in alphabet for char in stripped)


def _try_base64(text: str) -> str | None:
    stripped = text.strip()
    if not _mostly(text, config.BASE64_ALPHABET):
        return None
    if len(stripped) % 4 != 0:
        return None
    try:
        raw = base64.b64decode(stripped, validate = True)
    except (binascii.Error, ValueError):
        return None
    return _as_text(raw)


def _try_base32(text: str) -> str | None:
    stripped = text.strip()
    if not _mostly(text, config.BASE32_ALPHABET):
        return None
    if len(stripped) % 8 != 0:
        return None
    try:
        raw = base64.b32decode(stripped)
    except (binascii.Error, ValueError):
        return None
    return _as_text(raw)


def _try_hex(text: str) -> str | None:
    stripped = text.strip()
    if not _mostly(text, config.HEX_ALPHABET):
        return None
    if len(stripped) % 2 != 0:
        return None
    try:
        raw = bytes.fromhex(stripped)
    except ValueError:
        return None
    return _as_text(raw)


def _try_percent(text: str) -> str | None:
    if "%" not in text:
        return None
    candidate = urllib.parse.unquote(text, errors = "strict")
    if candidate == text:
        return None
    return candidate


def _try_quoted_printable(text: str) -> str | None:
    if "=" not in text:
        return None
    try:
        raw = quopri.decodestring(text.encode())
    except ValueError:
        return None
    candidate = _as_text(raw)
    if candidate is None or candidate == text:
        return None
    return candidate


def _as_text(raw: bytes) -> str | None:
    try:
        return raw.decode()
    except UnicodeDecodeError:
        return None


_CODECS: tuple[Callable[[str],
                        str | None],
               ...] = (
                   _try_base64,
                   _try_base32,
                   _try_hex,
                   _try_percent,
                   _try_quoted_printable,
               )


def _peel(text: str) -> str | None:
    for codec in _CODECS:
        try:
            candidate = codec(text)
        except (ValueError, binascii.Error):
            continue
        if candidate and candidate != text and _looks_decoded(candidate):
            return candidate
    return None


def unwrap(text: str) -> UnwrapResult:
    """
    Peel transport encodings until the text stops changing or the
    budget runs out, never crashing on hostile input
    """
    if len(text) > config.MAX_NORMALIZE_BYTES:
        return UnwrapResult(
            text = text,
            depth = 0,
            findings = (
                Finding(
                    layer = config.LAYER_NORMALIZE,
                    rule = config.RULE_INPUT_TOO_LARGE,
                    severity = Severity.HIGH,
                    invariant = False,
                    evidence = f"{len(text)} chars",
                ),
            ),
        )

    findings: list[Finding] = []
    working = text
    depth = 0

    while depth < config.MAX_DECODE_DEPTH:
        candidate = _peel(working)
        if candidate is None:
            break
        working = candidate
        depth += 1

    if depth and _peel(working) is not None:
        findings.append(
            Finding(
                layer = config.LAYER_NORMALIZE,
                rule = config.RULE_DECODE_BUDGET,
                severity = Severity.HIGH,
                invariant = False,
                evidence = f"stopped at depth {depth}",
            )
        )
    elif depth:
        findings.append(
            Finding(
                layer = config.LAYER_NORMALIZE,
                rule = config.RULE_TRANSPORT_ENCODED,
                severity = Severity.MEDIUM,
                invariant = False,
                evidence = f"unwrapped {depth} layers",
            )
        )

    return UnwrapResult(
        text = working,
        depth = depth,
        findings = tuple(findings),
    )
