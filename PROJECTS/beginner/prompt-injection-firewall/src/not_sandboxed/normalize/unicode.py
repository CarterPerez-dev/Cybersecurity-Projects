"""
©AngelaMos | 2026
unicode.py
"""

import unicodedata

from pydantic import BaseModel, ConfigDict

from not_sandboxed import config
from not_sandboxed.verdict import Finding, Severity


class TagBlockResult(BaseModel):
    """
    What a span looks like once the Unicode tag block is accounted for
    """

    model_config = ConfigDict(frozen = True)

    visible: str
    recovered: str
    unmasked: str
    finding: Finding | None = None


def _is_tag_char(char: str) -> bool:
    return (config.TAG_BLOCK_START <= ord(char) <= config.TAG_BLOCK_END)


def decode_tag_block(text: str) -> TagBlockResult:
    """
    Recover a payload hidden in the Unicode tag block, which renders as
    nothing at all in every mainstream client
    """
    visible_parts: list[str] = []
    unmasked_parts: list[str] = []
    recovered_parts: list[str] = []

    for char in text:
        if _is_tag_char(char):
            plain = chr(ord(char) - config.TAG_BLOCK_START)
            recovered_parts.append(plain)
            unmasked_parts.append(plain)
        else:
            visible_parts.append(char)
            unmasked_parts.append(char)

    recovered = "".join(recovered_parts)
    finding = None
    if recovered:
        finding = Finding(
            layer = config.LAYER_NORMALIZE,
            rule = config.RULE_TAG_SMUGGLING,
            severity = Severity.HIGH,
            invariant = False,
            evidence = recovered,
        )

    return TagBlockResult(
        visible = "".join(visible_parts),
        recovered = recovered,
        unmasked = "".join(unmasked_parts),
        finding = finding,
    )


class UnicodeResult(BaseModel):
    """
    Text with every hiding place accounted for, plus a record of what
    had to be done to read it
    """

    model_config = ConfigDict(frozen = True)

    text: str
    findings: tuple[Finding, ...] = ()


def _strip(
    text: str,
    banned: frozenset[str],
    rule: str,
    severity: Severity,
) -> tuple[str,
           Finding | None]:
    removed = [char for char in text if char in banned]
    if not removed:
        return text, None

    kept = "".join(char for char in text if char not in banned)
    finding = Finding(
        layer = config.LAYER_NORMALIZE,
        rule = rule,
        severity = severity,
        invariant = False,
        evidence = f"{len(removed)} removed",
    )
    return kept, finding


def _fold_confusables(text: str) -> tuple[str, Finding | None]:
    folded = "".join(config.CONFUSABLES.get(c, c) for c in text)
    if folded == text:
        return text, None

    finding = Finding(
        layer = config.LAYER_NORMALIZE,
        rule = config.RULE_CONFUSABLE,
        severity = Severity.MEDIUM,
        invariant = False,
        evidence = folded,
    )
    return folded, finding


def normalize_unicode(text: str) -> UnicodeResult:
    """
    Make text legible before anything judges it, recording every
    transform that was required to get there
    """
    findings: list[Finding] = []

    tags = decode_tag_block(text)
    if tags.finding is not None:
        findings.append(tags.finding)
    working = unicodedata.normalize("NFKC", tags.unmasked)

    working, zero_width = _strip(
        working,
        config.ZERO_WIDTH_CHARS,
        config.RULE_ZERO_WIDTH,
        Severity.MEDIUM,
    )
    if zero_width is not None:
        findings.append(zero_width)

    working, bidi = _strip(
        working,
        config.BIDI_CONTROLS,
        config.RULE_BIDI_CONTROL,
        Severity.HIGH,
    )
    if bidi is not None:
        findings.append(bidi)

    working, confusable = _fold_confusables(working)
    if confusable is not None:
        findings.append(confusable)

    return UnicodeResult(text = working, findings = tuple(findings))
