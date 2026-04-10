"""
©AngelaMos | 2026
redaction.py
"""


from dlp_scanner.constants import RedactionStyle


REDACTED_LABEL: str = "[REDACTED]"
MASK_CHAR: str = "*"
SNIPPET_CONTEXT_CHARS: int = 20


def redact(
    text: str,
    start: int,
    end: int,
    style: RedactionStyle = "partial",
) -> str:
    """
    Redact matched text according to the chosen strategy
    """
    matched = text[start : end]

    if style == "none":
        return _build_snippet(text, start, end, matched)

    if style == "full":
        return _build_snippet(text, start, end, REDACTED_LABEL)

    redacted = _partial_redact(matched)
    return _build_snippet(text, start, end, redacted)


def _partial_redact(value: str) -> str:
    """
    Partially mask a value, keeping the last few chars visible
    """
    stripped = value.replace("-", "").replace(" ", "")

    if len(stripped) >= 9 and stripped.isdigit():
        return MASK_CHAR * (len(value) - 4) + value[-4 :]

    if "@" in value:
        local, domain = value.rsplit("@", maxsplit = 1)
        masked_local = local[0] + MASK_CHAR * (len(local) - 1)
        return f"{masked_local}@{domain}"

    if len(value) > 8:
        visible = max(4, len(value) // 4)
        return (MASK_CHAR * (len(value) - visible) + value[-visible :])

    return MASK_CHAR * len(value)


def _build_snippet(
    text: str,
    start: int,
    end: int,
    replacement: str,
) -> str:
    """
    Build a snippet with context around the redacted match
    """
    context_start = max(0, start - SNIPPET_CONTEXT_CHARS)
    context_end = min(len(text), end + SNIPPET_CONTEXT_CHARS)

    prefix = text[context_start : start]
    suffix = text[end : context_end]

    prefix = prefix.replace("\n", " ").strip()
    suffix = suffix.replace("\n", " ").strip()

    parts: list[str] = []
    if context_start > 0:
        parts.append("...")
    parts.append(prefix)
    parts.append(replacement)
    parts.append(suffix)
    if context_end < len(text):
        parts.append("...")

    return "".join(parts)
