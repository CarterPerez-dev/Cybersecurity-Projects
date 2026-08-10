"""
©AngelaMos | 2026
firewall.py
"""

from not_sandboxed import config
from not_sandboxed.context import Context, Span, Trust


def _fence(span: Span, nonce: str) -> str:
    origin = span.origin
    channel = origin.channel if origin is not None else "unknown"
    ref = origin.ref if origin is not None else "unknown"

    opened = config.FENCE_OPEN.format(
        nonce = nonce,
        channel = channel,
        ref = ref,
    )
    closed = config.FENCE_CLOSE.format(nonce = nonce)
    return f"{opened}\n{span.text}\n{closed}"


def render(ctx: Context) -> str:
    """
    Build the prompt, fencing every untrusted span with a delimiter its
    own content cannot forge
    """
    parts: list[str] = []

    for span in ctx.spans:
        if span.trust is Trust.DATA:
            parts.append(_fence(span, ctx.nonce))
        else:
            parts.append(span.text)

    return "\n".join(parts)
