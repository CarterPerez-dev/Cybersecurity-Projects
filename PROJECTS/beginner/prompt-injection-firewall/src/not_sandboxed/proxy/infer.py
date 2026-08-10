"""
©AngelaMos | 2026
infer.py
"""

from collections.abc import Mapping, Sequence

from not_sandboxed import config
from not_sandboxed.context import Context, Origin


def infer_context(
    messages: Sequence[Mapping[str,
                               str]],
) -> Context:
    """
    Guess provenance from OpenAI message roles, which is weaker than
    declaring it and is documented as such everywhere it is used
    """
    ctx = Context()

    for message in messages:
        role = message.get("role", "")
        text = message.get("content", "")

        if role in config.PROXY_TRUSTED_ROLES:
            ctx = ctx.system(text)
        elif role in config.PROXY_SEMI_TRUSTED_ROLES:
            ctx = ctx.user(text)
        else:
            ctx = ctx.data(
                text,
                origin = Origin(
                    channel = config.PROXY_TOOL_CHANNEL,
                    ref = message.get(
                        "name",
                        config.PROXY_UNKNOWN_TOOL_REF,
                    ),
                ),
            )

    return ctx
