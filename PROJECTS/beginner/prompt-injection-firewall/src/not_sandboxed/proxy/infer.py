"""
©AngelaMos | 2026
infer.py
"""

from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict, JsonValue

from not_sandboxed import config
from not_sandboxed.context import Context, Origin


class ChatMessage(BaseModel):
    """
    One OpenAI chat message, accepting every shape a real client sends

    A real client sends content as null on an assistant turn carrying
    tool calls, and as a list of parts when the turn is multimodal;
    rejecting either breaks the drop-in claim
    """

    model_config = ConfigDict(extra = "allow")

    role: str = ""
    content: str | list[dict[str, JsonValue]] | None = None
    name: str | None = None
    tool_call_id: str | None = None


def flatten(content: str | list[dict[str, JsonValue]] | None) -> str:
    """
    Reduce a content field to the text the firewall inspects, keeping
    only the parts a model reads as language
    """
    if content is None:
        return ""
    if isinstance(content, str):
        return content

    parts = [
        part.get("text")
        for part in content
        if part.get("type") == config.PROXY_TEXT_PART_TYPE
    ]
    return "\n".join(part for part in parts if isinstance(part, str))


def _ref(message: ChatMessage) -> str:
    return (
        message.tool_call_id or message.name
        or config.PROXY_UNKNOWN_TOOL_REF
    )


def infer_context(messages: Sequence[ChatMessage]) -> Context:
    """
    Guess provenance from OpenAI message roles, which is weaker than
    declaring it and is documented as such everywhere it is used

    Any role outside the two known sets is treated as untrusted, so an
    unrecognised role fails closed rather than being promoted
    """
    ctx = Context()

    for message in messages:
        text = flatten(message.content)

        if message.role in config.PROXY_TRUSTED_ROLES:
            ctx = ctx.system(text)
        elif message.role in config.PROXY_SEMI_TRUSTED_ROLES:
            ctx = ctx.user(text)
        else:
            ctx = ctx.data(
                text,
                origin = Origin(
                    channel = config.PROXY_TOOL_CHANNEL,
                    ref = _ref(message),
                ),
            )

    return ctx
