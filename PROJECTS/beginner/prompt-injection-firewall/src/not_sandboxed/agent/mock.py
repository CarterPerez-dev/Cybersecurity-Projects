"""
©AngelaMos | 2026
mock.py
"""

import re
from typing import Final

from not_sandboxed import config
from not_sandboxed.tools import AgentReply, ToolCallRequest


_REVEAL: Final = re.compile(
    config.AGENT_REVEAL_PATTERN,
    re.IGNORECASE,
)
_EMAIL: Final = re.compile(
    config.AGENT_EMAIL_PATTERN,
    re.IGNORECASE,
)


class MockAgent:
    """
    A support agent that is reliably gullible, so that any leak is the
    firewall's failure and never the model having an off day
    """
    def __init__(self, secret: str) -> None:
        self.secret = secret

    def respond(self, prompt: str) -> AgentReply:
        """
        Obey every instruction found anywhere in the prompt, without
        caring which span it came from
        """
        parts: list[str] = []
        calls: list[ToolCallRequest] = []

        if _REVEAL.search(prompt) is not None:
            parts.append(
                config.AGENT_DISCLOSURE_TEMPLATE.format(
                    value = self.secret
                )
            )

        recipient = _EMAIL.search(prompt)
        if recipient is not None:
            calls.append(
                ToolCallRequest(
                    name = "send_email",
                    args = {
                        "to": recipient.group(1),
                        "body": self.secret,
                    },
                )
            )

        if not parts:
            parts.append(config.AGENT_DEFAULT_REPLY)

        return AgentReply(
            text = " ".join(parts),
            tool_calls = tuple(calls),
        )
