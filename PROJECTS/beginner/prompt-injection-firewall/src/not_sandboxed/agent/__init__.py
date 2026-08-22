"""
©AngelaMos | 2026
__init__.py
"""

from typing import Protocol

from not_sandboxed.tools import AgentReply


class Agent(Protocol):
    """
    Anything that turns a rendered prompt into a reply, whether that is
    the deterministic mock, a local model, or a hosted one
    """
    def respond(self, prompt: str) -> AgentReply:
        """
        Produce a reply for this prompt
        """
        ...
