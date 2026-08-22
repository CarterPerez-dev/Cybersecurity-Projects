"""
©AngelaMos | 2026
__init__.py
"""

from typing import Protocol

from not_sandboxed.context import Context
from not_sandboxed.policy import Policy
from not_sandboxed.verdict import Finding


class Layer(Protocol):
    """
    One inspection stage, which reports what it found and never
    decides what to do about it
    """

    name: str

    def inspect(
        self,
        ctx: Context,
        policy: Policy,
    ) -> list[Finding]:
        """
        Report every rule that fired against this context
        """
        ...
