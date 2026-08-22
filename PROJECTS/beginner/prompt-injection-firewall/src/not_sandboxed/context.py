"""
©AngelaMos | 2026
context.py
"""

import secrets
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from not_sandboxed import config


class Trust(StrEnum):
    """
    Where a span came from, which is the only thing that decides
    whether its words are instructions or inert content
    """

    SYSTEM = "system"
    USER = "user"
    DATA = "data"


class Origin(BaseModel):
    """
    The untrusted channel a DATA span arrived on
    """

    model_config = ConfigDict(frozen = True)

    channel: str
    ref: str


class Span(BaseModel):
    """
    One contiguous piece of a prompt, tagged with its trust level
    """

    model_config = ConfigDict(frozen = True)

    trust: Trust
    text: str
    origin: Origin | None = None

    @model_validator(mode = "after")
    def _origin_matches_trust(self) -> Self:
        if self.trust is Trust.DATA and self.origin is None:
            raise ValueError("a DATA span must declare its origin")
        if self.trust is not Trust.DATA and self.origin is not None:
            raise ValueError(f"a {self.trust} span cannot have an origin")
        return self


def _new_nonce() -> str:
    return secrets.token_hex(config.NONCE_BYTES)


class Context(BaseModel):
    """
    An immutable prompt under construction, where taint is a
    consequence of what was added rather than something a caller
    remembers to set
    """

    model_config = ConfigDict(frozen = True)

    spans: tuple[Span, ...] = ()
    nonce: str = Field(default_factory = _new_nonce)

    @property
    def tainted_by(self) -> tuple[Origin, ...]:
        """
        Every untrusted origin that has entered this context, in order
        """
        return tuple(
            span.origin
            for span in self.spans
            if span.trust is Trust.DATA and span.origin is not None
        )

    def _extend(self, span: Span) -> Self:
        return type(self)(spans = (*self.spans, span), nonce = self.nonce)

    def system(self, text: str) -> Self:
        """
        Append operator-authored text
        """
        return self._extend(Span(trust = Trust.SYSTEM, text = text))

    def user(self, text: str) -> Self:
        """
        Append text authored by the human at the keyboard
        """
        return self._extend(Span(trust = Trust.USER, text = text))

    def data(self, text: str, origin: Origin) -> Self:
        """
        Append untrusted content and taint the context by doing so
        """
        return self._extend(
            Span(trust = Trust.DATA,
                 text = text,
                 origin = origin)
        )
