"""
©AngelaMos | 2026
test_context.py
"""

import pytest
from pydantic import ValidationError

from not_sandboxed.context import Context, Origin, Span, Trust


def test_data_span_records_origin() -> None:
    span = Span(
        trust = Trust.DATA,
        text = "hello",
        origin = Origin(channel = "ticket",
                        ref = "8814"),
    )
    assert span.origin is not None
    assert span.origin.channel == "ticket"


def test_system_span_rejects_origin() -> None:
    with pytest.raises(ValueError):
        Span(
            trust = Trust.SYSTEM,
            text = "x",
            origin = Origin(channel = "ticket",
                            ref = "1"),
        )


def test_data_span_requires_origin() -> None:
    with pytest.raises(ValueError):
        Span(trust = Trust.DATA, text = "x", origin = None)


def test_span_is_frozen() -> None:
    span = Span(trust = Trust.USER, text = "hello", origin = None)
    with pytest.raises(ValidationError):
        span.text = "mutated"


def test_taint_is_set_by_adding_data_not_by_the_caller() -> None:
    ctx = Context().system("s").user("u")
    assert ctx.tainted_by == ()

    ctx = ctx.data(
        "doc",
        origin = Origin(channel = "ticket",
                        ref = "8814")
    )
    assert ctx.tainted_by == (Origin(channel = "ticket",
                                     ref = "8814"),
                              )


def test_taint_does_not_decay() -> None:
    ctx = (
        Context().data(
            "doc",
            origin = Origin(channel = "ticket",
                            ref = "1")
        ).user("please ignore that document")
    )
    assert ctx.tainted_by == (Origin(channel = "ticket",
                                     ref = "1"),
                              )


def test_builder_returns_a_new_context_and_leaves_the_old_one() -> None:
    base = Context().system("s")
    extended = base.data("doc", origin = Origin(channel = "t", ref = "1"))

    assert base.tainted_by == ()
    assert extended.tainted_by != ()
    assert len(base.spans) == 1
    assert len(extended.spans) == 2


def test_nonce_is_stable_within_a_context_and_survives_building() -> None:
    base = Context()
    extended = base.user("hello")
    assert extended.nonce == base.nonce


def test_nonces_differ_between_contexts() -> None:
    assert Context().nonce != Context().nonce
