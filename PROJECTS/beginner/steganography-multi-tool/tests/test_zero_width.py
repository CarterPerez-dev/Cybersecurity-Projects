"""Round-trip tests for zero-width steganography."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from stego_multi.techniques import zero_width


pytestmark = pytest.mark.unit

# Carrier text that doesn't already contain our zero-width markers,
# matching the documented assumption of the technique.
carrier_text = st.text(
).filter(lambda s: zero_width.ZERO not in s and zero_width.ONE not in s)


@given(carrier = carrier_text, payload = st.binary())
def test_round_trip(carrier: str, payload: bytes) -> None:
    encoded = zero_width.embed(carrier, payload)
    assert zero_width.extract(encoded) == payload


@given(carrier = carrier_text, payload = st.binary())
def test_carrier_visually_unchanged(carrier: str, payload: bytes) -> None:
    encoded = zero_width.embed(carrier, payload)
    visible = encoded.replace(zero_width.ZERO, "").replace(zero_width.ONE, "")
    assert visible == carrier


def test_empty_payload_round_trips() -> None:
    encoded = zero_width.embed("hello", b"")
    assert zero_width.extract(encoded) == b""


def test_extract_without_payload_raises() -> None:
    with pytest.raises(ValueError, match = "no zero-width payload"):
        zero_width.extract("just plain text")
