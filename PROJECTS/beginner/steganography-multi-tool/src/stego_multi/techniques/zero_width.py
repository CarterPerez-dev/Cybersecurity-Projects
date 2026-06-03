"""
Zero-width character steganography.

Hides arbitrary bytes inside a visible carrier text by encoding them as
sequences of invisible Unicode characters appended to the text.
"""

# Two zero-width characters carry the binary payload: one per bit.
# Both render with zero width and don't affect how the carrier looks.
ZERO = "\u200b"  # ZERO WIDTH SPACE       -> bit 0
ONE = "\u200c"  # ZERO WIDTH NON-JOINER  -> bit 1

# The payload length is stored as a fixed 32-bit prefix so the extractor
# knows exactly how many bytes to read back.
_LENGTH_BITS = 32
_MAX_PAYLOAD = (1 << _LENGTH_BITS) - 1


def _bytes_to_bits(data: bytes) -> str:
    """Convert bytes to a string of '0'/'1' characters, MSB first."""
    return "".join(format(byte, "08b") for byte in data)


def _bits_to_bytes(bits: str) -> bytes:
    """Convert a string of '0'/'1' characters back to bytes."""
    return bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))


def embed(carrier: str, payload: bytes) -> str:
    """Hide ``payload`` inside ``carrier``.

    Returns the carrier text with an invisible zero-width suffix that
    encodes a 32-bit length prefix followed by the payload bits.
    """
    if len(payload) > _MAX_PAYLOAD:
        raise ValueError(f"payload too large: {len(payload)} bytes (max {_MAX_PAYLOAD})")

    length_bits = format(len(payload), f"0{_LENGTH_BITS}b")
    all_bits = length_bits + _bytes_to_bits(payload)
    hidden = "".join(ONE if bit == "1" else ZERO for bit in all_bits)
    return carrier + hidden


def extract(text: str) -> bytes:
    """Recover the payload hidden in ``text``.

    Raises ValueError if no zero-width data is present or it is malformed.
    """
    bits = "".join("1" if ch == ONE else "0" for ch in text if ch in (ZERO, ONE))
    if len(bits) < _LENGTH_BITS:
        raise ValueError("no zero-width payload found")

    length = int(bits[: _LENGTH_BITS], 2)
    payload_bits = bits[_LENGTH_BITS : _LENGTH_BITS + length * 8]
    if len(payload_bits) < length * 8:
        raise ValueError("truncated zero-width payload")

    return _bits_to_bytes(payload_bits)
