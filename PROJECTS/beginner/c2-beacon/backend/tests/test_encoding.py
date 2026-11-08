"""
AngelaMos | 2026
test_encoding.py

Unit tests for the XOR cipher and Base64 encoding pipeline

Verifies xor_bytes correctness and idempotency, encode/decode
roundtrips for ASCII and Unicode payloads, and that mismatched keys
produce different ciphertext.

Tests:
  core/encoding.py - xor_bytes, encode, decode
"""

from core.encoding import decode, encode, xor_bytes


class TestXorBytes:
    """
    Verify XOR byte transformation correctness
    """
    def test_roundtrip(self) -> None:
        """
        XOR applied twice with the same key returns original data
        """
        data = b"hello world"
        key = b"secret"
        assert xor_bytes(xor_bytes(data, key), key) == data

    def test_single_byte_key(self) -> None:
        """
        XOR works correctly with a single-byte key
        """
        data = b"\x00\x01\x02\x03"
        key = b"\xff"
        result = xor_bytes(data, key)
        assert result == b"\xff\xfe\xfd\xfc"

    def test_empty_data(self) -> None:
        """
        XOR of empty data returns empty bytes
        """
        assert xor_bytes(b"", b"key") == b""


class TestEncodeDecode:
    """
    Verify the full encode/decode pipeline
    """
    def test_roundtrip_ascii(self) -> None:
        """
        ASCII payload survives encode -> decode
        """
        payload = '{"type": "REGISTER", "payload": {"hostname": "test"}}'
        key = "my-secret-key"
        assert decode(encode(payload, key), key) == payload

    def test_roundtrip_unicode(self) -> None:
        """
        Unicode payload survives encode -> decode
        """
        payload = '{"name": "test-\u00e9\u00e8\u00ea"}'
        key = "unicode-key"
        assert decode(encode(payload, key), key) == payload

    def test_different_keys_produce_different_output(self) -> None:
        """
        Same payload with different keys produces different ciphertext
        """
        payload = "identical payload"
        encoded_a = encode(payload, "key-alpha")
        encoded_b = encode(payload, "key-bravo")
        assert encoded_a != encoded_b

    def test_wrong_key_produces_garbage(self) -> None:
        """
        Decoding with the wrong key does not return the original payload
        """
        payload = '{"command": "shell"}'
        encoded = encode(payload, "correct-key")
        decoded = decode(encoded, "wrong-key-here")
        assert decoded != payload

    def test_empty_payload(self) -> None:
        """
        Empty string survives encode -> decode
        """
        assert decode(encode("", "key"), "key") == ""
