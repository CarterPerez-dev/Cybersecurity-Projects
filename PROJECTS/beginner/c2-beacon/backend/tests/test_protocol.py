"""
AngelaMos | 2026
test_protocol.py

Unit tests for protocol message pack/unpack roundtrips and validation

Verifies that all five MessageType values survive pack -> unpack, and
that unpack raises ValueError for invalid base64, malformed JSON,
missing fields, and unknown message types.

Tests:
  core/protocol.py - pack, unpack, Message, MessageType
"""

import pytest

from core.models import CommandType
from core.protocol import Message, MessageType, pack, unpack


TEST_KEY = "test-protocol-key"


class TestPackUnpack:
    """
    Verify protocol message serialization roundtrips
    """
    def test_register_roundtrip(self) -> None:
        """
        REGISTER message survives pack -> unpack
        """
        original = Message(
            type = MessageType.REGISTER,
            payload = {
                "hostname": "desktop-01",
                "os": "Linux",
                "username": "root",
                "pid": 1234,
                "internal_ip": "10.0.0.5",
                "arch": "x86_64",
            },
        )
        packed = pack(original, TEST_KEY)
        restored = unpack(packed, TEST_KEY)
        assert restored.type == MessageType.REGISTER
        assert restored.payload["hostname"] == "desktop-01"
        assert restored.payload["pid"] == 1234

    def test_task_roundtrip(self) -> None:
        """
        TASK message survives pack -> unpack
        """
        original = Message(
            type = MessageType.TASK,
            payload = {
                "id": "task-001",
                "command": CommandType.SHELL,
                "args": "whoami",
            },
        )
        restored = unpack(pack(original, TEST_KEY), TEST_KEY)
        assert restored.type == MessageType.TASK
        assert restored.payload["command"] == "shell"

    def test_result_roundtrip(self) -> None:
        """
        RESULT message survives pack -> unpack
        """
        original = Message(
            type = MessageType.RESULT,
            payload = {
                "task_id": "task-001",
                "output": "root\n",
                "error": None,
            },
        )
        restored = unpack(pack(original, TEST_KEY), TEST_KEY)
        assert restored.type == MessageType.RESULT
        assert restored.payload["output"] == "root\n"

    def test_heartbeat_roundtrip(self) -> None:
        """
        HEARTBEAT message survives pack -> unpack
        """
        original = Message(
            type = MessageType.HEARTBEAT,
            payload = {"id": "beacon-abc"},
        )
        restored = unpack(pack(original, TEST_KEY), TEST_KEY)
        assert restored.type == MessageType.HEARTBEAT

    def test_error_roundtrip(self) -> None:
        """
        ERROR message survives pack -> unpack
        """
        original = Message(
            type = MessageType.ERROR,
            payload = {"detail": "command not found"},
        )
        restored = unpack(pack(original, TEST_KEY), TEST_KEY)
        assert restored.type == MessageType.ERROR
        assert restored.payload["detail"] == "command not found"


class TestUnpackValidation:
    """
    Verify unpack rejects malformed data
    """
    def test_invalid_base64(self) -> None:
        """
        Non-base64 input raises ValueError
        """
        with pytest.raises(ValueError, match = "Invalid protocol message"):
            unpack("not-valid-base64!!!", TEST_KEY)

    def test_invalid_json_after_decode(self) -> None:
        """
        Valid base64 but invalid JSON after XOR raises ValueError
        """
        from core.encoding import encode

        encoded = encode("this is not json", TEST_KEY)
        with pytest.raises(ValueError, match = "Invalid protocol message"):
            unpack(encoded, TEST_KEY)

    def test_missing_type_field(self) -> None:
        """
        JSON without 'type' field raises ValueError
        """
        from core.encoding import encode

        encoded = encode('{"payload": {}}', TEST_KEY)
        with pytest.raises(ValueError, match = "Invalid protocol message"):
            unpack(encoded, TEST_KEY)

    def test_invalid_message_type(self) -> None:
        """
        Unknown message type raises ValueError
        """
        from core.encoding import encode

        encoded = encode('{"type": "BOGUS", "payload": {}}', TEST_KEY)
        with pytest.raises(ValueError, match = "Invalid protocol message"):
            unpack(encoded, TEST_KEY)
