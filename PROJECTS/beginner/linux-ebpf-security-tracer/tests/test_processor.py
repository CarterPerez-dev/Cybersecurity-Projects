"""
©AngelaMos | 2026
test_processor.py
"""
from __future__ import annotations

from src.processor import (
    _decode_comm,
    _decode_filename,
    _ipv4_to_str,
    should_include,
)


class TestDecodeComm:
    """
    Tests for comm field decoding
    """

    def test_normal_string(self):
        """
        Decodes a normal null-terminated comm
        """
        raw = b"bash\x00\x00\x00\x00"
        assert _decode_comm(raw) == "bash"

    def test_full_length(self):
        """
        Handles comm at max length without null
        """
        raw = b"long_process_nm"
        assert _decode_comm(raw) == "long_process_nm"

    def test_empty(self):
        """
        Handles empty comm
        """
        raw = b"\x00" * 16
        assert _decode_comm(raw) == ""


class TestDecodeFilename:
    """
    Tests for filename field decoding
    """

    def test_normal_path(self):
        """
        Decodes a normal filepath
        """
        raw = b"/usr/bin/ls\x00"
        assert _decode_filename(raw) == "/usr/bin/ls"

    def test_empty(self):
        """
        Handles empty filename
        """
        raw = b"\x00" * 256
        assert _decode_filename(raw) == ""


class TestIpv4ToStr:
    """
    Tests for IPv4 address conversion
    """

    def test_localhost(self):
        """
        Converts 127.0.0.1 in network byte order
        """
        assert _ipv4_to_str(0x0100007F) == "127.0.0.1"

    def test_ten_network(self):
        """
        Converts 10.0.0.1 in network byte order
        """
        assert _ipv4_to_str(0x0100000A) == "10.0.0.1"

    def test_zero(self):
        """
        Returns empty string for zero address
        """
        assert _ipv4_to_str(0) == ""


class TestShouldInclude:
    """
    Tests for event filtering logic
    """

    def test_passes_all_defaults(self, make_event):
        """
        Event passes with default filters
        """
        event = make_event()
        assert should_include(event, "LOW", None, None, "all", False)

    def test_severity_filter(self, make_event):
        """
        Filters events below minimum severity
        """
        event = make_event(severity="LOW")
        assert not should_include(event, "MEDIUM", None, None, "all",
                                  False)

    def test_severity_passes(self, make_event):
        """
        Passes events at or above minimum severity
        """
        event = make_event(severity="HIGH")
        assert should_include(event, "MEDIUM", None, None, "all", False)

    def test_pid_filter_match(self, make_event):
        """
        Passes when PID matches filter
        """
        event = make_event(pid=1234)
        assert should_include(event, "LOW", 1234, None, "all", False)

    def test_pid_filter_mismatch(self, make_event):
        """
        Filters when PID does not match
        """
        event = make_event(pid=1234)
        assert not should_include(event, "LOW", 5678, None, "all", False)

    def test_comm_filter_match(self, make_event):
        """
        Passes when comm matches filter
        """
        event = make_event(comm="bash")
        assert should_include(event, "LOW", None, "bash", "all", False)

    def test_comm_filter_mismatch(self, make_event):
        """
        Filters when comm does not match
        """
        event = make_event(comm="bash")
        assert not should_include(event, "LOW", None, "python", "all",
                                  False)

    def test_type_filter(self, make_event):
        """
        Filters events outside requested category
        """
        event = make_event(category="process")
        assert not should_include(event, "LOW", None, None, "network",
                                  False)

    def test_detections_only_with_detection(self, make_event):
        """
        Passes events with detections in detections mode
        """
        event = make_event()
        event.detection = "Test Detection"
        assert should_include(event, "LOW", None, None, "all", True)

    def test_detections_only_without_detection(self, make_event):
        """
        Filters events without detections in detections mode
        """
        event = make_event()
        assert not should_include(event, "LOW", None, None, "all", True)
