"""
©AngelaMos | 2026
test_renderer.py
"""
from __future__ import annotations

import io
import json

from src.renderer import JsonRenderer, _event_to_dict


class TestEventToDict:
    """
    Tests for event serialization
    """

    def test_basic_fields(self, make_event):
        """
        Serializes core event fields
        """
        event = make_event(
            event_type="execve",
            pid=1234,
            comm="bash",
        )
        d = _event_to_dict(event)
        assert d["event_type"] == "execve"
        assert d["pid"] == 1234
        assert d["comm"] == "bash"
        assert "timestamp" in d

    def test_filename_included(self, make_event):
        """
        Includes filename when present
        """
        event = make_event(filename="/usr/bin/ls")
        d = _event_to_dict(event)
        assert d["filename"] == "/usr/bin/ls"

    def test_filename_excluded_when_empty(self, make_event):
        """
        Omits filename when empty
        """
        event = make_event(filename="")
        d = _event_to_dict(event)
        assert "filename" not in d

    def test_network_fields(self, make_event):
        """
        Includes network fields for connect events
        """
        event = make_event(
            event_type="connect",
            addr_v4="10.0.0.1",
            port=4444,
        )
        d = _event_to_dict(event)
        assert d["dest_ip"] == "10.0.0.1"
        assert d["dest_port"] == 4444

    def test_detection_fields(self, make_event):
        """
        Includes detection metadata when present
        """
        event = make_event()
        event.detection = "Test Rule"
        event.detection_id = "D999"
        event.mitre_id = "T1234"
        d = _event_to_dict(event)
        assert d["detection"] == "Test Rule"
        assert d["detection_id"] == "D999"
        assert d["mitre_id"] == "T1234"

    def test_no_detection_fields_when_none(self, make_event):
        """
        Omits detection fields when no detection
        """
        event = make_event()
        d = _event_to_dict(event)
        assert "detection" not in d

    def test_setuid_zero_serialized(self, make_event):
        """
        Includes target_uid even when value is zero
        """
        event = make_event(
            event_type="setuid",
            target_uid=0,
        )
        d = _event_to_dict(event)
        assert "target_uid" in d
        assert d["target_uid"] == 0

    def test_ptrace_fields_serialized(self, make_event):
        """
        Includes ptrace fields for ptrace events
        """
        event = make_event(
            event_type="ptrace",
            ptrace_request=16,
            target_pid=1234,
        )
        d = _event_to_dict(event)
        assert d["ptrace_request"] == 16
        assert d["target_pid"] == 1234


class TestJsonRenderer:
    """
    Tests for JSON output rendering
    """

    def test_outputs_valid_json(self, make_event):
        """
        Produces valid JSON output
        """
        buf = io.StringIO()
        renderer = JsonRenderer(stream=buf)
        event = make_event(event_type="execve", pid=42, comm="ls")
        renderer.render(event)

        output = buf.getvalue().strip()
        parsed = json.loads(output)
        assert parsed["pid"] == 42
        assert parsed["comm"] == "ls"

    def test_one_line_per_event(self, make_event):
        """
        Each event is a single line
        """
        buf = io.StringIO()
        renderer = JsonRenderer(stream=buf)
        renderer.render(make_event(pid=1))
        renderer.render(make_event(pid=2))

        lines = buf.getvalue().strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0])["pid"] == 1
        assert json.loads(lines[1])["pid"] == 2
