"""
©AngelaMos | 2026
test_keylogger.py

Test suite for all keylogger components

Pytest-based with fixtures, parametrize, and mocking. Covers config validation,
event serialization, file writing with rotation, window title detection, webhook
buffering and delivery, key processing, and toggle behavior. Webhook HTTP calls
are intercepted via unittest.mock.patch so no real network traffic is generated.

Tests:
  TestKeyType          - Enum members exist and values are unique
  TestKeyloggerConfig  - Defaults, custom values, no side effects on construction
  TestKeyEvent         - to_dict and to_log_string output for all field combinations
  TestLogManager       - Write, rotation, deleted file recovery, instance isolation
  TestWindowTracker    - Returns None or str on any platform
  TestWebhookDelivery  - Enable/disable, buffer accumulation, batch firing, flush
  TestKeyProcessing    - SPECIAL_KEYS coverage, char keys, unmapped and unknown keys
  TestKeyloggerToggle  - Toggle pauses and resumes the logging Event

Connects to:
  keylogger.py - all tested classes and SPECIAL_KEYS imported from here
"""

import tempfile
from pathlib import Path
from datetime import datetime
from unittest.mock import (
    patch,
    MagicMock,
)

import pytest
from pynput.keyboard import Key, KeyCode

from keylogger import (
    Keylogger,
    KeyloggerConfig,
    KeyEvent,
    KeyType,
    LogManager,
    WindowTracker,
    WebhookDelivery,
    SPECIAL_KEYS,
)


@pytest.fixture()
def tmp_dir():
    """
    Provide a temporary directory for log output
    """
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture()
def config(tmp_dir):
    """
    Provide a KeyloggerConfig using a temp directory
    """
    return KeyloggerConfig(log_dir = tmp_dir)


@pytest.fixture()
def small_rotation_config(tmp_dir):
    """
    Config with tiny max size to trigger rotation
    """
    return KeyloggerConfig(
        log_dir = tmp_dir,
        max_log_size_mb = 0.001,
    )


class TestKeyType:
    def test_enum_members_exist(self):
        """
        All three key type variants are accessible
        """
        assert KeyType.CHAR
        assert KeyType.SPECIAL
        assert KeyType.UNKNOWN

    def test_enum_values_are_unique(self):
        """
        Each variant has a distinct value
        """
        values = [
            KeyType.CHAR.value,
            KeyType.SPECIAL.value,
            KeyType.UNKNOWN.value,
        ]
        assert len(values) == len(set(values))


class TestKeyloggerConfig:
    def test_defaults(self, tmp_dir):
        """
        Config initializes with expected defaults
        """
        cfg = KeyloggerConfig(log_dir = tmp_dir)
        assert cfg.max_log_size_mb == 5.0
        assert cfg.webhook_url is None
        assert cfg.webhook_batch_size == 50
        assert cfg.toggle_key == Key.f9
        assert cfg.enable_window_tracking is True
        assert cfg.log_special_keys is True

    def test_custom_values(self, tmp_dir):
        """
        Custom values override defaults
        """
        cfg = KeyloggerConfig(
            log_dir = tmp_dir,
            max_log_size_mb = 10.0,
            webhook_url = "https://example.com",
            webhook_batch_size = 100,
            toggle_key = Key.f8,
            enable_window_tracking = False,
            log_special_keys = False,
        )
        assert cfg.max_log_size_mb == 10.0
        assert cfg.webhook_url == ("https://example.com")
        assert cfg.webhook_batch_size == 100
        assert cfg.toggle_key == Key.f8
        assert (cfg.enable_window_tracking is False)
        assert cfg.log_special_keys is False

    def test_no_side_effects_on_construction(self):
        """
        Config construction does not create dirs
        """
        fake = Path("/tmp/_keylogger_test_nonexistent")
        cfg = KeyloggerConfig(log_dir = fake)
        assert not fake.exists()
        assert cfg.log_dir == fake


class TestKeyEvent:
    def test_to_dict_fields(self):
        """
        to_dict includes all required fields
        """
        event = KeyEvent(
            timestamp = datetime(2026,
                                 1,
                                 1),
            key = "a",
            window_title = "Terminal",
            key_type = KeyType.CHAR,
        )
        data = event.to_dict()
        assert data["key"] == "a"
        assert data["window_title"] == "Terminal"
        assert data["key_type"] == "char"
        assert "timestamp" in data

    def test_to_dict_null_window(self):
        """
        Null window title serializes as Unknown
        """
        event = KeyEvent(
            timestamp = datetime(2026,
                                 1,
                                 1),
            key = "b",
        )
        assert (event.to_dict()["window_title"] == "Unknown")

    def test_to_log_string_with_window(self):
        """
        Log string includes window title in brackets
        """
        event = KeyEvent(
            timestamp = datetime(2026,
                                 1,
                                 1),
            key = "x",
            window_title = "Firefox",
        )
        log = event.to_log_string()
        assert "[Firefox]" in log
        assert "x" in log
        assert "2026-01-01" in log

    def test_to_log_string_without_window(self):
        """
        Log string omits brackets when no window
        """
        event = KeyEvent(
            timestamp = datetime(2026,
                                 1,
                                 1),
            key = "y",
        )
        log = event.to_log_string()
        assert "[2026-01-01" in log
        assert "y" in log
        assert "[]" not in log

    def test_special_key_type_serializes(self):
        """
        Special key type serializes as lowercase
        """
        event = KeyEvent(
            timestamp = datetime(2026,
                                 1,
                                 1),
            key = "[ENTER]",
            key_type = KeyType.SPECIAL,
        )
        assert (event.to_dict()["key_type"] == "special")


class TestLogManager:
    def test_writes_event_to_file(self, config):
        """
        Events are persisted to the log file
        """
        manager = LogManager(config)
        event = KeyEvent(
            timestamp = datetime(2026,
                                 1,
                                 1),
            key = "hello",
            key_type = KeyType.CHAR,
        )
        manager.write_event(event)
        content = manager.get_current_log_content()
        assert "hello" in content
        manager.close()

    def test_creates_log_directory(self, tmp_dir):
        """
        LogManager creates the log directory on init
        """
        nested = tmp_dir / "sub" / "dir"
        cfg = KeyloggerConfig(log_dir = nested)
        manager = LogManager(cfg)
        assert nested.exists()
        manager.close()

    def test_rotation_creates_new_file(
        self,
        small_rotation_config,
    ):
        """
        Writing past max size triggers rotation
        """
        manager = LogManager(small_rotation_config)
        first_path = manager.current_log_path

        for i in range(50):
            event = KeyEvent(
                timestamp = datetime.now(),
                key = f"padding_key_{i:04d}",
                key_type = KeyType.CHAR,
            )
            manager.write_event(event)

        log_files = list(small_rotation_config.log_dir.glob("keylog_*.txt"))
        assert len(log_files) > 1
        assert (manager.current_log_path != first_path)
        manager.close()

    def test_survives_deleted_log_file(
        self,
        config,
    ):
        """
        Rotation recovers when log file is deleted
        """
        manager = LogManager(config)
        manager.current_log_path.unlink()

        event = KeyEvent(
            timestamp = datetime.now(),
            key = "after_delete",
            key_type = KeyType.CHAR,
        )
        manager.write_event(event)
        assert manager.current_log_path.exists()
        manager.close()

    def test_no_shared_state_between_instances(
        self,
        tmp_dir,
    ):
        """
        Two LogManagers write independently
        """
        dir_a = tmp_dir / "a"
        dir_b = tmp_dir / "b"
        cfg_a = KeyloggerConfig(log_dir = dir_a)
        cfg_b = KeyloggerConfig(log_dir = dir_b)

        mgr_a = LogManager(cfg_a)
        mgr_b = LogManager(cfg_b)

        event_a = KeyEvent(
            timestamp = datetime.now(),
            key = "only_in_a",
            key_type = KeyType.CHAR,
        )
        event_b = KeyEvent(
            timestamp = datetime.now(),
            key = "only_in_b",
            key_type = KeyType.CHAR,
        )

        mgr_a.write_event(event_a)
        mgr_b.write_event(event_b)

        content_a = mgr_a.get_current_log_content()
        content_b = mgr_b.get_current_log_content()

        assert "only_in_a" in content_a
        assert "only_in_b" not in content_a
        assert "only_in_b" in content_b
        assert "only_in_a" not in content_b

        mgr_a.close()
        mgr_b.close()


class TestWindowTracker:
    def test_returns_none_or_string(self):
        """
        get_active_window returns None or a string
        """
        result = WindowTracker.get_active_window()
        assert result is None or isinstance(
            result,
            str,
        )


class TestWebhookDelivery:
    def test_disabled_without_url(self, config):
        """
        Webhook is disabled when no URL configured
        """
        webhook = WebhookDelivery(config)
        assert not webhook.enabled

    def test_enabled_with_url(self, tmp_dir):
        """
        Webhook enables when URL and requests exist
        """
        cfg = KeyloggerConfig(
            log_dir = tmp_dir,
            webhook_url = "https://example.com",
        )
        webhook = WebhookDelivery(cfg)
        assert webhook.enabled

    def test_buffer_accumulates(self, tmp_dir):
        """
        Events buffer until batch size is reached
        """
        cfg = KeyloggerConfig(
            log_dir = tmp_dir,
            webhook_url = "https://example.com",
            webhook_batch_size = 10,
        )
        webhook = WebhookDelivery(cfg)

        for i in range(5):
            event = KeyEvent(
                timestamp = datetime.now(),
                key = f"k{i}",
                key_type = KeyType.CHAR,
            )
            webhook.add_event(event)

        assert len(webhook.event_buffer) == 5

    @patch("keylogger.requests")
    def test_batch_fires_at_threshold(
        self,
        mock_requests,
        tmp_dir,
    ):
        """
        Delivery triggers at batch size
        """
        mock_response = MagicMock()
        mock_response.ok = True
        mock_requests.post.return_value = (mock_response)

        cfg = KeyloggerConfig(
            log_dir = tmp_dir,
            webhook_url = "https://example.com",
            webhook_batch_size = 3,
        )
        webhook = WebhookDelivery(cfg)

        for i in range(3):
            event = KeyEvent(
                timestamp = datetime.now(),
                key = f"k{i}",
                key_type = KeyType.CHAR,
            )
            webhook.add_event(event)

        mock_requests.post.assert_called_once()
        assert len(webhook.event_buffer) == 0

    @patch("keylogger.requests")
    def test_flush_delivers_remaining(
        self,
        mock_requests,
        tmp_dir,
    ):
        """
        Flush sends events below batch threshold
        """
        mock_response = MagicMock()
        mock_response.ok = True
        mock_requests.post.return_value = (mock_response)

        cfg = KeyloggerConfig(
            log_dir = tmp_dir,
            webhook_url = "https://example.com",
            webhook_batch_size = 100,
        )
        webhook = WebhookDelivery(cfg)

        event = KeyEvent(
            timestamp = datetime.now(),
            key = "z",
            key_type = KeyType.CHAR,
        )
        webhook.add_event(event)
        assert len(webhook.event_buffer) == 1

        webhook.flush()
        mock_requests.post.assert_called_once()
        assert len(webhook.event_buffer) == 0

    def test_no_op_when_disabled(self, config):
        """
        add_event is a no-op when disabled
        """
        webhook = WebhookDelivery(config)
        event = KeyEvent(
            timestamp = datetime.now(),
            key = "x",
            key_type = KeyType.CHAR,
        )
        webhook.add_event(event)
        assert len(webhook.event_buffer) == 0


class TestKeyProcessing:
    @pytest.fixture()
    def keylogger(self, config):
        """
        Provide a Keylogger instance for testing
        """
        return Keylogger(config)

    @pytest.mark.parametrize(
        ("key",
         "expected_str"),
        [
            (Key.enter,
             "[ENTER]"),
            (Key.space,
             "[SPACE]"),
            (Key.tab,
             "[TAB]"),
            (Key.backspace,
             "[BACKSPACE]"),
            (Key.delete,
             "[DELETE]"),
            (Key.shift,
             "[SHIFT]"),
            (Key.shift_r,
             "[SHIFT]"),
            (Key.ctrl,
             "[CTRL]"),
            (Key.ctrl_r,
             "[CTRL]"),
            (Key.alt,
             "[ALT]"),
            (Key.alt_r,
             "[ALT]"),
            (Key.cmd,
             "[CMD]"),
            (Key.cmd_r,
             "[CMD]"),
            (Key.esc,
             "[ESC]"),
            (Key.up,
             "[UP]"),
            (Key.down,
             "[DOWN]"),
            (Key.left,
             "[LEFT]"),
            (Key.right,
             "[RIGHT]"),
        ],
    )
    def test_special_key_mapping(
        self,
        keylogger,
        key,
        expected_str,
    ):
        """
        Each mapped special key produces its label
        """
        result, key_type = (keylogger._process_key(key))
        assert result == expected_str
        assert key_type == KeyType.SPECIAL

    def test_unmapped_special_key(self, keylogger):
        """
        Unmapped special keys use uppercase name
        """
        result, key_type = (keylogger._process_key(Key.caps_lock))
        assert result == "[CAPS_LOCK]"
        assert key_type == KeyType.SPECIAL

    def test_char_key(self, keylogger):
        """
        Character keys return the character
        """
        key = KeyCode.from_char('a')
        result, key_type = (keylogger._process_key(key))
        assert result == "a"
        assert key_type == KeyType.CHAR

    def test_unknown_key(self, keylogger):
        """
        Keys without char attribute return UNKNOWN
        """
        key = KeyCode(vk = 999)
        result, key_type = (keylogger._process_key(key))
        assert result == "[UNKNOWN]"
        assert key_type == KeyType.UNKNOWN

    def test_special_keys_constant_coverage(self):
        """
        SPECIAL_KEYS covers all expected modifiers
        """
        expected = {
            Key.space,
            Key.enter,
            Key.tab,
            Key.backspace,
            Key.delete,
            Key.shift,
            Key.shift_r,
            Key.ctrl,
            Key.ctrl_r,
            Key.alt,
            Key.alt_r,
            Key.cmd,
            Key.cmd_r,
            Key.esc,
            Key.up,
            Key.down,
            Key.left,
            Key.right,
        }
        assert set(SPECIAL_KEYS.keys()) == expected


class TestKeyloggerToggle:
    @pytest.fixture()
    def keylogger(self, config):
        """
        Provide a Keylogger with logging active
        """
        kl = Keylogger(config)
        kl.is_logging.set()
        return kl

    def test_toggle_pauses(self, keylogger):
        """
        Toggle from active state pauses logging
        """
        keylogger._toggle_logging()
        assert not keylogger.is_logging.is_set()

    def test_toggle_resumes(self, keylogger):
        """
        Toggle from paused state resumes logging
        """
        keylogger._toggle_logging()
        keylogger._toggle_logging()
        assert keylogger.is_logging.is_set()
