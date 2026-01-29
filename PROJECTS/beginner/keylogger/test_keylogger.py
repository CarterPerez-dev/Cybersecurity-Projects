"""
CarterPerez-dev | 2025
Test suite for keylogger
"""

import sys
import tempfile
import traceback
from pathlib import Path
from datetime import datetime
from pynput.keyboard import Key

from keylogger import (
    Keylogger,
    KeyloggerConfig,
    KeyEvent,
    KeyType,
    LogManager,
    WindowTracker,
    WebhookDelivery,
)


def test_key_type_enum():
    """
    Test KeyType enum exists and has correct values
    """
    print("Testing KeyType enum...")
    assert KeyType.CHAR
    assert KeyType.SPECIAL
    assert KeyType.UNKNOWN
    print("KeyType enum works")


def test_keylogger_config():
    """
    Test KeyloggerConfig dataclass initialization
    """
    print("\nTesting KeyloggerConfig...")

    with tempfile.TemporaryDirectory() as tmpdir:
        config = KeyloggerConfig(
            log_dir = Path(tmpdir),
            max_log_size_mb = 1.0,
            webhook_url = "https://example.com/webhook",
            webhook_batch_size = 10,
            toggle_key = Key.f9,
            enable_window_tracking = True,
            log_special_keys = True
        )

        assert config.log_dir.exists()
        assert config.max_log_size_mb == 1.0
        assert config.webhook_url == "https://example.com/webhook"
        assert config.webhook_batch_size == 10
        assert config.toggle_key == Key.f9

    print("KeyloggerConfig works")


def test_key_event():
    """
    Test KeyEvent dataclass and serialization
    """
    print("\nTesting KeyEvent...")

    event = KeyEvent(
        timestamp = datetime.now(),
        key = "a",
        window_title = "TestApp",
        key_type = KeyType.CHAR
    )

    data = event.to_dict()
    assert data["key"] == "a"
    assert data["window_title"] == "TestApp"
    assert data["key_type"] == "char"
    assert "timestamp" in data

    log_str = event.to_log_string()
    assert "a" in log_str
    assert "TestApp" in log_str

    print("KeyEvent works")


def test_log_manager():
    """
    Test LogManager file writing and rotation
    """
    print("\nTesting LogManager...")

    with tempfile.TemporaryDirectory() as tmpdir:
        config = KeyloggerConfig(
            log_dir = Path(tmpdir),
            max_log_size_mb = 0.001
        )

        manager = LogManager(config)

        for i in range(10):
            event = KeyEvent(
                timestamp = datetime.now(),
                key = f"key_{i}",
                window_title = "TestApp",
                key_type = KeyType.CHAR
            )
            manager.write_event(event)

        log_files = list(Path(tmpdir).glob("keylog_*.txt"))
        assert len(log_files) > 0

        content = manager.get_current_log_content()
        assert "key_0" in content or "key_9" in content

    print("LogManager works")


def test_window_tracker():
    """
    Test WindowTracker (may return None if not on supported platform)
    """
    print("\nTesting WindowTracker...")

    window_title = WindowTracker.get_active_window()

    # window_title can be None or a string depending on platform
    assert window_title is None or isinstance(window_title, str)

    print(
        f"WindowTracker works (got: {window_title or 'None (platform not supported)'})"
    )


def test_webhook_delivery():
    """
    Test WebhookDelivery buffering logic
    """
    print("\nTesting WebhookDelivery...")

    config = KeyloggerConfig(
        webhook_url = None,
        webhook_batch_size = 5
    )

    webhook = WebhookDelivery(config)

    assert not webhook.enabled

    config_with_url = KeyloggerConfig(
        webhook_url = "https://example.com/webhook",
        webhook_batch_size = 3
    )

    webhook_enabled = WebhookDelivery(config_with_url)
    assert webhook_enabled.enabled

    for i in range(2):
        event = KeyEvent(
            timestamp = datetime.now(),
            key = f"k{i}",
            key_type = KeyType.CHAR
        )
        webhook_enabled.add_event(event)

    assert len(webhook_enabled.event_buffer) == 2

    print("WebhookDelivery works")


def test_key_processing():
    """
    Test key processing would work correctly
    """
    print("\nTesting key processing logic...")

    with tempfile.TemporaryDirectory() as tmpdir:
        config = KeyloggerConfig(log_dir = Path(tmpdir))
        keylogger = Keylogger(config)

        key_str, key_type = keylogger._process_key(Key.enter)
        assert key_str == "[ENTER]"
        assert key_type == KeyType.SPECIAL

        key_str, key_type = keylogger._process_key(Key.space)
        assert key_str == "[SPACE]"
        assert key_type == KeyType.SPECIAL

        print("Key processing works")


def run_all_tests():
    """
    Run all tests
    """
    print("KEYLOGGER COMPONENT TESTS")
    try:
        test_key_type_enum()
        test_keylogger_config()
        test_key_event()
        test_log_manager()
        test_window_tracker()
        test_webhook_delivery()
        test_key_processing()

        print("ALL TESTS PASSED!")
        return 0

    except Exception as e:
        print(f"\n✗ TEST FAILED: {e}")
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
