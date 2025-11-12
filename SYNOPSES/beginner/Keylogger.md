# Keylogger

## Overview
Create an educational keylogging tool using Python's `pynput` library to capture keyboard input and log it with timestamps. This project demonstrates event-driven programming and system-level input monitoring, but must always include clear ethical disclaimers since keyloggers are commonly used maliciously.

## Step-by-Step Instructions

1. **Install and understand pynput library** by running `pip install pynput` and exploring its `Listener` class, which monitors keyboard and mouse events system-wide. Read through the documentation to understand how event callbacks work and what information is available from keyboard events (key pressed, key released, special keys, regular characters).

2. **Create a basic listener that captures keyboard events** by implementing a callback function that triggers whenever a key is pressed. Start simple by just printing each keystroke to the console to verify the listener is working correctly, then expand to capture both regular keys and special keys (Shift, Alt, Ctrl, Enter, Backspace, etc.).

3. **Implement timestamp logging** so each keystroke is recorded with the date, time, and exact timestamp. Store this data in a structured format (dictionary or tuple) that includes the key pressed and when it was pressed, creating a timeline of keyboard activity that can reveal user patterns and behavior.

4. **Add a toggle mechanism** using a designated hotkey (like F12 or Ctrl+Shift+Q) that starts and stops the logging without closing the entire program. This allows users to pause logging when discussing sensitive information or switch between different users on the same machine.

5. **Create file persistence** by writing logged keystrokes to a local text file with organized formatting—include session start/stop times, user information if available, and consider using JSON format for more complex data structures. Implement file rotation to create new log files daily or when reaching a certain file size to prevent one massive log file.

6. **Add filtering capabilities** to optionally exclude certain keys (like passwords being entered) or specific applications. Implement configuration options that allow users to customize what gets logged—for instance, only logging keystrokes in certain programs or during certain hours.

7. **Create a data export feature** that can convert logged keystroke data into useful formats (CSV for spreadsheet analysis, JSON for programmatic access, plain text for readability). Add basic analytics like keystroke frequency, most-used keys, and active typing periods to provide insights from the collected data.

8. **Include prominent ethical warnings and legal disclaimers** in the code comments, README, and console output emphasizing that unauthorized keylogging is illegal in most jurisdictions. Make it absolutely clear this tool is for educational purposes only on systems you own or have explicit permission to monitor—non-compliance could result in serious legal consequences.

## Key Concepts to Learn
- Event-driven programming and callbacks
- System-level input monitoring
- File I/O and data persistence
- Timestamp and datetime handling
- Configuration management and filtering

## Deliverables
- Functional keylogger with configurable toggle mechanism
- Timestamped log files with structured data
- Export functionality to multiple formats
- Comprehensive documentation with ethical guidelines and legal warnings
