"""
Prompt Scan — File Reader Plugin
Author: mohelobeid (https://github.com/mohelobeid)

WARNING: Intentionally vulnerable — LLM07/LLM08.
Reads any file path without validation, enabling directory traversal.
"""

from __future__ import annotations

import os


def read_file(path: str) -> dict:
    """Read any file without path validation. LLM07/LLM08."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        return {"success": True, "path": path, "content": content, "size": len(content)}
    except FileNotFoundError:
        return {"success": False, "error": f"File not found: {path}", "path": path}
    except PermissionError:
        return {"success": False, "error": f"Permission denied: {path}", "path": path}
    except Exception as exc:  # pylint: disable=broad-exception-caught
        return {"success": False, "error": str(exc), "path": path}


def list_directory(path: str) -> dict:
    """List directory contents without validation — LLM07/LLM08."""
    try:
        return {"success": True, "path": path, "entries": os.listdir(path)}
    except Exception as exc:  # pylint: disable=broad-exception-caught
        return {"success": False, "error": str(exc), "path": path}
