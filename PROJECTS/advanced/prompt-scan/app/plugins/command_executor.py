"""
Prompt Scan — Command Executor Plugin
Author: mohelobeid (https://github.com/mohelobeid)

WARNING: This plugin is EXTREMELY DANGEROUS and intentionally vulnerable.
LLM07: Insecure Plugin Design | LLM08: Excessive Agency
"""

from __future__ import annotations

import os
import platform
import subprocess


def execute_command(command: str) -> dict:
    """Execute an arbitrary OS command. LLM07/LLM08: shell=True, no whitelist."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        return {"success": True, "command": command, "stdout": result.stdout,
                "stderr": result.stderr, "return_code": result.returncode, "cwd": os.getcwd()}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Command timeout", "command": command}
    except Exception as exc:  # pylint: disable=broad-exception-caught
        return {"success": False, "error": str(exc), "command": command}


def execute_python_code(code: str) -> dict:
    """Execute arbitrary Python via exec(). LLM07/LLM08: no sandboxing."""
    try:
        exec_globals: dict = {}
        exec(code, exec_globals)  # noqa: S102
        return {"success": True, "code": code, "globals": str(exec_globals)}
    except Exception as exc:  # pylint: disable=broad-exception-caught
        return {"success": False, "error": str(exc), "code": code}


def get_environment_variables() -> dict:
    """Return all environment variables — LLM06."""
    return {"success": True, "env_vars": dict(os.environ)}


def get_system_info() -> dict:
    """Return system platform details — LLM06."""
    return {
        "success": True, "system": platform.system(), "release": platform.release(),
        "python_version": platform.python_version(), "cwd": os.getcwd(),
        "user": os.getenv("USER") or os.getenv("USERNAME"),
    }
