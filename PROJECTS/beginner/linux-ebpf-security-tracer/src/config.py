"""
©AngelaMos | 2026
config.py
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Literal

PACKAGE_DIR = Path(__file__).parent
EBPF_DIR = PACKAGE_DIR / "ebpf"

TASK_COMM_LEN = 16
MAX_FILENAME_LEN = 256
RING_BUFFER_BYTES = 256 * 1024
CORRELATION_WINDOW_SEC = 10
MAX_EVENTS_PER_PID = 64
SWEEP_INTERVAL = 1000
MIN_KERNEL_MAJOR = 5
MIN_KERNEL_MINOR = 8

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
OutputFormat = Literal["json", "table", "live"]
TracerType = Literal["process", "file", "network", "privilege", "system",
                     "all"]

SEVERITY_ORDER: dict[str, int] = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}

SEVERITY_COLORS: dict[str, str] = {
    "LOW": "cyan",
    "MEDIUM": "yellow",
    "HIGH": "red",
    "CRITICAL": "bold red",
}


class EventType(IntEnum):
    """
    Numeric identifiers for traced syscall events
    """
    EXECVE = 1
    CLONE = 2
    OPENAT = 3
    UNLINKAT = 4
    RENAMEAT2 = 5
    CONNECT = 6
    ACCEPT4 = 7
    BIND = 8
    LISTEN = 9
    SETUID = 10
    SETGID = 11
    PTRACE = 12
    MOUNT = 13
    INIT_MODULE = 14


EVENT_TYPE_NAMES: dict[int, str] = {
    e.value: e.name.lower()
    for e in EventType
}

EVENT_TYPE_CATEGORIES: dict[int, str] = {
    EventType.EXECVE: "process",
    EventType.CLONE: "process",
    EventType.OPENAT: "file",
    EventType.UNLINKAT: "file",
    EventType.RENAMEAT2: "file",
    EventType.CONNECT: "network",
    EventType.ACCEPT4: "network",
    EventType.BIND: "network",
    EventType.LISTEN: "network",
    EventType.SETUID: "privilege",
    EventType.SETGID: "privilege",
    EventType.PTRACE: "system",
    EventType.MOUNT: "system",
    EventType.INIT_MODULE: "system",
}

SENSITIVE_READ_PATHS: tuple[str, ...] = (
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/master.passwd",
)

CREDENTIAL_PATHS: tuple[str, ...] = (
    "/.ssh/id_rsa",
    "/.ssh/id_ed25519",
    "/.ssh/id_ecdsa",
    "/.ssh/id_dsa",
    "/.ssh/authorized_keys",
    "/.aws/credentials",
    "/.gnupg/",
)

CREDENTIAL_ACCESS_ALLOWLIST: tuple[str, ...] = (
    "sshd",
    "ssh",
    "ssh-agent",
    "ssh-add",
    "gpg-agent",
    "gpg",
    "gpg2",
    "gpgsm",
)

PERSISTENCE_CRON_PATHS: tuple[str, ...] = (
    "/etc/cron",
    "/var/spool/cron",
    "/etc/crontab",
)

PERSISTENCE_SYSTEMD_PATHS: tuple[str, ...] = (
    "/etc/systemd/system/",
    "/lib/systemd/system/",
    "/usr/lib/systemd/system/",
)

LOG_PATHS: tuple[str, ...] = (
    "/var/log/",
    "/var/log/syslog",
    "/var/log/auth.log",
    "/var/log/kern.log",
)

SHELL_BINARIES: tuple[str, ...] = (
    "sh",
    "bash",
    "dash",
    "zsh",
    "csh",
    "tcsh",
    "fish",
    "ksh",
)

PTRACE_ATTACH = 16
PTRACE_SEIZE = 16902
PTRACE_SETREGS = 13


@dataclass(frozen=True)
class DetectionRule:
    """
    Metadata for a single detection rule
    """
    rule_id: str
    name: str
    severity: Severity
    mitre_id: str
    description: str


DETECTION_RULES: dict[str, DetectionRule] = {
    "D001":
    DetectionRule(
        rule_id="D001",
        name="Privilege Escalation",
        severity="CRITICAL",
        mitre_id="T1548",
        description="setuid(0) called by non-root process",
    ),
    "D002":
    DetectionRule(
        rule_id="D002",
        name="Sensitive File Read",
        severity="MEDIUM",
        mitre_id="T1003.008",
        description=("Non-standard process reading credential files"),
    ),
    "D003":
    DetectionRule(
        rule_id="D003",
        name="SSH Key Access",
        severity="MEDIUM",
        mitre_id="T1552.004",
        description="Process accessing SSH key material",
    ),
    "D004":
    DetectionRule(
        rule_id="D004",
        name="Process Injection",
        severity="MEDIUM",
        mitre_id="T1055.008",
        description="ptrace attach to another process",
    ),
    "D005":
    DetectionRule(
        rule_id="D005",
        name="Kernel Module Load",
        severity="HIGH",
        mitre_id="T1547.006",
        description="Kernel module loaded via init_module",
    ),
    "D006":
    DetectionRule(
        rule_id="D006",
        name="Reverse Shell",
        severity="CRITICAL",
        mitre_id="T1059.004",
        description=("Shell execution following network connection"),
    ),
    "D007":
    DetectionRule(
        rule_id="D007",
        name="Persistence via Cron",
        severity="MEDIUM",
        mitre_id="T1053.003",
        description="Write operation to cron directories",
    ),
    "D008":
    DetectionRule(
        rule_id="D008",
        name="Persistence via Systemd",
        severity="MEDIUM",
        mitre_id="T1543.002",
        description=("Write operation to systemd unit directories"),
    ),
    "D009":
    DetectionRule(
        rule_id="D009",
        name="Log Tampering",
        severity="MEDIUM",
        mitre_id="T1070.002",
        description="Deletion or truncation of log files",
    ),
    "D010":
    DetectionRule(
        rule_id="D010",
        name="Suspicious Mount",
        severity="HIGH",
        mitre_id="T1611",
        description=("Filesystem mount operation detected"),
    ),
}
