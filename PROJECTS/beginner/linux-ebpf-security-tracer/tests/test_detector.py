"""
©AngelaMos | 2026
test_detector.py
"""
from __future__ import annotations

from src.detector import DetectionEngine


class TestPrivilegeEscalation:
    """
    Tests for D001 privilege escalation detection
    """

    def test_setuid_zero_by_nonroot(self, make_event):
        """
        Detects setuid(0) from non-root UID
        """
        engine = DetectionEngine()
        event = make_event(
            event_type="setuid",
            category="privilege",
            uid=1000,
            target_uid=0,
        )
        result = engine.evaluate(event)
        assert result.detection == "Privilege Escalation"
        assert result.severity == "CRITICAL"
        assert result.detection_id == "D001"

    def test_setuid_zero_by_root_ignored(self, make_event):
        """
        Allows setuid(0) when already root
        """
        engine = DetectionEngine()
        event = make_event(
            event_type="setuid",
            category="privilege",
            uid=0,
            target_uid=0,
        )
        result = engine.evaluate(event)
        assert result.detection is None

    def test_setuid_nonzero_ignored(self, make_event):
        """
        Allows setuid to non-root UIDs
        """
        engine = DetectionEngine()
        event = make_event(
            event_type="setuid",
            category="privilege",
            uid=1000,
            target_uid=1001,
        )
        result = engine.evaluate(event)
        assert result.detection is None


class TestSensitiveFileRead:
    """
    Tests for D002 sensitive file read detection
    """

    def test_shadow_read_nonroot(self, make_event):
        """
        Detects /etc/shadow access by non-root
        """
        engine = DetectionEngine()
        event = make_event(
            event_type="openat",
            category="file",
            uid=1000,
            filename="/etc/shadow",
        )
        result = engine.evaluate(event)
        assert result.detection == "Sensitive File Read"
        assert result.severity == "MEDIUM"

    def test_shadow_read_root_ignored(self, make_event):
        """
        Allows /etc/shadow access by root
        """
        engine = DetectionEngine()
        event = make_event(
            event_type="openat",
            category="file",
            uid=0,
            filename="/etc/shadow",
        )
        result = engine.evaluate(event)
        assert result.detection is None

    def test_gshadow_read_nonroot(self, make_event):
        """
        Detects /etc/gshadow access by non-root
        """
        engine = DetectionEngine()
        event = make_event(
            event_type="openat",
            category="file",
            uid=1000,
            filename="/etc/gshadow",
        )
        result = engine.evaluate(event)
        assert result.detection == "Sensitive File Read"

    def test_shadow_write_not_read_detection(self, make_event):
        """
        Write to sensitive file does not trigger read detection
        """
        engine = DetectionEngine()
        event = make_event(
            event_type="openat",
            category="file",
            uid=1000,
            filename="/etc/shadow",
            flags=1,
        )
        result = engine.evaluate(event)
        assert result.detection != "Sensitive File Read"


class TestSSHKeyAccess:
    """
    Tests for D003 SSH key access detection
    """

    def test_ssh_private_key(self, make_event):
        """
        Detects SSH private key file access
        """
        engine = DetectionEngine()
        event = make_event(
            event_type="openat",
            category="file",
            filename="/home/user/.ssh/id_rsa",
        )
        result = engine.evaluate(event)
        assert result.detection == "SSH Key Access"
        assert result.mitre_id == "T1552.004"

    def test_authorized_keys(self, make_event):
        """
        Detects authorized_keys access
        """
        engine = DetectionEngine()
        event = make_event(
            event_type="openat",
            category="file",
            filename="/root/.ssh/authorized_keys",
        )
        result = engine.evaluate(event)
        assert result.detection == "SSH Key Access"

    def test_sshd_authorized_keys_ignored(self, make_event):
        """
        Allows sshd to read authorized_keys
        """
        engine = DetectionEngine()
        event = make_event(
            event_type="openat",
            category="file",
            comm="sshd",
            filename="/root/.ssh/authorized_keys",
        )
        result = engine.evaluate(event)
        assert result.detection is None

    def test_ssh_agent_key_ignored(self, make_event):
        """
        Allows ssh-agent to access private keys
        """
        engine = DetectionEngine()
        event = make_event(
            event_type="openat",
            category="file",
            comm="ssh-agent",
            filename="/home/user/.ssh/id_ed25519",
        )
        result = engine.evaluate(event)
        assert result.detection is None


class TestProcessInjection:
    """
    Tests for D004 ptrace-based injection detection
    """

    def test_ptrace_attach(self, make_event):
        """
        Detects PTRACE_ATTACH calls
        """
        engine = DetectionEngine()
        event = make_event(
            event_type="ptrace",
            category="system",
            ptrace_request=16,
            target_pid=1234,
        )
        result = engine.evaluate(event)
        assert result.detection == "Process Injection"
        assert result.mitre_id == "T1055.008"

    def test_ptrace_setregs(self, make_event):
        """
        Detects PTRACE_SETREGS calls
        """
        engine = DetectionEngine()
        event = make_event(
            event_type="ptrace",
            category="system",
            ptrace_request=13,
            target_pid=1234,
        )
        result = engine.evaluate(event)
        assert result.detection == "Process Injection"

    def test_ptrace_traceme_ignored(self, make_event):
        """
        Ignores PTRACE_TRACEME (normal debugging)
        """
        engine = DetectionEngine()
        event = make_event(
            event_type="ptrace",
            category="system",
            ptrace_request=0,
            target_pid=0,
        )
        result = engine.evaluate(event)
        assert result.detection is None


class TestKernelModule:
    """
    Tests for D005 kernel module load detection
    """

    def test_init_module(self, make_event):
        """
        Detects init_module calls
        """
        engine = DetectionEngine()
        event = make_event(
            event_type="init_module",
            category="system",
        )
        result = engine.evaluate(event)
        assert result.detection == "Kernel Module Load"
        assert result.severity == "HIGH"


class TestPersistence:
    """
    Tests for D007/D008 persistence detection
    """

    def test_cron_write(self, make_event):
        """
        Detects writes to cron directories
        """
        engine = DetectionEngine()
        event = make_event(
            event_type="openat",
            category="file",
            filename="/etc/cron.d/backdoor",
            flags=1,
        )
        result = engine.evaluate(event)
        assert result.detection == "Persistence via Cron"

    def test_systemd_write(self, make_event):
        """
        Detects writes to systemd unit directories
        """
        engine = DetectionEngine()
        event = make_event(
            event_type="openat",
            category="file",
            filename="/etc/systemd/system/evil.service",
            flags=1,
        )
        result = engine.evaluate(event)
        assert result.detection == "Persistence via Systemd"

    def test_cron_read_ignored(self, make_event):
        """
        Allows reads from cron directories
        """
        engine = DetectionEngine()
        event = make_event(
            event_type="openat",
            category="file",
            filename="/etc/cron.d/something",
            flags=0,
        )
        result = engine.evaluate(event)
        assert result.detection is None


class TestLogTampering:
    """
    Tests for D009 log tampering detection
    """

    def test_log_truncation(self, make_event):
        """
        Detects log file truncation
        """
        engine = DetectionEngine()
        event = make_event(
            event_type="openat",
            category="file",
            filename="/var/log/auth.log",
            flags=512,
        )
        result = engine.evaluate(event)
        assert result.detection == "Log Tampering"

    def test_log_deletion(self, make_event):
        """
        Detects log file deletion
        """
        engine = DetectionEngine()
        event = make_event(
            event_type="unlinkat",
            category="file",
            filename="/var/log/syslog",
        )
        result = engine.evaluate(event)
        assert result.detection == "Log Tampering"


class TestReverseShell:
    """
    Tests for D006 reverse shell correlation detection
    """

    def test_connect_then_shell(self, make_event):
        """
        Detects shell spawn after network connect
        """
        engine = DetectionEngine()

        connect_event = make_event(
            event_type="connect",
            category="network",
            pid=2000,
            addr_v4="10.0.0.1",
            port=4444,
        )
        engine.evaluate(connect_event)

        shell_event = make_event(
            event_type="execve",
            category="process",
            pid=2000,
            comm="bash",
            filename="/bin/bash",
        )
        result = engine.evaluate(shell_event)
        assert result.detection == "Reverse Shell"
        assert result.severity == "CRITICAL"

    def test_shell_without_connect(self, make_event):
        """
        Normal shell execution is not flagged
        """
        engine = DetectionEngine()
        event = make_event(
            event_type="execve",
            category="process",
            pid=3000,
            comm="bash",
            filename="/bin/bash",
        )
        result = engine.evaluate(event)
        assert result.detection is None

    def test_connect_then_nonshell(self, make_event):
        """
        Non-shell execution after connect is not flagged
        """
        engine = DetectionEngine()

        connect_event = make_event(
            event_type="connect",
            category="network",
            pid=4000,
            addr_v4="10.0.0.1",
            port=80,
        )
        engine.evaluate(connect_event)

        exec_event = make_event(
            event_type="execve",
            category="process",
            pid=4000,
            comm="curl",
            filename="/usr/bin/curl",
        )
        result = engine.evaluate(exec_event)
        assert result.detection is None

    def test_shell_then_connect(self, make_event):
        """
        Detects network connect after shell execution
        """
        engine = DetectionEngine()

        shell_event = make_event(
            event_type="execve",
            category="process",
            pid=5000,
            comm="bash",
            filename="/bin/bash",
        )
        engine.evaluate(shell_event)

        connect_event = make_event(
            event_type="connect",
            category="network",
            pid=5000,
            addr_v4="10.0.0.1",
            port=4444,
        )
        result = engine.evaluate(connect_event)
        assert result.detection == "Reverse Shell"
        assert result.severity == "CRITICAL"

    def test_nonshell_then_connect(self, make_event):
        """
        Connect after non-shell exec is not flagged
        """
        engine = DetectionEngine()

        exec_event = make_event(
            event_type="execve",
            category="process",
            pid=6000,
            comm="curl",
            filename="/usr/bin/curl",
        )
        engine.evaluate(exec_event)

        connect_event = make_event(
            event_type="connect",
            category="network",
            pid=6000,
            addr_v4="10.0.0.1",
            port=80,
        )
        result = engine.evaluate(connect_event)
        assert result.detection is None


class TestMount:
    """
    Tests for D010 suspicious mount detection
    """

    def test_mount_detected(self, make_event):
        """
        Detects mount syscalls
        """
        engine = DetectionEngine()
        event = make_event(
            event_type="mount",
            category="system",
            filename="/dev/sda1",
        )
        result = engine.evaluate(event)
        assert result.detection == "Suspicious Mount"
        assert result.severity == "HIGH"
