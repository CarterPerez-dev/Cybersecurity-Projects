"""
©AngelaMos | 2026
loader.py
"""
from __future__ import annotations

import os
import signal
import sys
from collections.abc import Callable
from typing import Any

from .config import (
    EBPF_DIR,
    MIN_KERNEL_MAJOR,
    MIN_KERNEL_MINOR,
    TracerType,
)

TRACER_FILES: dict[str, str] = {
    "process": "process_tracer.c",
    "file": "file_tracer.c",
    "network": "network_tracer.c",
    "privilege": "privilege_tracer.c",
    "system": "system_tracer.c",
}


def check_privileges() -> None:
    """
    Verify the process has root privileges
    """
    if os.geteuid() != 0:
        sys.stderr.write("Error: eBPF tracing requires root privileges.\n"
                         "Run with: sudo uv run ebpf-tracer\n")
        sys.exit(1)


def check_kernel_version() -> None:
    """
    Verify the kernel version supports ring buffers
    """
    release = os.uname().release
    parts = release.split(".")
    major = int(parts[0])
    minor = int(parts[1].split("-")[0])

    if (major < MIN_KERNEL_MAJOR
            or (major == MIN_KERNEL_MAJOR and minor < MIN_KERNEL_MINOR)):
        sys.stderr.write(f"Error: Kernel {release} detected. "
                         f"Requires {MIN_KERNEL_MAJOR}."
                         f"{MIN_KERNEL_MINOR}+ for ring buffer.\n")
        sys.exit(1)


def _resolve_tracers(tracer_type: TracerType, ) -> list[str]:
    """
    Determine which tracer files to load
    """
    if tracer_type == "all":
        return list(TRACER_FILES.keys())
    return [tracer_type]


class TracerLoader:
    """
    Loads and manages eBPF programs via BCC
    """

    def __init__(
        self,
        tracer_type: TracerType,
        callback: Callable[..., None],
    ) -> None:
        """
        Initialize the loader with tracer selection
        """
        self._bpf_objects: list[Any] = []
        self._tracer_type = tracer_type
        self._callback = callback
        self._running = False

    def load(self) -> None:
        """
        Compile and load all selected eBPF programs
        """
        from bcc import BPF  # type: ignore[import-untyped]

        tracers = _resolve_tracers(self._tracer_type)

        for name in tracers:
            filename = TRACER_FILES[name]
            src_path = EBPF_DIR / filename
            c_text = src_path.read_text()

            bpf = BPF(text=c_text)
            bpf["events"].open_ring_buffer(self._callback)
            self._bpf_objects.append(bpf)

    def poll(self) -> None:
        """
        Start polling all ring buffers for events
        """
        self._running = True
        original_sigint = signal.getsignal(signal.SIGINT)
        original_sigterm = signal.getsignal(signal.SIGTERM)

        def _handle_stop(signum: int, frame: Any) -> None:
            self._running = False

        signal.signal(signal.SIGINT, _handle_stop)
        signal.signal(signal.SIGTERM, _handle_stop)

        try:
            while self._running:
                for bpf in self._bpf_objects:
                    bpf.ring_buffer_poll(timeout=100)
        finally:
            signal.signal(signal.SIGINT, original_sigint)
            signal.signal(signal.SIGTERM, original_sigterm)
            self.cleanup()

    def cleanup(self) -> None:
        """
        Detach all eBPF programs and free resources
        """
        for bpf in self._bpf_objects:
            bpf.cleanup()
        self._bpf_objects.clear()
