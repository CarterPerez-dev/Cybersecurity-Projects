"""
ⒸAngelaMos | 2026
statistics.py

Thread safe statistics collection for packet capture analysis
"""

import threading
import time
from collections import defaultdict

from netanal.constants import CaptureDefaults
from netanal.models import (
    BandwidthSample,
    CaptureStatistics,
    ConversationStats,
    EndpointStats,
    PacketInfo,
    Protocol,
)


class StatisticsCollector:
    """
    Thread safe collector for packet capture statistics
    """
    def __init__(
        self,
        bandwidth_interval: float = CaptureDefaults.
        BANDWIDTH_SAMPLE_INTERVAL_SECONDS,
    ) -> None:
        """
        Initialize statistics collector with bandwidth sampling interval
        """
        self._lock = threading.Lock()
        self._bandwidth_interval = bandwidth_interval

        self._start_time: float = 0.0
        self._last_sample_time: float = 0.0
        self._interval_bytes: int = 0
        self._interval_packets: int = 0

        self._total_packets: int = 0
        self._total_bytes: int = 0
        self._protocol_counts: dict[Protocol, int] = defaultdict(int)
        self._protocol_bytes: dict[Protocol, int] = defaultdict(int)
        self._endpoints: dict[str, EndpointStats] = {}
        self._conversations: dict[tuple[str, str], ConversationStats] = {}
        self._bandwidth_samples: list[BandwidthSample] = []

    def start(self) -> None:
        """
        Mark the start of a capture session
        """
        with self._lock:
            self._start_time = time.time()
            self._last_sample_time = self._start_time

    def record_packet(self, packet: PacketInfo) -> None:
        """
        Record statistics for a captured packet (thread-safe)
        """
        with self._lock:
            self._total_packets += 1
            self._total_bytes += packet.size
            self._interval_packets += 1
            self._interval_bytes += packet.size

            self._protocol_counts[packet.protocol] += 1
            self._protocol_bytes[packet.protocol] += packet.size

            self._update_endpoint(packet.src_ip, sent_bytes=packet.size)
            self._update_endpoint(
                packet.dst_ip,
                received_bytes=packet.size
            )

            self._update_conversation(
                packet.src_ip,
                packet.dst_ip,
                packet.size
            )

            self._check_bandwidth_sample(packet.timestamp)

    def _update_endpoint(
        self,
        ip_address: str,
        sent_bytes: int = 0,
        received_bytes: int = 0,
    ) -> None:
        """
        Update statistics for a network endpoint
        """
        if ip_address not in self._endpoints:
            self._endpoints[ip_address] = EndpointStats(
                ip_address=ip_address
            )

        endpoint = self._endpoints[ip_address]
        if sent_bytes > 0:
            endpoint.packets_sent += 1
            endpoint.bytes_sent += sent_bytes
        if received_bytes > 0:
            endpoint.packets_received += 1
            endpoint.bytes_received += received_bytes

    def _update_conversation(
        self,
        src_ip: str,
        dst_ip: str,
        size: int,
    ) -> None:
        """
        Update statistics for a conversation between two endpoints
        """
        key = tuple(sorted([src_ip, dst_ip]))
        conv_key = (key[0], key[1])

        if conv_key not in self._conversations:
            self._conversations[conv_key] = ConversationStats(
                endpoint_a=conv_key[0],
                endpoint_b=conv_key[1],
            )

        conv = self._conversations[conv_key]
        conv.packets += 1
        conv.bytes_total += size

    def _check_bandwidth_sample(self, timestamp: float) -> None:
        """
        Check if bandwidth sample interval has elapsed and record if so
        """
        if timestamp - self._last_sample_time >= self._bandwidth_interval:
            elapsed = timestamp - self._last_sample_time
            if elapsed > 0:
                bps = self._interval_bytes / elapsed
                pps = self._interval_packets / elapsed
                self._bandwidth_samples.append(
                    BandwidthSample(
                        timestamp=timestamp,
                        bytes_per_second=bps,
                        packets_per_second=pps,
                    )
                )
            self._interval_bytes = 0
            self._interval_packets = 0
            self._last_sample_time = timestamp

    def get_statistics(self) -> CaptureStatistics:
        """
        Get current capture statistics snapshot (thread-safe)
        """
        with self._lock:
            return CaptureStatistics(
                start_time=self._start_time,
                end_time=time.time(),
                total_packets=self._total_packets,
                total_bytes=self._total_bytes,
                protocol_distribution=dict(self._protocol_counts),
                protocol_bytes=dict(self._protocol_bytes),
                endpoints=dict(self._endpoints),
                conversations=dict(self._conversations),
                bandwidth_samples=list(self._bandwidth_samples),
            )

    def reset(self) -> None:
        """
        Reset all statistics to initial state
        """
        with self._lock:
            self._start_time = 0.0
            self._last_sample_time = 0.0
            self._interval_bytes = 0
            self._interval_packets = 0
            self._total_packets = 0
            self._total_bytes = 0
            self._protocol_counts = defaultdict(int)
            self._protocol_bytes = defaultdict(int)
            self._endpoints = {}
            self._conversations = {}
            self._bandwidth_samples = []

    @property
    def packet_count(self) -> int:
        """
        Get current packet count (thread-safe)
        """
        with self._lock:
            return self._total_packets

    @property
    def byte_count(self) -> int:
        """
        Get current byte count (thread-safe)
        """
        with self._lock:
            return self._total_bytes


__all__ = [
    "StatisticsCollector",
]
