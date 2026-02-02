"""
ⒸAngelaMos | 2026
models.py

Data models for packet capture and network traffic analysis
"""

from dataclasses import dataclass, field
from enum import StrEnum


class Protocol(StrEnum):
    """
    Network protocols identified during packet analysis
    """
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    DNS = "DNS"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    ARP = "ARP"
    OTHER = "OTHER"


@dataclass(frozen=True, slots=True)
class PacketInfo:
    """
    Information extracted from a single captured packet
    """
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: Protocol
    size: int
    src_port: int | None = None
    dst_port: int | None = None
    src_mac: str | None = None
    dst_mac: str | None = None


@dataclass(slots=True)
class EndpointStats:
    """
    Traffic statistics for a single network endpoint
    """
    ip_address: str
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0

    @property
    def total_packets(self) -> int:
        """
        Calculate total packets for this endpoint
        """
        return self.packets_sent + self.packets_received

    @property
    def total_bytes(self) -> int:
        """
        Calculate total bytes for this endpoint
        """
        return self.bytes_sent + self.bytes_received


@dataclass(slots=True)
class ConversationStats:
    """
    Traffic statistics for a conversation between two endpoints
    """
    endpoint_a: str
    endpoint_b: str
    packets: int = 0
    bytes_total: int = 0


@dataclass(slots=True)
class BandwidthSample:
    """
    Bandwidth measurement at a point in time
    """
    timestamp: float
    bytes_per_second: float
    packets_per_second: float


@dataclass(slots=True)
class CaptureStatistics:
    """
    Aggregated statistics from a packet capture session
    """
    start_time: float = 0.0
    end_time: float = 0.0
    total_packets: int = 0
    total_bytes: int = 0
    protocol_distribution: dict[Protocol,
                                int] = field(default_factory=dict)
    protocol_bytes: dict[Protocol, int] = field(default_factory=dict)
    endpoints: dict[str, EndpointStats] = field(default_factory=dict)
    conversations: dict[tuple[str,
                              str],
                        ConversationStats] = field(default_factory=dict)
    bandwidth_samples: list[BandwidthSample] = field(
        default_factory=list
    )

    @property
    def duration_seconds(self) -> float:
        """
        Calculate capture duration in seconds
        """
        if self.end_time <= self.start_time:
            return 0.0
        return self.end_time - self.start_time

    @property
    def average_bandwidth(self) -> float:
        """
        Calculate average bandwidth in bytes per second
        """
        duration = self.duration_seconds
        if duration <= 0:
            return 0.0
        return self.total_bytes / duration

    def get_top_talkers(self, limit: int = 10) -> list[EndpointStats]:
        """
        Return endpoints sorted by total bytes transferred
        """
        sorted_endpoints = sorted(
            self.endpoints.values(),
            key=lambda e: e.total_bytes,
            reverse=True
        )
        return sorted_endpoints[: limit]

    def get_protocol_percentages(self) -> dict[Protocol, float]:
        """
        Calculate protocol distribution as percentages
        """
        if self.total_packets == 0:
            return {}
        return {
            proto: (count / self.total_packets) * 100
            for proto, count in self.protocol_distribution.items()
        }


@dataclass(frozen=True, slots=True)
class CaptureConfig:
    """
    Configuration for a packet capture session
    """
    interface: str | None = None
    bpf_filter: str | None = None
    packet_count: int | None = None
    timeout_seconds: float | None = None
    promiscuous: bool = True
    store_packets: bool = False


@dataclass(frozen=True, slots=True)
class ExportOptions:
    """
    Options for exporting capture data
    """
    include_packets: bool = True
    include_statistics: bool = True
    include_endpoints: bool = True
    include_conversations: bool = True
    pretty_print: bool = True
