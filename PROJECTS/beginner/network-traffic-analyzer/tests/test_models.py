"""
ⒸAngelaMos | 2026
test_models.py

Basic happy path tests for data models
"""

import pytest

from netanal.models import (
    CaptureConfig,
    CaptureStatistics,
    EndpointStats,
    PacketInfo,
    Protocol,
)


class TestProtocol:
    """
    Tests for the Protocol enum
    """
    def test_protocol_values(self):
        """
        Verify all protocol enum values match expected strings
        """
        assert Protocol.TCP.value == "TCP"
        assert Protocol.UDP.value == "UDP"
        assert Protocol.ICMP.value == "ICMP"
        assert Protocol.DNS.value == "DNS"
        assert Protocol.HTTP.value == "HTTP"
        assert Protocol.HTTPS.value == "HTTPS"
        assert Protocol.ARP.value == "ARP"
        assert Protocol.OTHER.value == "OTHER"


class TestPacketInfo:
    """
    Tests for the PacketInfo dataclass
    """
    def test_create_packet_info(self):
        """
        Verify PacketInfo stores all fields correctly
        """
        packet = PacketInfo(
            timestamp = 1234567890.123,
            src_ip = "192.168.1.1",
            dst_ip = "192.168.1.2",
            protocol = Protocol.TCP,
            size = 1500,
            src_port = 443,
            dst_port = 54321,
        )

        assert packet.timestamp == 1234567890.123
        assert packet.src_ip == "192.168.1.1"
        assert packet.dst_ip == "192.168.1.2"
        assert packet.protocol == Protocol.TCP
        assert packet.size == 1500
        assert packet.src_port == 443
        assert packet.dst_port == 54321

    def test_packet_info_optional_fields(self):
        """
        Verify optional fields default to None
        """
        packet = PacketInfo(
            timestamp = 0.0,
            src_ip = "10.0.0.1",
            dst_ip = "10.0.0.2",
            protocol = Protocol.ICMP,
            size = 64,
        )

        assert packet.src_port is None
        assert packet.dst_port is None
        assert packet.src_mac is None
        assert packet.dst_mac is None


class TestCaptureConfig:
    """
    Tests for the CaptureConfig dataclass
    """
    def test_default_config(self):
        """
        Verify default configuration values
        """
        config = CaptureConfig()

        assert config.interface is None
        assert config.bpf_filter is None
        assert config.packet_count is None
        assert config.timeout_seconds is None
        assert config.store_packets is False

    def test_custom_config(self):
        """
        Verify custom configuration is stored correctly
        """
        config = CaptureConfig(
            interface = "eth0",
            bpf_filter = "tcp port 80",
            packet_count = 100,
            timeout_seconds = 30.0,
        )

        assert config.interface == "eth0"
        assert config.bpf_filter == "tcp port 80"
        assert config.packet_count == 100
        assert config.timeout_seconds == 30.0


class TestEndpointStats:
    """
    Tests for the EndpointStats dataclass
    """
    def test_endpoint_stats_totals(self):
        """
        Verify total_packets and total_bytes computed properties
        """
        endpoint = EndpointStats(ip_address = "192.168.1.100")
        endpoint.packets_sent = 50
        endpoint.packets_received = 30
        endpoint.bytes_sent = 5000
        endpoint.bytes_received = 3000

        assert endpoint.total_packets == 80
        assert endpoint.total_bytes == 8000


class TestCaptureStatistics:
    """
    Tests for the CaptureStatistics dataclass
    """
    def test_empty_statistics(self):
        """
        Verify empty statistics have zero values
        """
        stats = CaptureStatistics()

        assert stats.total_packets == 0
        assert stats.total_bytes == 0
        assert len(stats.protocol_distribution) == 0
        assert len(stats.endpoints) == 0

    def test_duration_calculation(self):
        """
        Verify duration_seconds computed property
        """
        stats = CaptureStatistics(
            start_time = 1000.0,
            end_time = 1010.0,
        )

        assert stats.duration_seconds == 10.0

    def test_average_bandwidth(self):
        """
        Verify average_bandwidth calculation (bytes/second)
        """
        stats = CaptureStatistics(
            start_time = 1000.0,
            end_time = 1010.0,
            total_bytes = 10000,
        )

        assert stats.average_bandwidth == 1000.0

    def test_protocol_percentages(self):
        """
        Verify get_protocol_percentages returns correct distribution
        """
        stats = CaptureStatistics(total_packets = 100)
        stats.protocol_distribution[Protocol.TCP] = 70
        stats.protocol_distribution[Protocol.UDP] = 30

        percentages = stats.get_protocol_percentages()

        assert percentages[Protocol.TCP] == 70.0
        assert percentages[Protocol.UDP] == 30.0

    def test_top_talkers(self):
        """
        Verify get_top_talkers returns endpoints sorted by total bytes
        """
        stats = CaptureStatistics()

        endpoint1 = EndpointStats(ip_address = "192.168.1.1")
        endpoint1.bytes_sent = 1000
        endpoint1.bytes_received = 500

        endpoint2 = EndpointStats(ip_address = "192.168.1.2")
        endpoint2.bytes_sent = 5000
        endpoint2.bytes_received = 2000

        endpoint3 = EndpointStats(ip_address = "192.168.1.3")
        endpoint3.bytes_sent = 100
        endpoint3.bytes_received = 50

        stats.endpoints["192.168.1.1"] = endpoint1
        stats.endpoints["192.168.1.2"] = endpoint2
        stats.endpoints["192.168.1.3"] = endpoint3

        top = stats.get_top_talkers(limit = 2)

        assert len(top) == 2
        assert top[0].ip_address == "192.168.1.2"
        assert top[1].ip_address == "192.168.1.1"
