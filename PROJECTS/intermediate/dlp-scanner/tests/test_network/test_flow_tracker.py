"""
©AngelaMos | 2026
test_flow_tracker.py
"""


from dlp_scanner.network.flow_tracker import (
    FlowTracker,
    make_flow_key,
)
from dlp_scanner.network.pcap import PacketInfo


def _make_packet(
    src_ip: str = "192.168.1.1",
    dst_ip: str = "10.0.0.1",
    src_port: int = 12345,
    dst_port: int = 80,
    protocol: str = "tcp",
    payload: bytes = b"data",
    timestamp: float = 1.0,
    tcp_seq: int = 0,
) -> PacketInfo:
    """
    Helper to create a PacketInfo for testing
    """
    return PacketInfo(
        timestamp = timestamp,
        src_ip = src_ip,
        dst_ip = dst_ip,
        src_port = src_port,
        dst_port = dst_port,
        protocol = protocol,
        payload = payload,
        raw_length = len(payload) + 54,
        tcp_seq = tcp_seq,
    )


class TestMakeFlowKey:
    def test_bidirectional_key(self) -> None:
        pkt_fwd = _make_packet(
            src_ip = "192.168.1.1",
            dst_ip = "10.0.0.1",
            src_port = 12345,
            dst_port = 80,
        )
        pkt_rev = _make_packet(
            src_ip = "10.0.0.1",
            dst_ip = "192.168.1.1",
            src_port = 80,
            dst_port = 12345,
        )
        assert make_flow_key(pkt_fwd) == make_flow_key(pkt_rev)

    def test_different_ports_different_key(
        self,
    ) -> None:
        pkt1 = _make_packet(src_port = 1000)
        pkt2 = _make_packet(src_port = 2000)
        assert make_flow_key(pkt1) != make_flow_key(pkt2)


class TestFlowTracker:
    def test_add_single_packet(self) -> None:
        tracker = FlowTracker()
        pkt = _make_packet()
        tracker.add_packet(pkt)

        assert tracker.flow_count == 1
        flows = tracker.get_flows()
        assert flows[0].packet_count == 1
        assert flows[0].total_bytes == 4

    def test_add_multiple_packets_same_flow(
        self,
    ) -> None:
        tracker = FlowTracker()
        pkt1 = _make_packet(timestamp = 1.0)
        pkt2 = _make_packet(timestamp = 2.0)
        tracker.add_packet(pkt1)
        tracker.add_packet(pkt2)

        assert tracker.flow_count == 1
        flow = tracker.get_flows()[0]
        assert flow.packet_count == 2
        assert flow.total_bytes == 8
        assert flow.start_time == 1.0
        assert flow.end_time == 2.0

    def test_different_flows_tracked(self) -> None:
        tracker = FlowTracker()
        pkt1 = _make_packet(dst_port = 80)
        pkt2 = _make_packet(dst_port = 443)
        tracker.add_packet(pkt1)
        tracker.add_packet(pkt2)

        assert tracker.flow_count == 2

    def test_bidirectional_packets_same_flow(
        self,
    ) -> None:
        tracker = FlowTracker()
        pkt_out = _make_packet(
            src_ip = "192.168.1.1",
            dst_ip = "10.0.0.1",
        )
        pkt_in = _make_packet(
            src_ip = "10.0.0.1",
            dst_ip = "192.168.1.1",
            src_port = 80,
            dst_port = 12345,
        )
        tracker.add_packet(pkt_out)
        tracker.add_packet(pkt_in)

        assert tracker.flow_count == 1
        flow = tracker.get_flows()[0]
        assert flow.packet_count == 2

    def test_reassemble_stream_ordered(
        self,
    ) -> None:
        tracker = FlowTracker()
        pkt1 = _make_packet(
            payload = b"first",
            tcp_seq = 100,
            timestamp = 1.0,
        )
        pkt2 = _make_packet(
            payload = b"second",
            tcp_seq = 200,
            timestamp = 2.0,
        )
        pkt3 = _make_packet(
            payload = b"third",
            tcp_seq = 150,
            timestamp = 1.5,
        )
        tracker.add_packet(pkt1)
        tracker.add_packet(pkt2)
        tracker.add_packet(pkt3)

        key = make_flow_key(pkt1)
        stream = tracker.reassemble_stream(key)
        assert stream == b"firstthirdsecond"

    def test_reassemble_deduplicates_retransmits(
        self,
    ) -> None:
        tracker = FlowTracker()
        pkt1 = _make_packet(
            payload = b"data",
            tcp_seq = 100,
        )
        pkt2 = _make_packet(
            payload = b"data",
            tcp_seq = 100,
        )
        tracker.add_packet(pkt1)
        tracker.add_packet(pkt2)

        key = make_flow_key(pkt1)
        stream = tracker.reassemble_stream(key)
        assert stream == b"data"

    def test_reassemble_unknown_key(self) -> None:
        tracker = FlowTracker()
        result = tracker.reassemble_stream(("1.1.1.1", "2.2.2.2", 1, 2))
        assert result == b""

    def test_get_flow_by_key(self) -> None:
        tracker = FlowTracker()
        pkt = _make_packet()
        tracker.add_packet(pkt)

        key = make_flow_key(pkt)
        flow = tracker.get_flow(key)
        assert flow is not None
        assert flow.packet_count == 1

    def test_get_flow_missing_key(self) -> None:
        tracker = FlowTracker()
        flow = tracker.get_flow(("1.1.1.1", "2.2.2.2", 0, 0))
        assert flow is None

    def test_empty_payload_not_stored(self) -> None:
        tracker = FlowTracker()
        pkt = _make_packet(payload = b"")
        tracker.add_packet(pkt)

        key = make_flow_key(pkt)
        flow = tracker.get_flow(key)
        assert flow is not None
        assert len(flow.segments) == 0
