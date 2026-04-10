"""
©AngelaMos | 2026
test_pcap.py
"""


from dlp_scanner.network.pcap import PacketInfo


class TestPacketInfo:
    def test_tcp_packet_construction(self) -> None:
        pkt = PacketInfo(
            timestamp = 1000.0,
            src_ip = "192.168.1.1",
            dst_ip = "10.0.0.1",
            src_port = 12345,
            dst_port = 80,
            protocol = "tcp",
            payload = b"hello",
            raw_length = 100,
            tcp_flags = 0x02,
            tcp_seq = 1000,
        )
        assert pkt.src_ip == "192.168.1.1"
        assert pkt.dst_ip == "10.0.0.1"
        assert pkt.protocol == "tcp"
        assert pkt.payload == b"hello"
        assert pkt.tcp_seq == 1000

    def test_udp_packet_defaults(self) -> None:
        pkt = PacketInfo(
            timestamp = 1000.0,
            src_ip = "10.0.0.1",
            dst_ip = "8.8.8.8",
            src_port = 54321,
            dst_port = 53,
            protocol = "udp",
            payload = b"\x00",
            raw_length = 50,
        )
        assert pkt.tcp_flags == 0
        assert pkt.tcp_seq == 0
        assert pkt.protocol == "udp"

    def test_packet_is_frozen(self) -> None:
        pkt = PacketInfo(
            timestamp = 1.0,
            src_ip = "1.1.1.1",
            dst_ip = "2.2.2.2",
            src_port = 1,
            dst_port = 2,
            protocol = "tcp",
            payload = b"",
            raw_length = 0,
        )
        try:
            pkt.src_ip = "changed"
            raise AssertionError()
        except AttributeError:
            pass
