"""
©AngelaMos | 2026
flow_tracker.py
"""


from dataclasses import dataclass, field

import structlog

from dlp_scanner.network.pcap import PacketInfo


log = structlog.get_logger()

FlowKey = tuple[str, str, int, int]


@dataclass(slots = True)
class FlowStats:
    """
    Aggregated statistics for a network flow
    """

    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""
    packet_count: int = 0
    total_bytes: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    segments: list[tuple[int, bytes]] = field(default_factory = list)


class FlowTracker:
    """
    Tracks and reassembles network flows from packets
    """
    def __init__(self) -> None:
        self._flows: dict[FlowKey, FlowStats] = {}

    def add_packet(self, packet: PacketInfo) -> None:
        """
        Add a packet to its corresponding flow
        """
        key = make_flow_key(packet)
        flow = self._flows.get(key)

        if flow is None:
            flow = FlowStats(
                src_ip = packet.src_ip,
                dst_ip = packet.dst_ip,
                src_port = packet.src_port,
                dst_port = packet.dst_port,
                protocol = packet.protocol,
                start_time = packet.timestamp,
            )
            self._flows[key] = flow

        flow.packet_count += 1
        flow.total_bytes += len(packet.payload)
        flow.end_time = packet.timestamp

        if packet.payload:
            flow.segments.append((packet.tcp_seq, packet.payload))

    def get_flows(self) -> list[FlowStats]:
        """
        Return all tracked flows
        """
        return list(self._flows.values())

    def get_flow(self, key: FlowKey) -> FlowStats | None:
        """
        Get a specific flow by key
        """
        return self._flows.get(key)

    def reassemble_stream(self, key: FlowKey) -> bytes:
        """
        Reassemble TCP payload ordered by sequence number
        """
        flow = self._flows.get(key)
        if flow is None:
            return b""

        sorted_segments = sorted(flow.segments, key = lambda s: s[0])

        seen_offsets: set[int] = set()
        parts: list[bytes] = []
        for seq, data in sorted_segments:
            if seq not in seen_offsets:
                seen_offsets.add(seq)
                parts.append(data)

        return b"".join(parts)

    @property
    def flow_count(self) -> int:
        """
        Return the number of tracked flows
        """
        return len(self._flows)


def make_flow_key(
    packet: PacketInfo,
) -> FlowKey:
    """
    Create a bidirectional flow key from a packet
    """
    forward = (
        packet.src_ip,
        packet.dst_ip,
        packet.src_port,
        packet.dst_port,
    )
    reverse = (
        packet.dst_ip,
        packet.src_ip,
        packet.dst_port,
        packet.src_port,
    )
    return min(forward, reverse)
