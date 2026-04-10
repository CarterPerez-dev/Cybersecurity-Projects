"""
©AngelaMos | 2026
pcap.py
"""


import socket
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import structlog


log = structlog.get_logger()

TCP_PROTO: int = 6
UDP_PROTO: int = 17


@dataclass(frozen = True, slots = True)
class PacketInfo:
    """
    Parsed network packet with extracted metadata
    """

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    payload: bytes
    raw_length: int
    tcp_flags: int = 0
    tcp_seq: int = 0


def read_pcap(
    path: Path,
    max_packets: int = 0,
) -> Iterator[PacketInfo]:
    """
    Read packets from a PCAP or PCAPNG file
    """
    import dpkt

    with open(path, "rb") as f:
        try:
            pcap = dpkt.pcap.Reader(f)
        except ValueError:
            f.seek(0)
            pcap = dpkt.pcapng.Reader(f)

        count = 0
        for timestamp, buf in pcap:
            if max_packets > 0 and count >= max_packets:
                break

            packet = _parse_ethernet(timestamp, buf)
            if packet is not None:
                yield packet
                count += 1


def _parse_ethernet(
    timestamp: float,
    buf: bytes,
) -> PacketInfo | None:
    """
    Parse an Ethernet frame into a PacketInfo
    """
    import dpkt

    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except (dpkt.NeedData, dpkt.UnpackError):
        return None

    if not isinstance(eth.data, dpkt.ip.IP):
        return None

    ip_pkt = eth.data
    src_ip = socket.inet_ntoa(ip_pkt.src)
    dst_ip = socket.inet_ntoa(ip_pkt.dst)

    if isinstance(ip_pkt.data, dpkt.tcp.TCP):
        tcp = ip_pkt.data
        return PacketInfo(
            timestamp = timestamp,
            src_ip = src_ip,
            dst_ip = dst_ip,
            src_port = tcp.sport,
            dst_port = tcp.dport,
            protocol = "tcp",
            payload = bytes(tcp.data),
            raw_length = len(buf),
            tcp_flags = tcp.flags,
            tcp_seq = tcp.seq,
        )

    if isinstance(ip_pkt.data, dpkt.udp.UDP):
        udp = ip_pkt.data
        return PacketInfo(
            timestamp = timestamp,
            src_ip = src_ip,
            dst_ip = dst_ip,
            src_port = udp.sport,
            dst_port = udp.dport,
            protocol = "udp",
            payload = bytes(udp.data),
            raw_length = len(buf),
        )

    return None
