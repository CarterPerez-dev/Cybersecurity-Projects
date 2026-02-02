"""
ⒸAngelaMos | 2026
analyzer.py

Protocol dissection and packet analysis using Scapy layers
"""

from scapy.layers.dns import DNS
from scapy.layers.inet import (
    ICMP,
    IP,
    TCP,
    UDP,
)
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet
from scapy.utils import PcapReader

from netanal.constants import DefaultIPs, Ports
from netanal.models import PacketInfo, Protocol


def identify_protocol(packet: Packet) -> Protocol:
    """
    Identify the highest level protocol in a packet
    """
    if packet.haslayer(DNS):
        return Protocol.DNS

    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        if tcp_layer.dport == Ports.HTTP or tcp_layer.sport == Ports.HTTP:
            return Protocol.HTTP
        if tcp_layer.dport == Ports.HTTPS or tcp_layer.sport == Ports.HTTPS:
            return Protocol.HTTPS
        return Protocol.TCP

    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        if udp_layer.dport == Ports.DNS or udp_layer.sport == Ports.DNS:
            return Protocol.DNS
        return Protocol.UDP

    if packet.haslayer(ICMP):
        return Protocol.ICMP

    if packet.haslayer(ARP):
        return Protocol.ARP

    return Protocol.OTHER


def extract_packet_info(packet: Packet) -> PacketInfo | None:
    """
    Extract relevant information from a Scapy packet
    """
    timestamp = float(packet.time) if hasattr(packet, "time") else 0.0
    size = len(packet)

    src_mac: str | None = None
    dst_mac: str | None = None
    src_ip: str = DefaultIPs.UNKNOWN
    dst_ip: str = DefaultIPs.UNKNOWN
    src_port: int | None = None
    dst_port: int | None = None

    if packet.haslayer(Ether):
        ether_layer = packet[Ether]
        src_mac = ether_layer.src
        dst_mac = ether_layer.dst

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
    elif packet.haslayer(ARP):
        arp_layer = packet[ARP]
        src_ip = arp_layer.psrc
        dst_ip = arp_layer.pdst
    else:
        return None

    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        src_port = udp_layer.sport
        dst_port = udp_layer.dport

    protocol = identify_protocol(packet)

    return PacketInfo(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        size=size,
        src_port=src_port,
        dst_port=dst_port,
        src_mac=src_mac,
        dst_mac=dst_mac,
    )


def extract_dns_info(packet: Packet) -> dict[str, str | list[str]] | None:
    """
    Extract DNS query and response information from a packet
    """
    if not packet.haslayer(DNS):
        return None

    dns_layer = packet[DNS]
    info: dict[str, str | list[str]] = {}

    if dns_layer.qr == 0:
        info["type"] = "query"
        if dns_layer.qd:
            info["query_name"] = dns_layer.qd.qname.decode().rstrip(".")
    else:
        info["type"] = "response"
        answers: list[str] = []
        if dns_layer.an:
            for i in range(dns_layer.ancount):
                try:
                    rr = dns_layer.an[i]
                    if hasattr(rr, "rdata"):
                        answers.append(str(rr.rdata))
                except (IndexError, AttributeError):
                    continue
        info["answers"] = answers

    return info


def get_packet_summary(packet: Packet) -> str:
    """
    Generate a human readable summary of a packet
    """
    info = extract_packet_info(packet)
    if info is None:
        return "Unknown packet"

    summary_parts = [
        f"{info.protocol.value}",
        f"{info.src_ip}",
    ]

    if info.src_port:
        summary_parts.append(f":{info.src_port}")

    summary_parts.append(" -> ")
    summary_parts.append(info.dst_ip)

    if info.dst_port:
        summary_parts.append(f":{info.dst_port}")

    summary_parts.append(f" ({info.size} bytes)")

    return "".join(summary_parts)


def analyze_pcap_file(filepath: str) -> list[PacketInfo]:
    """
    Analyze packets from a pcap file using
    memory efficient PcapReader
    """
    packets: list[PacketInfo] = []

    with PcapReader(filepath) as reader:
        for packet in reader:
            info = extract_packet_info(packet)
            if info:
                packets.append(info)

    return packets


__all__ = [
    "analyze_pcap_file",
    "extract_dns_info",
    "extract_packet_info",
    "get_packet_summary",
    "identify_protocol",
]
