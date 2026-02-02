"""
ⒸAngelaMos | 2026
filters.py

BPF filter builder for kernel-level packet filtering
"""

import ipaddress
from dataclasses import dataclass
from typing import Literal, Self

from netanal.constants import PortRange, Ports
from netanal.exceptions import ValidationError
from netanal.models import Protocol


BPF_PROTOCOL_MAP: dict[Protocol,
                       str] = {
                           Protocol.TCP: "tcp",
                           Protocol.UDP: "udp",
                           Protocol.ICMP: "icmp",
                           Protocol.ARP: "arp",
                           Protocol.DNS:
                           f"udp port {Ports.DNS} or tcp port {Ports.DNS}",
                           Protocol.HTTP: f"tcp port {Ports.HTTP}",
                           Protocol.HTTPS: f"tcp port {Ports.HTTPS}",
                       }


def _validate_port(port_number: int) -> None:
    """
    Validate port number is within valid range
    """
    if not PortRange.MIN <= port_number <= PortRange.MAX:
        raise ValidationError(
            f"Port must be {PortRange.MIN}-{PortRange.MAX}, got {port_number}"
        )


def _validate_ip_address(ip_address: str) -> None:
    """
    Validate IP address format
    """
    try:
        ipaddress.ip_address(ip_address)
    except ValueError as e:
        raise ValidationError(f"Invalid IP address: {ip_address}") from e


def _validate_network(network: str) -> None:
    """
    Validate network CIDR notation
    """
    try:
        ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        raise ValidationError(f"Invalid network: {network}") from e


@dataclass(slots=True)
class FilterBuilder:
    """
    Builds BPF filter expressions for efficient kernel-level packet filtering
    """
    _expressions: list[str]

    def __init__(self) -> None:
        """
        Initialize empty filter builder
        """
        self._expressions = []

    def protocol(self, proto: Protocol) -> Self:
        """
        Filter by protocol type using the Protocol enum
        """
        bpf_expr = BPF_PROTOCOL_MAP.get(proto)
        if bpf_expr:
            self._expressions.append(f"({bpf_expr})")
        return self

    def protocols(self, protos: list[Protocol]) -> Self:
        """
        Filter by multiple protocols (OR logic)
        """
        bpf_exprs = [
            BPF_PROTOCOL_MAP[p] for p in protos if p in BPF_PROTOCOL_MAP
        ]
        if bpf_exprs:
            combined = " or ".join(f"({expr})" for expr in bpf_exprs)
            self._expressions.append(f"({combined})")
        return self

    def port(self, port_number: int) -> Self:
        """
        Filter by port number (source or destination)
        """
        _validate_port(port_number)
        self._expressions.append(f"port {port_number}")
        return self

    def src_port(self, port_number: int) -> Self:
        """
        Filter by source port
        """
        _validate_port(port_number)
        self._expressions.append(f"src port {port_number}")
        return self

    def dst_port(self, port_number: int) -> Self:
        """
        Filter by destination port
        """
        _validate_port(port_number)
        self._expressions.append(f"dst port {port_number}")
        return self

    def host(self, ip_address: str) -> Self:
        """
        Filter by IP address (source or destination)
        """
        _validate_ip_address(ip_address)
        self._expressions.append(f"host {ip_address}")
        return self

    def src_host(self, ip_address: str) -> Self:
        """
        Filter by source IP address
        """
        _validate_ip_address(ip_address)
        self._expressions.append(f"src host {ip_address}")
        return self

    def dst_host(self, ip_address: str) -> Self:
        """
        Filter by destination IP address
        """
        _validate_ip_address(ip_address)
        self._expressions.append(f"dst host {ip_address}")
        return self

    def net(self, network: str) -> Self:
        """
        Filter by network (CIDR notation)
        """
        _validate_network(network)
        self._expressions.append(f"net {network}")
        return self

    def port_range(self, start: int, end: int) -> Self:
        """
        Filter by port range
        """
        _validate_port(start)
        _validate_port(end)
        if start > end:
            raise ValidationError(f"Invalid port range: {start}-{end}")
        self._expressions.append(f"portrange {start}-{end}")
        return self

    def not_port(self, port_number: int) -> Self:
        """
        Exclude traffic on specified port
        """
        _validate_port(port_number)
        self._expressions.append(f"not port {port_number}")
        return self

    def not_host(self, ip_address: str) -> Self:
        """
        Exclude traffic from/to specified host
        """
        _validate_ip_address(ip_address)
        self._expressions.append(f"not host {ip_address}")
        return self

    def raw(self, expression: str) -> Self:
        """
        Add raw BPF expression for advanced filtering
        """
        self._expressions.append(expression)
        return self

    def build(self, operator: Literal["and", "or"] = "and") -> str | None:
        """
        Build final BPF filter string combining all expressions
        """
        if not self._expressions:
            return None
        return f" {operator} ".join(self._expressions)

    def reset(self) -> Self:
        """
        Clear all filter expressions
        """
        self._expressions = []
        return self


def protocol_to_bpf(proto: Protocol) -> str | None:
    """
    Convert Protocol enum to BPF filter expression
    """
    return BPF_PROTOCOL_MAP.get(proto)


def combine_filters(
    filters: list[str],
    operator: Literal["and",
                      "or"] = "and",
) -> str | None:
    """
    Combine multiple BPF filter strings with logical operator
    """
    valid_filters = [f for f in filters if f]
    if not valid_filters:
        return None
    if len(valid_filters) == 1:
        return valid_filters[0]
    wrapped = [f"({f})" for f in valid_filters]
    return f" {operator} ".join(wrapped)


def validate_bpf_filter(filter_str: str) -> bool:
    """
    Validate BPF filter syntax using Scapy
    """
    try:
        from scapy.arch import compile_filter

        compile_filter(filter_str)
        return True
    except Exception:
        return False


__all__ = [
    "BPF_PROTOCOL_MAP",
    "FilterBuilder",
    "combine_filters",
    "protocol_to_bpf",
    "validate_bpf_filter",
]
